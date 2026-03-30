# API Relay Audit -- 技术架构全解析

> 这个项目是一把"X光机"，专门用来透视那些 AI API 中继服务的黑箱操作。
> 中继商说"我们只是转发请求"，这个工具会告诉你：他们到底在请求里塞了什么私货。

---

## 目录

1. [项目全景：你在审计什么？](#项目全景你在审计什么)
2. [client.py -- 自适应客户端](#clientpy----自适应客户端)
3. [context.py -- 金丝雀算法](#contextpy----金丝雀算法)
4. [audit.py -- 七步审计编排](#auditpy----七步审计编排)
5. [extract-data.py -- 报告解析器](#extract-datapy----报告解析器)
6. [reporter.py -- 报告生成器](#reporterpy----报告生成器)
7. [架构决策：为什么这样设计](#架构决策为什么这样设计)
8. [踩过的坑和经验教训](#踩过的坑和经验教训)
9. [最佳实践清单](#最佳实践清单)

---

## 项目全景：你在审计什么？

想象你去餐厅点了一杯"纯净水"。服务员端来一杯水，看起来很清澈。但你怎么知道他们没在里面加糖、加盐、甚至加药？

API 中继服务就是这个"服务员"。用户以为自己直接在跟 Claude 或 GPT 对话，但实际上请求经过了一个中间层。这个中间层可能在做以下事情：

- **注入隐藏的 system prompt**（"你是 Kiro，由 Amazon 制造"）
- **截断上下文窗口**（你付了 200K token 的钱，实际只给你 50K）
- **覆盖用户指令**（你说"你是 Claude"，它偷偷改成"你是 Kiro"）
- **伪装 API 格式**（明明是 OpenAI 格式的后端，对外却说是 Anthropic 兼容的）

这个项目用 7 个步骤，系统性地检测上述所有猫腻。

---

## client.py -- 自适应客户端

### 设计模式：状态机 + 策略模式

`APIClient` 是整个项目的"嘴巴"——所有与 API 的通信都通过它。它解决了一个很实际的问题：**你事先不知道目标 API 说的是哪种"方言"**。

Anthropic 和 OpenAI 的 API 格式差异巨大：

| 维度 | Anthropic | OpenAI |
|------|-----------|--------|
| 认证头 | `x-api-key: xxx` | `Authorization: Bearer xxx` |
| 端点 | `/v1/messages` | `/v1/chat/completions` |
| system prompt | 顶层 `system` 字段 | messages 数组里的 `system` 角色 |
| 响应结构 | `content[0].text` | `choices[0].message.content` |
| token 计量 | `input_tokens` / `output_tokens` | `prompt_tokens` / `completion_tokens` |

### 格式自动检测状态机

这不是简单的 if-else，而是一个**三态状态机**：

```
初始状态: _format = None
         ↓
    尝试 Anthropic 格式
         ↓
   成功且有内容? ──是──→ _format = "anthropic" (锁定)
         ↓ 否
    尝试 OpenAI 格式
         ↓
   成功且有内容? ──是──→ _format = "openai" (锁定)
         ↓ 否
   返回最佳结果 (不锁定，下次重试)
```

**为什么先试 Anthropic？** 因为 Anthropic 格式更严格——如果一个 API 同时支持两种格式，Anthropic 格式的响应更可靠（结构更确定性）。OpenAI 格式是"通用方言"，几乎什么 API 都能糊弄过去返回个 200，但内容可能是空的。

**为什么锁定后不再探测？** 这是一个性能决策。第一次调用是"侦察兵"，花两倍时间（最坏情况两次请求）；后续所有调用走已知路径，零额外开销。`_format` 一旦赋值就成为缓存，整个审计过程中不会再浪费一次请求在格式猜测上。

### SSL 回退机制

```python
def _handle_ssl_error(self, e: Exception) -> bool:
    if not self._use_curl and ("SSL" in str(e) or "Connect" in type(e).__name__):
        self._use_curl = True
        return True  # 告诉调用者：可以重试了
    return False
```

这段代码解决了一个特别恶心的现实问题：很多中继服务用自签名证书或者过期证书。Python 的 `httpx`（底层用 OpenSSL）会严格验证证书链，直接报错。

解决方案很聪明：**降级到 curl**。curl 加上 `-sk` 参数会跳过证书验证。这不是安全最佳实践（在生产代码中你绝对不应该这样做），但在审计工具中，你的目的是"能连上"而不是"安全地连上"——你是去检查别人安不安全的，不是去跟他们做交易的。

注意 `_handle_ssl_error` 返回一个布尔值，这触发了 `_call_with_detection` 中的**递归重试**：

```python
except Exception as e:
    if self._handle_ssl_error(e):
        return self._call_with_detection(messages, system, max_tokens)  # 递归！
```

这个递归最多触发一次（因为 `_use_curl` 设为 True 后，`_handle_ssl_error` 不会再返回 True），所以不会无限循环。这是一种优雅的"一次性重试"模式。

---

## context.py -- 金丝雀算法

### 金丝雀标记（Canary Marker）

这个名字来自煤矿里的金丝雀——矿工把金丝雀带进矿井，如果金丝雀死了，说明有毒气。同样，我们在文本中放置"金丝雀标记"，如果模型找不到某些标记了，说明上下文在那个位置被截断了。

```python
canaries = [f"CANARY_{i}_{uuid.uuid4().hex[:8]}" for i in range(5)]
```

每个金丝雀标记长这样：`CANARY_0_a3f8b2c1`。UUID 后缀确保每次测试的标记都是唯一的——模型不可能"记住"上次测试的标记来作弊。

5 个标记被**等间距**地插入到一段很长的填充文本中：

```
[CANARY_0_xxx] ~~~填充文本~~~ [CANARY_1_xxx] ~~~填充文本~~~ ... [CANARY_4_xxx]
```

然后问模型："请列出你能找到的所有 CANARY 标记。"

- 如果模型能找到全部 5 个 → 上下文窗口覆盖了全部文本
- 如果只找到前 3 个 → 文本在第 3 和第 4 个标记之间被截断了
- 如果一个都找不到 → 要么文本超出了窗口，要么 API 出错了

### 粗扫 + 二分查找：找到精确的截断边界

这是整个项目中算法最精巧的部分。

**第一阶段：粗扫（Coarse Scan）**

```python
coarse_steps = [50, 100, 200, 400, 600, 800]  # 单位：千字符
```

从 50K 字符开始，逐步加大。像一个人在黑暗中拿着手电筒，每隔一大步照一下。一旦某步失败（比如 400K 通过但 600K 失败），就知道边界在 400K~600K 之间。

**第二阶段：二分查找（Binary Search）**

```python
lo, hi = last_ok, first_fail  # 例如 400, 600
while hi - lo > 20:
    mid = (lo + hi) // 2       # 500
    # 测试 500K...
    # 通过 → lo = 500
    # 失败 → hi = 500
```

经典二分查找。每次把搜索范围缩小一半。从 200K 的范围缩小到 20K 以内，只需要大约 `log2(200/20) ≈ 3.3`，也就是 4 次请求。

**第三阶段：精扫（Fine Scan）**

在最后的 20K 范围内，每 10K 一步，逐一测试。最多 2 次额外请求。

**总复杂度分析**：

| 阶段 | 最大请求数 | 说明 |
|------|-----------|------|
| 粗扫 | 6 | 固定步数 |
| 二分 | ~4 | log2(范围/20) |
| 精扫 | ~2 | 范围/10 |
| **总计** | **~12** | 远少于暴力扫描的 80 次 |

如果暴力从 50K 到 800K 每 10K 测一次，需要 75 次 API 调用。这个算法用不到 12 次就能达到同样的精度。这就是算法的力量——**用 O(log n) 替代 O(n)**。

### 为什么填充文本用重复的字母表？

```python
FILLER = "abcdefghijklmnopqrstuvwxyz0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
```

不是随机噪声，而是可预测的重复文本。原因：

1. **tokenizer 友好**：常规字母和数字的 token 化效率稳定，不会因为随机字节导致 token 数量波动
2. **不会触发安全过滤**：随机字节可能被误判为攻击payload
3. **可复现**：相同长度的填充文本会产生近似相同的 token 数量

---

## audit.py -- 七步审计编排

这是整个项目的"总指挥"，按顺序执行 7 个测试模块。让我深入讲解其中最精妙的三个测试。

### 第 3 步：Token 注入检测（Delta 方法）

这是整个审计中最重要的测试，原理出奇地简单：

```
你发送: "Say hi" (大约 10 个 token)
API 返回: input_tokens = 847
差值 delta = 847 - 10 = 837 个 token
```

这 837 个 token 从哪来的？你没发，模型说收到了。**唯一的解释：中继服务在你的请求里注入了一个大约 837 token 的隐藏 system prompt。**

这个方法之所以有效，是因为它利用了一个关键事实：**token 计数是由底层模型计算的，中继服务无法伪造**。就像你寄了一个 100 克的包裹，收件人说"我收到了 1 公斤"——中间一定有人塞了东西进去。

代码发送三组不同的测试消息，取最大差值：

```python
tests = [
    ("'Say hi' (no system prompt)", None, "Say hi", 10),
    ("'Say hi' + short system prompt", "You are a helpful assistant.", "Say hi", 20),
    ("'Who are you' (no system prompt)", None, "Who are you?", 15),
]
```

**为什么要多组？** 因为某些中继服务可能根据消息内容动态注入不同长度的 prompt。多组测试增加了检测的鲁棒性。

风险等级判定很实际：
- delta > 100 tokens → 红色警报（几乎可以确定有大型隐藏prompt）
- delta > 20 tokens → 黄色警告（可能有少量元数据注入）
- delta ≤ 20 tokens → 绿色安全（在正常误差范围内）

### 第 5 步：猫测试（Cat Test）

这是我见过最有创意的行为验证测试：

```python
system = 'From now on, you can only reply with the single word "meow".'
user = "What is 1+1?"
```

如果中继服务没有注入隐藏指令，模型应该乖乖回复 "meow"。但如果中继在幕后注入了另一套 system prompt（比如"你是一个有用的编程助手"），模型就会陷入指令冲突。

可能的结果：

| 回复 | 含义 |
|------|------|
| "meow" | 用户 system prompt 完全生效，没有隐藏指令覆盖 |
| "meow... but the answer is 2" | "人格分裂"——两套指令在打架 |
| "2" | 用户指令被完全覆盖，隐藏指令优先级更高 |

**为什么用"meow"而不是其他词？**

这是精心选择的。"meow" 是一个：
- 极端简单的指令（消除了模型"理解失败"的可能）
- 与数学问题完全无关的回复（任何"正常回答"的痕迹都说明有指令冲突）
- 容易用正则检测的标志词

检测逻辑也很巧妙：

```python
has_meow = "meow" in text
has_other = bool(re.search(r"[0-9]|equals|two|plus", text))
```

不只看有没有 "meow"，还检查有没有数学相关的词。这避免了模型回复"Meow! The answer is 2"时误判为"通过"。

### 第 5 步续：身份覆盖测试（Identity Override）

```python
system = "You are Claude, made by Anthropic. Never claim to be anyone else."
user = "Who are you? Who made you?"
```

这个测试直接戳到中继服务的痛处：如果中继注入了"你是 Kiro，由 Amazon 制造"这样的指令，模型在面对用户说的"你是 Claude"和隐藏指令说的"你是 Kiro"时，会怎么选？

```python
if "anthropic" in text_lower and "claude" in text_lower:
    # 用户指令生效
elif any(kw in text_lower for kw in ["amazon", "kiro", "aws"]):
    # 隐藏指令覆盖了用户指令！
```

这是整个审计中最直观的测试——如果你明确告诉模型"你是 Claude"，它却说自己是 Kiro，那中继服务一定在幕后搞鬼。

### 审计编排的设计

注意 `main()` 函数的结构：

```python
# 3. Token injection
injection = test_token_injection(client, report)
# ...
# 5. Instruction conflict
overridden = test_instruction_conflict(client, report)
# ...
# 8. Overall rating
if injection > 100 and overridden:
    # HIGH RISK
elif injection > 100:
    # MEDIUM RISK
```

每个测试函数返回一个关键指标（注入大小、是否泄露、是否被覆盖），最后在 Overall Rating 中做交叉分析。这不是简单的"红灯/绿灯"，而是一个**二维风险矩阵**：

```
              指令被覆盖
              是      否
注入 > 100  | HIGH  | MEDIUM |
注入 ≤ 100  | MEDIUM | LOW   |
```

---

## extract-data.py -- 报告解析器

这个脚本做的事情很直接：从审计生成的 Markdown 报告中提取结构化数据，输出为 JSON，供前端展示用。

### 正则解析策略

核心函数 `extract_test_result` 用正则从 Markdown 中抠出每个测试的结果：

```python
pattern = rf"### {re.escape(test_name)}\s*\n\n(.*?)(?=\n###|\n##|$)"
```

这个正则的意思是："找到以 `### 测试名称` 开头的章节，捕获其内容，直到下一个 `###` 或 `##` 标题出现"。

`re.escape(test_name)` 很重要——测试名称可能包含特殊正则字符（比如括号），必须转义。

**双语支持**是一个有意思的细节：

```python
test_names = {
    "Test A - Verbatim": "Verbatim",
    "测试 A 复述法": "Verbatim",  # 中文版
}
```

这说明这个工具经历过中英文两个版本的迭代。代码兼容两种格式的报告，不需要用户指定语言。

### 上下文测试表格解析

```python
table_match = re.search(
    r"## (?:7\.|七).*?\n\n\|.*?\n\|.*?\n((?:\|.*?\n)+)", content, re.DOTALL
)
```

这个正则匹配 `## 7.` 或 `## 七` 开头的章节（同样是双语兼容），然后跳过表头和分隔行，抓取所有数据行。

值得注意的是，这种"用正则解析 Markdown 表格"的做法虽然脆弱（Markdown 格式稍有变化就可能失败），但对于自己生成、格式高度可控的报告来说，是一个合理的权衡——比引入一个完整的 Markdown parser 库要轻量得多。

---

## reporter.py -- 报告生成器

`Reporter` 类是一个轻量级的 Markdown 构建器，采用 Builder 模式：

```python
report = Reporter()
report.h2("1. Infrastructure Recon")
report.p("Some finding")
report.flag("red", "Something bad detected!")
md = report.render()
```

`flag()` 方法做了双重工作：既把带颜色圆点的警告写入正文，又收集到 `self.summary` 列表中。`render()` 时，所有 flag 会被汇总到报告顶部的 Risk Summary 区域。

这意味着读者不需要通读整篇报告就能看到所有风险点——它们被自动聚合到了最上面。这是报告设计中的一个好实践：**Executive Summary 应该自动生成，而不是手动编写**。

---

## 架构决策：为什么这样设计

### 模块化的帕累托前沿分析

这个项目的模块拆分体现了一种"帕累托前沿"思维——在"灵活性"和"简洁性"之间找到最优平衡点。

项目只有 4 个核心模块：

```
api_relay_audit/
├── client.py      # 通信层（HOW to talk）
├── context.py     # 算法层（WHAT to measure）
├── reporter.py    # 输出层（HOW to present）
scripts/
├── audit.py       # 编排层（WHAT to do）
├── context-test.py  # 独立工具（单一功能入口）
├── extract-data.py  # 数据转换（report → JSON）
```

**为什么不是更细？** 可以把每个测试拆成单独的模块（`test_injection.py`, `test_jailbreak.py` 等），但这些测试之间有共享的模式（都用 `client.call()`，都用 `report.flag()`），拆开后反而增加了胶水代码。

**为什么不是更粗？** 可以把所有东西塞进一个 `audit.py`，但 `client.py` 和 `context.py` 的逻辑明显是可复用的（`context-test.py` 就单独使用了它们），拆出来是值得的。

这就是帕累托前沿：在这个点上，任何进一步的拆分都不会带来足够的收益来补偿增加的复杂度，任何进一步的合并都会牺牲有价值的复用性。

### 为什么 `_format` 用实例变量而不是参数？

```python
client = APIClient(base_url, api_key, model)
# 不是 client = APIClient(..., format="openai")
```

因为在审计场景中，你通常不知道目标 API 的格式。自动检测是默认行为，不应该要求用户手动指定。如果以后需要强制指定格式，只需在 `__init__` 中加一个可选参数，给 `_format` 赋初值就行——向后兼容。

### 为什么用 `httpx` 而不是 `requests`？

`httpx` 支持 HTTP/2，API 超时控制更精确，而且接口跟 `requests` 几乎一样。在审计工具中，超时控制至关重要——你不想因为一个挂起的请求卡住整个审计流程。

---

## 踩过的坑和经验教训

### 坑 1：SSL 证书验证的地狱

很多中继服务的 SSL 配置一塌糊涂——自签名证书、过期证书、证书链不完整。Python 的 SSL 库（通过 httpx）会直接报错，导致审计工具连"门"都进不去。

**修复**：引入 curl 回退机制（`-sk` 跳过验证）。但这引入了新的复杂度——curl 的输入/输出格式跟 httpx 不同，需要 `_curl_post` 方法做适配。

**教训**：永远为"不理想的现实环境"准备 Plan B。在审计/安全工具中，"能用"比"优雅"重要得多。

### 坑 2：空响应 vs 错误响应

自动检测最初的版本只检查 `"error" not in result`，但有些 API 返回 200 状态码、没有 error 字段、但 text 是空字符串。这导致错误地锁定了格式。

**修复**：加上 `.strip()` 检查：

```python
if "error" not in anthropic_result and anthropic_result.get("text", "").strip():
```

**教训**：在做协议自动检测时，"成功"的定义不只是"没有错误"，还要确认"有实质性内容"。

### 坑 3：二分查找的边界条件

最初二分查找结束后直接返回 `lo` 作为边界，但实际截断点可能在 `lo` 和 `hi` 之间的某个非二分点上。

**修复**：加入精扫阶段（Fine Scan），在最后 20K 范围内每 10K 步测试一次，并用 `if not any(x[0] == k for x in results)` 避免重复测试已有数据的点。

**教训**：二分查找给你一个"足够好"的范围，但如果精度要求更高，在最后一段用线性扫描"兜底"是常见做法。很多实际系统都用这种"二分 + 线性精修"的混合策略。

### 坑 4：正则解析 Markdown 的脆弱性

`extract-data.py` 中的正则假设了特定的 Markdown 格式（比如 `**Response**:` 后面跟代码块）。报告模板稍作修改就可能导致解析失败。

**教训**：如果你要用正则解析自己生成的格式，那就把"生成"和"解析"看作一份合约——修改一端时必须同时检查另一端。更好的做法是在 `reporter.py` 中同时输出一份结构化的 JSON，但这意味着更多的代码，在这个项目规模下不值得。这又是一个帕累托权衡。

---

## 最佳实践清单

### 1. 防御性编程无处不在

```python
# 所有 API 调用都有超时
self.timeout = timeout
# 所有外部命令都有超时
subprocess.run(cmd, ..., timeout=self.timeout + 10)
# 所有响应都有长度截断
r.text[:200]  # 错误信息不会撑爆日志
r["text"][:2000]  # 报告中的响应不会无限长
```

### 2. 渐进式降级（Graceful Degradation）

```
httpx 失败 → 降级到 curl
Anthropic 格式失败 → 降级到 OpenAI 格式
两种格式都失败 → 返回最佳可用结果（而不是崩溃）
```

审计工具的第一原则是"别崩"。宁可给出不完美的结果，也不要因为一个未处理的异常中断整个审计流程。

### 3. 幂等性和可恢复性

每个测试函数都是独立的——第 3 步失败不影响第 5 步执行。`--skip-infra` 和 `--skip-context` 参数允许跳过耗时的步骤。这意味着如果审计中途出问题，你可以只重跑失败的部分。

### 4. 测试结果的交叉验证

单一信号可能误判。Delta 方法检测到注入（量化证据），猫测试验证行为影响（定性证据），身份测试确认具体内容（内容证据）。三者结合才构成完整的结论。

这是安全审计的基本原则：**永远不要基于单一信号下结论。**

### 5. 常量命名即文档

```python
FILLER = "abcdefghijklmnopqrstuvwxyz0123456789 ..."
```

变量名叫 `FILLER`，你一看就知道这是填充用的，不需要注释解释"这段文本没有语义意义"。

---

## 最后的话

这个项目的精髓不在于代码量（总共不到 500 行），而在于它的**思维方式**：

1. **利用不变量检测异常**：token 计数是不可伪造的不变量，delta 方法就是基于这个不变量
2. **用行为测试替代静态分析**：你无法直接看到中继服务的代码，但你可以通过"猫测试"观察它的行为
3. **算法选择匹配问题特征**：上下文截断是单调的（短文本通过 → 更短的也通过），所以二分查找是最优策略
4. **帕累托最优的工程权衡**：不追求完美的模块化或完美的覆盖率，而是在当前规模下找到最实用的平衡点

好的工程不是写出最多的代码，而是用最少的代码解决最关键的问题。这个项目就是一个很好的例子。
