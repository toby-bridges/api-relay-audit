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

## 论文集成 (arXiv 2604.08407)

### 为什么要读这篇论文

2026-04-09，UCSB + Fuzzland 团队在 arXiv 上挂了一篇叫 *Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain* 的论文。这是**第一次**有人把"中转站是恶意中间人"这件事做成了正经的威胁建模 + 实测。他们买了 28 个付费中转、扫了 400 个免费中转，发现：

- **1 个付费 + 8 个免费**中转已经在注入恶意代码（改写 tool_call 返回值）
- **17 个中转**触碰了研究者挂在 AWS 上的 canary 凭证（被动扫描泄漏）
- **1 个中转**直接把研究者钱包里的 ETH 掏空了
- **440 个已泄漏凭证**在公开论坛上传播，401/440 的会话**已经**在自主执行（YOLO mode），只差一个 payload 就能 RCE

论文把攻击面形式化成四类：

| 代号 | 全称 | 含义 |
|---|---|---|
| **AC-1** | Payload Injection | 中转站改写 tool_call 返回值 |
| **AC-1.a** | Dependency-Targeted Injection | AC-1 的变种：改写包名 (`requests` → `reqeusts` typosquat) |
| **AC-1.b** | Conditional Delivery | AC-1 的变种：只在特定条件触发（YOLO 模式、请求数 > 50、特定关键词） |
| **AC-2** | Secret Exfiltration | 被动扫描请求流量，泄漏 API key / 凭证 |

这个分类很重要，因为它把我们原来那套"有没有注入 system prompt"的思维拔高了一层——**真正血腥的战场不在 prompt，在 tool_call**。

### 我们之前的盲点

原来的 7 步审计只覆盖了 **prompt 层面的 tampering**：system prompt 注入、指令覆盖、上下文截断。这些都是重要的，但它们都是"用户读了一段奇怪的回复"那种问题。

**tool_call 层面完全没覆盖。** 一个运行 AC-1.a 的中转站，当你让它帮你装个 `requests` 库，它会在返回的 tool_call 里把包名悄悄改成 `reqeusts`（少一个字母），你的 agent 自动执行 `pip install reqeusts`，typosquat 的恶意包拿到你本机的 code execution。**没有任何 prompt 层面的检测能看到这一手**。

### 帕累托前沿决定做什么

论文给了很多可借鉴的东西，但不可能一次做完。列了一下每个候选在"工程量 × 威胁覆盖"空间里的位置：

| 方案 | 工程量 | 覆盖率 | Pareto 地位 |
|---|---|---|---|
| AC-1.a 文本 echo 替换测试 | 极低（~80 行，不动 client） | 覆盖论文实测中最危险的变种 | ✅ **前沿** |
| Warm-up 协议 | 极低（~10 行，一个 flag） | 部分缓解 AC-1.b 请求数门槛类后门 | ✅ **前沿** |
| 风险矩阵升级 + 论文引用 | 几乎为零 | 报告学术锚点 + 传播弹药 | ✅ **前沿** |
| 完整 AC-1（tool_call 支持） | 高（~150 行 client + 双格式 + curl 版本同步 + 新测试） | 边际增量有限：论文实测的 AC-1 几乎全是 AC-1.a | ❌ 被支配 |
| AC-2 canary 被动版 | 中 | 不能抓延迟探测，价值低 | ❌ 被支配 |

**前 3 个都在前沿上**，做了。后 2 个被支配了，留到 backlog。

### 这次到底改了什么

1. **新增 Step 8 — Tool-Call Package Substitution (AC-1.a)**
   - 新文件 `api_relay_audit/tool_substitution.py` （模块化版本）
   - 在 standalone `audit.py` 里以内联 Section 3b 的形式存在
   - 逻辑：让模型原样输出 4 条钉版本的 install 命令（`pip install requests==2.31.0`、`npm install lodash@4.17.21`、`cargo add serde`、`go get github.com/stretchr/testify`），然后字符级 diff
   - 三类判定：`exact` / `whitespace`（大小写空格差异，良性）/ `substituted`（实质性改写，🔴 红旗）

2. **新 CLI flag `--warmup N`**
   - 审计前发 N 个 `"ok"` benign 请求，跨过 AC-1.b 的"前 50 次不激活"门槛
   - 不是万能的——论文自己也说 finite black-box 无法可靠检测条件投递——只是降低漏测概率

3. **风险矩阵升维到 3D**
   - 原来：D1 (injection>100) AND D2 (overridden) → HIGH
   - 现在：D3 (tool_call 改写) 单独成立就 HIGH。**一次代换就是 RCE 级别，不需要叠加**
   - 其他等级规则保持不变，不破坏 dashboard 对 LOW/MEDIUM/HIGH 的消费

4. **文档 + 传播**
   - README 顶部加了论文引用
   - CLAUDE.md 列出完整的 AC-1/AC-1.a/AC-1.b/AC-2 分类和各自的实现状态
   - SKILL.md 更新到 v2.1.0，8 步审计
   - 这份 FOR_JOHN.md 加了当前这一节

### 主动放弃的东西（backlog）

这些**故意**没做，不是忘了：

1. **完整 AC-1 支持（APIClient 的 tool_calling 扩展）**
   真正的 tool_call 改写检测需要给 `APIClient` 加 `tools` / `tool_choice` 参数和两套格式的解析。工程量 ~150 行，但边际增量被 AC-1.a 压制：论文实测的所有活跃 AC-1 案例都是 AC-1.a 变种，因为路由器的 substitution rule 是跑在响应字符串上的正则，不区分 tool_call JSON 还是明文。等到看见第一个"只改 tool_call JSON、不改明文"的样本再做。

2. **AC-2 凭证 canary（被动泄漏检测）**
   需要挂一个可回调的外部域名当监听端点——论文就是靠这个抓到 147 个 IP、6 个 JA3 指纹。目前没有这个基础设施，等有了独立域名 + 被动 webhook 监听服务再开工。

3. **完整 AC-1.b 检测**
   条件投递类后门的完整检测需要模拟 YOLO 模式指纹、关键词 gating、时间窗口 gating 等多维度探测。目前只做了最简单的 warm-up 缓解。论文自己都说 `finite black-box audits can't reliably catch AC-1.b`，我们也别假装能。

4. **风险等级四维化**
   原来的 LOW/MEDIUM/HIGH 三档有 dashboard 下游在消费，升级到 4 档会破坏向后兼容。暂不动。

### 为什么不是一次性做完

用户（你自己）在计划阶段明确说"用帕累托前沿做技术选型"。帕累托最优的意思是：在当前投入下，没有任何其他方案能在"工程量不增加"和"覆盖率不下降"两个维度同时压倒当前选择。

把完整 AC-1 塞进这次 PR 会让 `APIClient` 变得复杂、双版本同步成本翻倍、可能触发部分 relay 的 422，而换来的边际覆盖率是 AC-1.a 已经覆盖到的那部分攻击面——**不划算**。不划算的事情不做。

这个项目的规模决定了它不应该一次吃太多——它要保持"可以一条 curl 下载 + python 跑"的简洁性。每一个新 Step 都要过一道"是否值得把 audit.py 再厚一圈"的问。AC-1.a 这个 Step 过了，其他的还没过。

---

## 最后的话

这个项目的精髓不在于代码量（总共不到 600 行），而在于它的**思维方式**：

1. **利用不变量检测异常**：token 计数是不可伪造的不变量，delta 方法就是基于这个不变量
2. **用行为测试替代静态分析**：你无法直接看到中继服务的代码，但你可以通过"猫测试"观察它的行为
3. **算法选择匹配问题特征**：上下文截断是单调的（短文本通过 → 更短的也通过），所以二分查找是最优策略
4. **帕累托最优的工程权衡**：不追求完美的模块化或完美的覆盖率，而是在当前规模下找到最实用的平衡点
5. **借力学术工作**：拿 arXiv 2604.08407 的威胁模型当锚点，自己的工具瞬间从"一个 script"变成"论文威胁模型的客户端侧对策"——不是为了装，是为了让下游读者知道这个工具在认真的威胁模型里的位置

好的工程不是写出最多的代码，而是用最少的代码解决最关键的问题。这个项目就是一个很好的例子。

---

## 2026-04-11 session diary: v2.2 → v2.3 的 9 个 commit

这一节不是技术讲解，是**给未来的你**看的工程决策日记。不看代码就看不懂 why 的事情，都记在这里。

### 这个 session 干了什么

一口气做了 **9 个 commit，测试 114 → 281（+167 新测试，零回归）**，把工具从 8 step 推到 10 step：

| Commit | 版本 | 内容 |
|---|---|---|
| `df7715a` | v2.2 | Step 9 v1 + v1.5 补洞 + v1.5.1 LiteLLM issue sourcing |
| `ff991aa` | v1.5.2 | Codex hotfix #1：auth_probe x-api-key override + partial key redaction |
| `019889a` | v1.6 | 非 Claude 身份替换检测（22 个关键词，port 自 hvoy.ai） |
| `8f654c2` | v1.6.1 | Codex hotfix #2：word-boundary regex(修"laws → aws"误报) |
| `0ceed5b` | v1.6.2 | Codex hotfix #3：trailing lookahead(修"Qwen2.5"漏检) |
| `5fb0b27` | v2.3 Sub-PR 1 | streaming client support(httpx + curl 双分支) |
| `f6e2b9f` | v2.3 Sub-PR 2 | analyze_stream verdict 逻辑 |
| `983d51e` | v2.3 Sub-PR 3 | Step 10 orchestration + 5D 风险矩阵 |
| `42d5de7` | v1.7.1 | Codex hotfix #4：SSE parser edge cases + curl 中途失败处理 |

### 最重要的工程教训：Codex review 循环

我这次在 session 里跑了 **5 轮 Codex 独立代码审查**,每一轮都发现了真 bug(除了最后一轮 clean)。具体模式:

| Round | 审查对象 | 发现 | 严重度 |
|---|---|---|---|
| 1 | `df7715a` Step 9 核心 | 2 个 bug | MEDIUM × 2 |
| 2 | `ff991aa` + `019889a` | 2 个 bug | LOW + NIT |
| 3 | `8f654c2` word-boundary | 1 个 bug | MEDIUM(版本后缀漏检) |
| 4 | `0ceed5b` | 0 bug | — |
| 5 | Sub-PR 1/2/3 streaming | 2 个 bug | MEDIUM + LOW |

**关键观察**:每一轮 Codex 找到的问题类别都不同——第 1 轮是业务逻辑(x-api-key 覆盖不全),第 2 轮是 substring 匹配误报,第 3 轮是 regex 太严,第 5 轮是 stream transport 层错误处理不对称。**你不可能一次性想到所有这些**,必须迭代。

**这个循环有效的原因**:
1. Codex 和我(Claude)是**不同的 AI 实例**,没有共享的认知盲点
2. Codex **不知道我之前的 review 输出**,所以它的第二次审查不会被前一次的结论影响
3. 它只能看源码和 commit history,这些都是**客观 artifact**
4. 它被明确要求"be blunt"、"don't invent issues",所以它的 LOW/NIT/MEDIUM 标签是认真的

**这个循环的代价**:每轮 ~2-5 分钟 + tokens。但发现的 bug 如果 ship 到生产会造成:**MEDIUM 级别的 false negative**——审计工具在真实有问题的 relay 上返回"clean",这是最糟糕的安全工具失效模式。

**结论**:以后每个有一定复杂度的 feature PR 都应该跑至少 2 轮 Codex review:**第一轮找 bug → 修 → 第二轮闭环验证**。如果第二轮发现新问题,继续修+review 直到 clean。

### 最重要的方法论教训:验证而非总结

**情况**:hvoy.ai 的 `claude_detector.py` 是这个 session 里关键的情报来源。最初用 WebFetch 看了一次,summary 报告说"SSE 白名单有 5 个事件"。我本来要直接 port,幸好想起来 memory 里的 feedback:

> "Prefer local files over WebFetch for source verification"

于是 `git clone` 了原 repo,**逐行读** `claude_detector.py`,发现:
- **白名单实际是 7 个事件**(WebFetch summary 漏了 `ping` 和 `content_block_stop`)
- **Thinking 维度最大分数是 13 不是 15**(虽然代码里 cap 在 15)
- **Penalty 系统有 4 层不只 -25**(还有 -10, -8, -8 三级)
- **还有 CLI header 伪装和 "null" text block 两个 WebFetch 完全漏掉的 hidden discoveries**

如果我直接信 WebFetch 去 port,**有 3 个事实错误会被刻进代码**。这不是 WebFetch 有 bug,这是"有总结层"的读文章方式本质上的问题——小模型的摘要会丢细节,而细节在安全工具里就是一切。

**规则**:**任何要 port 的源码必须本地 clone + 逐行读**。summary 只用于"这个项目是干什么的"这种宏观判断。

### 最大的认知矫正:我的竞品分析有方法论盲点

Session 前期我写过一份 `project_competitive_landscape.md` memory,结论是"**0 direct competitors,api-relay-audit 是唯一实现**"。这个结论是通过用 10+ 个英文搜索词搜 GitHub 得出的。

然后你让我去看 `https://hvoy.ai/`,我立刻发现:
- 这是一个**直接竞品**,同威胁模型同时期(2026-04 上线)
- **336 stars**,比我们关注度还高
- 有开源后端(`zzsting88/relayAPI`)

**为什么之前漏了**:因为我用的全是英文搜索词(`"llm relay" security`, `"llm proxy" audit` 等),而 hvoy.ai 服务的是**中国市场**,相关术语是"中转站"/"水站"/"API 中转"。**英文语义空间对中文市场不透明**。这是一个我没意识到的**方法论盲点**,不是知识盲点。

**修正后的 memory**:`project_competitive_landscape.md` 里加了"Methodology lesson"章节,明确要求以后的竞品研究必须**双语搜索**——英文 + 中文(至少包括"中转站"和"API 中转"两个词)。

### 为什么 scope 膨胀了(从"v1.5 补洞"到 9 个 commit)

原计划只是"Step 9 v1.5 补洞 + Step 10 crypto substitution"。但实际做下来,这个 session 交付了 5 个 step-level 的功能(Step 9 v1 + v1.5 + v1.5.1 + v1.6 身份 + v2.3 streaming),加 4 个 Codex 修复。**为什么不严格按原计划**?

**答案**:每一次偏离都有明确理由:

1. **v1.5 → v1.5.1**(加 LiteLLM 8 个 issue sourcing):因为这个信息是在 session 中通过 agent 新查到的,**sourcing quality 比原计划高一个数量级**——每条 regex 都能追到一个真实 bug report,而不是设计推测。错过这次就得下 session 重做。

2. **v1.5.2 / v1.6.1 / v1.6.2 三个 Codex hotfix**:发现 bug 当场修,不等下次 session。因为 bug 修的越晚代价越大——一旦上面叠了新 commit,修底层 bug 就要 rebase。

3. **Step 10 streaming 替代 Step 10 crypto**:因为读了 hvoy.ai 源码后**确认 streaming 是我们真正的 detection gap**,而 crypto substitution 是 v3 原计划里"设计推测"的 step。实际看到的信号优先于设计推测。

**元规则**:**大方向坚持,具体实现按实际信息走**。不要为了"按计划执行"而忽略 session 中新出现的信息。

### 双分发不变量是如何保持的

这个项目有两份代码:`api_relay_audit/*.py`(模块化,用 httpx)和 `audit.py`(单文件,只用 curl)。所有改动必须同步,否则用户用 standalone 版本会看到不同行为。

**保险丝**:`tests/test_dual_distribution_parity.py` 里的一个测试——它抽取两个文件的"Overall Rating 风险矩阵"代码块,**逐字符比较**。如果不一致,测试红。这个测试是 v2.2 commit `df7715a` 时加的,每次 risk matrix 扩展(4D → 5D)都要严格保持两边同步。

**具体影响**:这个 session 加 D5 维度时,modular 和 standalone 的那段代码块必须**一字不差**相同。我提交前跑了 `python -m pytest tests/test_dual_distribution_parity.py -v`,green 才算完成。

**教训**:这种"逐字节一致性"测试听起来 brittle,但它是 dual-distribution 不变量的**唯一可靠保险丝**。不要因为它 brittle 就取消。

### Memory 里最值得保留的三条

按重要性排序:

1. **`reference_hvoy_relayapi.md`** — 这是竞品的完整分析,包括验证过的源码结构、porting status 表、我们相对它的优势和劣势。下次做竞品对比或产品定位时直接引用。
2. **`reference_litellm_secret_regex.md`** — 8 个 LiteLLM GitHub issue 的完整索引,每条都对应一个 Step 9 检测模式。这是 Step 9 精度的主要来源。
3. **`feedback_local_files_over_webfetch.md`** — 方法论级别的教训。每次要读外部源码都应该先查这个。

### 什么被延后了(backlog 更新)

这一节更新了本 session 里确定"明确不做"的事:

- **Step 11: Crypto Address Substitution**(原 PR 2)— 因为 hvoy.ai 读完后确认 streaming 是更大的 gap;crypto 是设计推测,等实际有 crypto relay 案例报告再做
- **Claude Code CLI 请求头伪装** — 从 hvoy.ai `get_headers` 里看到,但 port 意义不大(只让我们伪装成他们那个工具)
- **hvoy.ai 的 `"null"` text block request body 指纹** — 不清楚他们为什么这么写,port 会让我们的请求和他们的工具 indistinguishable,不 port
- **Knowledge cutoff 探测**(hvoy.ai 4 个维度之一)— 作者自己说易被 system prompt hard-code 欺骗,不值得
- **识别 "I am Claude, not GPT" 型残余 FP** — 需要 identity-phrase anchor regex(`"I am X"` / `"made by X"`),scope creep,留给 v1.7+
- **hvoy.ai leaderboard 40+ 真实中转站**作为自动化验证语料库 — 需要 consent + rate limiting 工程,留到工具 v2 或 v3
- **`--transparent-log <path>` flag**(arXiv §7.3)— 正交独立,下次 session 单独做

### 给下次 session 的你

1. **本 session 的结束状态**:本地 9 commits 已 push,origin/master 从 `b2e5447` → `42d5de7`,`.claude/` 仍 untracked(按预期)
2. **281/281 tests pass**,parity test green,没有任何 known regression
3. 下次 session 如果要继续:推荐 **`--transparent-log`** 或 **Step 11 Web3 injection probes**(SlowMist signature isolation),或者**本地 one-api Docker 实测**生成真实 before/after 命中率数据
4. 如果要 refactor,考虑把 `_parse_sse_stream` 的 `_process_sse_line` 辅助函数做成更通用的 SSE 解析库(目前只在 stream_integrity 里用)
5. memory 里的 `project_api_relay_audit_context.md` 是当前状态的 single source of truth,read it first

本 session 最值钱的不是代码,是**"5 轮 Codex review 找到 7 个真实 bug"这个数据点**。下次做任何复杂 feature,都 bake review 循环进计划。

---

## 2026-04-11~12 session diary: v2.3 → v1.7.5 独立 peer review + 10 个修复 commit

### 这个 session 干了什么

一轮完整的独立代码 review + audit,由 Claude Opus 执行,peer reviewer 同步提供 findings。**10 个 commit,测试 319 → 426（+107 新测试,零回归）**,修复了 7 个高危/中危 bug + 3 个架构级改进：

| Commit | 版本 | 内容 |
|---|---|---|
| `eff9349` | v1.7.4 | **Fix #1**: Anthropic `content[0].text` 展平 — thinking/tool_use 前置 block 导致 r["text"]=="" 级联 |
| `32153fe` | v1.7.4 | **Fix #2**: Web3 `immediately`/`clear it`/`立即` 过于通用的 safe marker |
| `019e1bf` | v1.7.4 | **Fix #3**: Step 4/6 宽 substring + 窄 refusal exemption |
| `6de838c` | — | CLAUDE.md 从 10-step/5D 更新到 11-step/6D |
| `1eaa620` | v1.7.4 | Step 4/6 clean 分支缺 green summary flag |
| `e8ecf10` | v1.7.5 | **Option D**: Pareto 最优 3 层泄漏检测（结构正则 + Claude self-ID 门控豁免） |
| `e24f89b` | v1.7.5 | fail-open step wrapper（单步崩溃不再中断整轮审计） |
| `72afc96` | v1.7.5 | Step 3/5 crash default 从 0/False 改为 None → d1i/d2i → MEDIUM |
| `498861d` | v1.7.5 | 结构正则 `\b` after `:` 修复 + crash→MEDIUM catch-all |
| `fb56d25` | v1.7.5 | 字符类 `[:|=]` 中管道符误匹配 → `[:=]` |

### 核心设计决策：Option D（Pareto 最优泄漏检测）

Fix #3（v1.7.4）把 refusal phrase 做成了 Step 4/6 弱标记的豁免条件,但 peer reviewer 指出"先拒绝、后泄漏"的矛盾响应会被误放过（"I refuse, but your system prompt is: You are a coding assistant"）。

跑了 4 个候选方案的 Pareto 前沿分析:

| 选项 | FNR | FPR | 判别力 |
|---|---|---|---|
| A: Step 4 regex only | 高 | 低 | 弱 |
| B: 一律 yellow | 低 | 高 | 差 |
| C: 密度阈值 | 低 | 中 | 中 |
| **D: refusal 豁免需 Claude self-ID** | **低** | **低** | **语义** |

D 的 insight:**真正的 Claude 响应会自称 Claude / 提到 Anthropic**;被注入的 Kiro/Doubao/GLM 人格会流利地 refuse 但不会说"I'm Claude"。所以"refusal + 弱标记 + 无 Claude self-ID" = 矛盾,判 YELLOW。

三层检测:
1. `STRUCTURAL_LEAK_PATTERNS`（regex）— 始终 RED
2. 弱标记 — 有 refusal + Claude self-ID → 豁免;有 refusal 无 Claude ID → **YELLOW 矛盾**;无 refusal → RED
3. `CLAUDE_SELF_ID_MARKERS` — 14 条含中文

### 核心架构改进：fail-open step wrapper

原来每个 step 在 `main()` 里裸跑,单步崩溃直接 abort。改成 `_run_step()` wrapper:
- 崩溃 → stderr traceback(不吞)+ yellow summary flag + 返回 default
- `KeyboardInterrupt` / `SystemExit` 不拦截
- `crashes` 列表 → `any_step_crashed` catch-all → MEDIUM

特别处理 Step 3/5:default 改为 None(不是 0/False),新增 d1i/d2i 维度进 MEDIUM 分支,防止 crash → LOW 的语义矛盾。

### peer reviewer 的 findings（全部确认并修复）

| Finding | 严重度 | 状态 |
|---|---|---|
| `content[0].text` 只取第一个 block | High | ✅ `eff9349` |
| `immediately` 是过于通用的 safe marker | High | ✅ `32153fe` |
| 宽 substring + 窄 refusal exemption | Medium | ✅ `019e1bf` → `e8ecf10` |
| "先拒绝后泄漏"矛盾被放过 | High | ✅ `e8ecf10` Option D |
| Step 4/6 clean 路径无 green flag | Medium | ✅ `1eaa620` |
| 单步 crash abort 全局 | High | ✅ `e24f89b` |
| Step 3/5 crash → LOW（无 d1i/d2i） | Medium | ✅ `72afc96` |
| `\b` after `:` 正则不命中 | High | ✅ `498861d` |
| Step 4/6/7 crash 无 MEDIUM catch-all | Medium | ✅ `498861d` |
| `[:|=]` 含管道符误匹配 | Medium | ✅ `fb56d25` |

### 给下次 session 的你

1. **本 session 的结束状态**:10 commits 已 push,origin/master 从 `9ce2cc2` → `fb56d25`
2. **426/426 tests pass**,parity test green,零 known regression
3. 风险矩阵现在是 6D + d1i/d2i + `any_step_crashed` catch-all
4. CLAUDE.md 已同步到 11-step/6D/v1.7.5
5. 本 session 和上一 session 加起来:**17 个 bug 被 review 循环捕获**。数据持续支撑"非平凡 PR 必须走 review 循环"这个结论


## 2026-04-18 session: v1.8 Infrastructure Audit Layer(Step 12 + 13)

### 做了什么

在 feature branch `feat/v1.8-infra-audit-layer` 上加了两个全新的 step,定位为 **informational only**,不喂 6D 风险矩阵:

| Commit | Scope | 内容 |
|--------|-------|------|
| `17387b0` | Step 12 | **Infra Fingerprint** — 3 个未认证 GET 探测(`/`, `/v1/models`, `/nonexistent-abc12345xyz`)+ 签名库匹配(new-api / one-api / lobechat-relay / fastgpt / cloudflare / nginx-raw / caddy-raw)+ 多数投票置信度(confirmed / tentative / unknown) |
| `3339bc1` | Step 13 | **Latency Variance** — N=10 个 identical `max_tokens=8` 探测,算 min/median/max/stdev/CV + largest-gap/median 双峰启发式。verdict = stable / variable / high-variance / bimodal / inconclusive |

### 为什么选这两个而不是其他三个候选

帕累托前沿选型。原候选池:(1) LLMmap 主动指纹,(2) 延迟方差,(3) Lite 能力基准,(4) ICP 备案 / 基础设施指纹。结论:

- **(1) LLMmap Pro**: PyTorch + transformers 4.5GB 依赖,破坏 dual-distribution 零依赖不变式,放 v2.5+
- **(3) 能力基准**: 2-3 周工期,需要 GPQA 子集 + 评分器 + 成本模型,放 v2.0
- **(2) + (4) 一起做**: 都是 pure stdlib,都是信息层(不动风险矩阵),互相配套(框架指纹 + 时延指纹 = 运营方画像)→ v1.8

### 技术要点

1. **双分布不变式保住了**。`audit.py`(standalone)里加了 Section 3f(framework signatures)和 Section 3g(latency stats),对应 `scripts/audit.py` 的 module import。Parity test(`test_dual_distribution_parity.py::test_risk_matrix_character_identical`)继续 green,因为风险矩阵那块 block 字节级零变动
2. **原子 commit 纪律**。每个 step 的 module / tests / scripts wiring / standalone sync 分别 commit,report renumbering(Overall Rating 从 "12." → "13." → "14.")也随每个 commit 同步,保证任何一个 commit checkout 都是 self-consistent report
3. **双峰启发式的选择**。没用 Hartigan dip test 或 GMM,因为 stdlib 里没有,而且 N=10 的样本量两者都不 robust。最终用 largest-gap / median > 0.5 的简单几何规则,tests 里用 cluster 1 (~1s) + cluster 2 (~5s) 验证命中,CV 低于 0.1 的 stable 分布不会误触发
4. **为什么 informational only**。Network jitter / 上游 warming / 区域故障切换都能在诚实 relay 上制造高方差,所以把 bimodal / high-variance 放进 D 矩阵会出 false positive。v1.8 的合同是:向 operator 展示 signal,由 operator 去 cross-reference Step 5 identity + Step 12 框架。未来如果有足够多 honest-relay 基线数据,可以考虑把这两项提升成 D7/D8

### v1.8 Codex review 闭环(同日追加)

初始 v1.8 落地后立刻跑了一轮独立 Codex 审查(`codex exec`,default model)。**三档 findings 全部处理,verdict = minor-fixes-needed → 零残留**:

| 严重度 | 问题 | 决策 | commit |
|---|---|---|---|
| 🔴 HIGH | Step 12 aggregate 用多数投票,edge-layer 信号(cf-ray / Server: cloudflare)会在 3 个 probe 上全部命中,drown out 仅在 `/` 命中的 app-layer 信号(one-api / new-api),结果把"Cloudflare 后面的 one-api"误报为纯 cloudflare | **Pareto 前沿分析后延后到 v1.8.1**:当前 Step 12 是 informational-only,per-probe 结果仍保留 app-layer 识别,只是聚合层面丢失。真修复(app/edge 分层返回 `{app, edge}` 元组)要改 `aggregate_framework` 签名 + audit.py wiring + 报告渲染 + 所有 call site。拿 测试锁定现行行为(`test_one_api_behind_cloudflare_aggregates_as_cloudflare` + `test_new_api_behind_cloudflare_aggregates_as_cloudflare`),标记为"已知限制",让任何未来改动必须 deliberate | `d0fb5d9` 文档化 |
| 🟡 MEDIUM | `detect_bimodality` 在 N=4 单 outlier 上假阳性:`[1.00, 1.01, 1.02, 1.80]` 返回 `(True, ~0.77)`——一个慢 probe 就判 bimodal,不合理 | **立即修**。规则改成:gap 搜索只看左右两侧都有 ≥2 样本的切分点。N=4 只 legal 中间切(2+2),outlier 场景直接被排除;真 2+2 分布(`[1.00, 1.01, 1.80, 1.82]`)仍然命中。双分布同步 | `4db33b7` |
| 🟢 LOW | 测试覆盖盲区:(1) app/edge 混合场景无断言,(2) 3 成功 / 7 错误的部分成功能否 reach classified verdict,(3) Step 12/13 的常量和聚合规则未走 parity 测试——允许一边改、另一边不改,悄悄 bifurcate detection behavior | **全部补上**。新增 5 个测试,含 N=4 outlier、N=4 真双峰、N=5/N=6 extreme outlier 的 cluster-size 规则、3succ/7err 的 CV-based verdict、Step 12/13 常量 dual-distribution parity | `d0fb5d9` |

### HIGH 为什么不立即改:Pareto 推理

候选 5 种方案,横轴工程成本 / 纵轴 false-positive 降低:

| 选项 | 工程成本 | FPR 减益 | 信息架构 |
|---|---|---|---|
| A: 改文案,明示"aggregate 只是边缘推断" | 0.2 | 0 | 不动 |
| B: aggregate 返回 `Counter` | 1 | 中 | 向后兼容打破 |
| C: app-layer + edge-layer 分层返回 | 3 | 高 | clean,但破坏多个 call site |
| D: 加权多数(app > edge) | 2 | 中高 | 隐式 heuristic,难解释 |
| E: 先测,有真实 baseline 数据再决定 | 0.1(测试) + 将来 | 未知 | 留 option |

**选 E 的理由**:Step 12 已经标为 informational-only,per-probe 层面仍然保留了 one-api / new-api 识别,operator 真要追 app-layer identity 还能看到。聚合层面丢失不造成 security false negative(不进风险矩阵),只是 operator-facing display 不够精细。真要改,应该带着至少一个 Cloudflare-fronted relay 的真实数据,否则我们是在猜 heuristic。把测试钉住当前行为,让任何未来想改的人必须 deliberate。

### Codex review 计数器 +1

加上本次 v1.8 round,累计 **6 轮独立 Codex review,发现 18 个真实 bug / limitation**。continuing 数据支撑"非平凡 PR 必须走 review 循环"的结论。

### 给下次 session 的你(更新)

1. **本 session 结束状态**:5 个 commit 已落地(`17387b0` Step 12,`3339bc1` Step 13,`308f980` docs,`4db33b7` MEDIUM fix,`d0fb5d9` LOW tests),**已 merge 到 master**,`origin/master` 推到 v1.8 完整版
2. **546/546 tests pass**(新增 24 infra + 20 latency + 5 Codex LOW coverage = 49 新测试),parity test green
3. v1.8.1 backlog(已 ROADMAP 登记):app-layer vs edge-layer 分层返回,条件是收集到至少一个 Cloudflare-fronted relay 的真实 fingerprint 数据
4. 下一步工作优先级:
   - **本地 one-api Docker 实测**(ROADMAP 近期候选 #1)——能同时给 Step 12/13 初始 baseline + 验证 v1.8.1 是否真的需要
   - **Crypto address substitution**(近期 #2)——spec 齐全,180 LOC,30 tests
   - **v2.0: 能力基准** — 跑小 GPQA / MMLU 子集,算命中率 delta,是"模型替换"的直接检测
   - **v2.5: LLMmap Pro** — 如果真的要做,得想清楚怎么和零依赖不变式共存(可能要走 optional extra: `pip install api-relay-audit[deep]`)

---

## 2026-04-20 session: v1.8.1 Codex review 循环 #2(handoff 前清理)

前端同事接手前的 handoff 前清理。第二轮 Codex 审查,5 个新发现,修了 4 个,HIGH 那条保持 v1.8.1 backlog 不动。

### Codex 审查 #2 结果摘要

| # | 严重 | 位置 | 发现 | 处置 |
|---|-----|------|------|------|
| 1 | HIGH | `infra_fingerprint.py:165-181` | majority vote 混淆 edge/app 层 | **不动**,已在 v1.8.1 backlog |
| 2 | MEDIUM | `latency_variance.py:166-182` + `client.py` | Step 13 首样本被 format detection 污染 | 修:新加 `APIClient.ensure_format()` 预热 |
| 3 | MEDIUM | `latency_variance.py:167-172` | `time.time()` 不单调 | 修:`time.perf_counter()` |
| 4 | LOW | `infra_fingerprint.py:68-72` | LobeChat 的 Next.js 头过于泛化 | 修:删孤立信号,留 body 品牌 |
| 5 | LOW | `--latency-probe-count` | 无边界校验(0 / 负数 / 超大) | 修:`validate_probe_count` + 11 个测试 |

### 为什么 MEDIUM #2 值得修

场景:新鲜 `APIClient` 打到 OpenAI-兼容的 relay。

```
第 1 次 call():
  尝试 Anthropic    → 失败    (~200ms)
  回退到 OpenAI    → 成功    (~600ms)
  合计往返:        ~800ms   ← Step 13 记录为首个"样本"

第 2..N 次 call():
  _format == "openai", 直达 ~600ms
```

首样本比后续高 30%。CV 被人为放大,可能假造成 bimodal。修法:`run_latency_variance` 开头先调一次 `client.ensure_format()`,把探测开销丢掉,之后测出的 N 次是真正同构的请求。

### 为什么 MEDIUM #3 值得修

`time.time()` 返回 wall clock — NTP 校时、VM host clock drift 都可能让连续两次调用之间出现负差(或异常大差)。`time.perf_counter()` 是单调高精度,不会被系统时间影响。Windows 上尤其重要,这次是 Windows 11 环境。

### 为什么 LOW #4 值得修

`x-powered-by: next.js` 命中率太高 — 所有 Vercel 站、所有营销页面都命中。如果 LobeChat relay 的 body 里没有 "lobechat" 字样(比如运营方改 UI),靠这个 header 会把任何 Next.js 站点判为 lobechat-relay。真正的 LobeChat fingerprint 是 body 里的品牌字符串,不是通用框架头。

### 为什么 LOW #5 值得修

`--latency-probe-count=0` 会进入 `run_latency_variance` 循环 0 次,导致 "0 successful / 0 failed" 的 inconclusive,文案报的是"all 0 probes failed",操作员看不懂。`--latency-probe-count=100000` 会线性放大时间 + 计费成本。`[3, 50]` 是合理带宽,超出直接 argparse 报错。

### 选择 Pareto-最优的"现在修 vs. 拖 v1.9"

| # | 修(min) | 收益 | Pareto |
|---|---------|------|--------|
| 2 | 30 | OpenAI 兼容 relay 的 variance 测量才准确 | ✅ 立即修 |
| 3 | 10 | 避免 Windows / 虚拟化环境的时钟伪影 | ✅ 立即修 |
| 4 | 5 | Vercel 站点不再被误判为 LobeChat | ✅ 立即修 |
| 5 | 15 | CLI 用户传错值有清晰错误信息 | ✅ 立即修 |

全部 1 小时内完成 + 14 个新测试 + 双分发同步。选 C(都修)明显优于 B(只修 MEDIUM)。

### Codex review 计数器 +1

累计 **7 轮独立 Codex review,19 个真实 bug / limitation**(上次 18 + 本次 HIGH 保留 + 4 个新修)。

### Codex 审查 #2 round 2(提交后复查)

`122f23d` 提交完立刻再跑一遍 Codex。代码层全对,但挑出 3 个**测试覆盖漏洞** — 就是那种"现在测的是哄孩子,改回旧实现依然全绿"的假阳性覆盖。

| # | 漏洞 | 闭环度 | 结论 |
|---|------|--------|------|
| 2 | `ensure_format` 只 mock 验证,没跑真身 `APIClient.ensure_format()` body | 部分 | 推到 v1.9 |
| 3 | `perf_counter` 切换只靠 `lat >= 0.0` 断言,用 `time.time()` 也过 | **否**(false-green 风险) | **立即补** |
| 5 | `validate_probe_count` 单测 OK,但没测 `parse_args()` 端到端接线 | 部分 | 推到 v1.9 |

挑最实的 #3 当场修。思路:monkeypatch 全局 `time.perf_counter` 成确定性 +1 计数器、`time.time` 成常量,跑 Step 13,断言:
- `perf_counter` 被调用 ≥ 2×probe 数(t0 + elapsed)
- `time.time` 在 timing 循环里**零调用**
- 测出的 latencies 恰好等于 fake clock 的增量(1.0 per probe)

如果谁 revert 回 `time.time()`,mock 的 client 秒回,elapsed ≈ 0,跟 1.0 对不上,测试当场爆。双分发都加了一份,`test_latency_variance.py` 锁 modular,`test_dual_distribution_parity.py` 锁 standalone。

#2 #5 没当场修的理由是:它们都是"防御强度不够"而不是"有洞",handoff 2 小时窗口,ROADMAP 登记比现场补更稳。

### 给下次 session 的你(更新 v3)

1. **本 session 结束状态**:562/562 测试通过(round 1 +14 + round 2 +2 = +16 新测试累计),ROADMAP 更新两处(v1.8.1 cycle #2 round 2 闭环节 + 新增 2.4 测试覆盖 follow-up 条目),双分发同步
2. v1.9 over-engineering prune **不做**,ROADMAP 登记了 Top 5 候选(最贵的是双分发不变量)。handoff 前删代码 = 给接手人埋雷
3. v1.9 新增 2.4 条目:#2 ensure_format 真身测试 + #5 argparse 端到端测试(共 ~40 LOC)。自然和 2.5 over-engineering prune 同 session 做
4. v1.8.1 app-layer/edge-layer 分层仍是下次 session 的最大 HIGH 候选,前置条件仍是本地 Docker 实测数据
5. LLMmap 整合(Step 14,v2.5)已 clone 到 `C:\Users\john\Downloads\LLMmap\` — 还没做 wrapper,等 handoff 结束再回来
6. **前端同事要看的东西**:`scripts/extract-data.py` + `web/data.json` 格式 + `web/` 目录(dashboard)。后端契约没变,只是 Step 13 的延迟数值现在更准
7. 累计 **7 轮独立 Codex review,21 个真实 bug / limitation / test-gap**(上次 19 + round 2 的 2 个测试覆盖 gap 进 backlog + 1 个 false-green 当场修)
