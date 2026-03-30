"""Shared context length testing logic (canary markers + binary search)."""

import time
import uuid

FILLER = "abcdefghijklmnopqrstuvwxyz0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"


def single_context_test(client, target_k):
    """Test if model can recall 5 canary markers in target_k * 1000 chars of text.

    Returns: (target_k, found, total, input_tokens, status, elapsed)
    where status is "ok" or "truncated" or "error".
    """
    chars = target_k * 1000
    canaries = [f"CANARY_{i}_{uuid.uuid4().hex[:8]}" for i in range(5)]
    seg = (chars - 350) // 4
    parts = []
    for i in range(5):
        parts.append(f"[{canaries[i]}]")
        if i < 4:
            parts.append((FILLER * (seg // len(FILLER) + 1))[:seg])
    prompt = ("I placed 5 markers [CANARY_N_XXXXXXXX] in the text. "
              "List ALL you can find, one per line.\n\n" + "".join(parts))

    r = client.call([{"role": "user", "content": prompt}], max_tokens=512)
    if "error" in r:
        return target_k, 0, 5, None, "error", r.get("time", 0)
    found = sum(1 for c in canaries if c in r["text"])
    status = "ok" if found == 5 else "truncated"
    return target_k, found, 5, r["input_tokens"], status, r["time"]


def run_context_scan(client, coarse_steps=None, sleep_between=2):
    """Run coarse scan + binary search to find context truncation boundary.

    Returns: list of (target_k, found, total, input_tokens, status, elapsed) tuples.
    """
    if coarse_steps is None:
        coarse_steps = [50, 100, 200, 400, 600, 800]

    results = []
    last_ok, first_fail = 0, None

    # Coarse scan
    for k in coarse_steps:
        r = single_context_test(client, k)
        results.append(r)
        if r[4] == "ok":
            last_ok = k
        else:
            first_fail = k
            break
        time.sleep(sleep_between)

    # Binary search for precise boundary
    if first_fail:
        lo, hi = last_ok, first_fail
        while hi - lo > 20:
            mid = (lo + hi) // 2
            r = single_context_test(client, mid)
            results.append(r)
            if r[4] == "ok":
                lo = mid
            else:
                hi = mid
            time.sleep(sleep_between)
        # Fine scan
        for k in range(lo, hi + 1, 10):
            if not any(x[0] == k for x in results):
                results.append(single_context_test(client, k))
                time.sleep(sleep_between)

    results.sort()
    return results
