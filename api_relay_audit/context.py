"""Shared context length testing logic (canary markers + binary search)."""

import time
import uuid

FILLER = "abcdefghijklmnopqrstuvwxyz0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"


def single_context_test(client, target_k):
    """Test whether the model can recall canary markers embedded in filler text.

    Five unique ``CANARY_N_<hex>`` markers are placed at evenly spaced
    intervals inside ``target_k * 1000`` characters of filler.  The model
    is asked to list every marker it can find; the number found indicates
    how much of the context window was actually processed.

    Args:
        client: An ``APIClient`` instance used to send the prompt.
        target_k: Desired context size expressed in thousands of
            characters (e.g. ``200`` means ~200 000 chars).

    Returns:
        A 6-tuple ``(target_k, found, total, input_tokens, status, elapsed)``
        where:

        - ``target_k`` (int): The requested size (echo of the argument).
        - ``found`` (int): Number of canaries the model recalled.
        - ``total`` (int): Total canaries planted (always 5).
        - ``input_tokens`` (int | None): Token count, or ``None`` on error.
        - ``status`` (str): ``"ok"`` if all 5 found, ``"truncated"`` if
          fewer, or ``"error"`` if the API call failed.
        - ``elapsed`` (float): Wall-clock seconds for the API call.
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
    """Find the relay's context-truncation boundary via coarse scan + binary search.

    First, a coarse sweep tests progressively larger context sizes.  When
    a size fails (fewer than 5 canaries recalled), a binary search
    between the last passing and first failing size narrows the boundary
    to within ~10 k-chars, followed by a fine 10-step sweep.

    Args:
        client: An ``APIClient`` instance used to send prompts.
        coarse_steps: List of context sizes (in k-chars) for the initial
            sweep.  Defaults to ``[50, 100, 200, 400, 600, 800]``.
        sleep_between: Seconds to pause between API calls to avoid
            rate-limiting. Defaults to 2.

    Returns:
        A sorted list of result tuples, each in the format returned by
        ``single_context_test``:
        ``(target_k, found, total, input_tokens, status, elapsed)``.

    Examples:
        >>> from api_relay_audit.client import APIClient
        >>> client = APIClient("https://relay.example.com", "sk-...", "claude-3")
        >>> results = run_context_scan(client, coarse_steps=[50, 100, 200])
        >>> for r in results:
        ...     print(f"{r[0]}k: {r[1]}/{r[2]} canaries, status={r[4]}")
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
