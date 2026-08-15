"""Stream integrity signals for Step 10 SSE-level relay tampering detection.

This module provides the data structures that capture what an
Anthropic-format streaming response looked like at the SSE event
layer. The actual verdict logic (:func:`analyze_stream`) is added in
a follow-up commit (Sub-PR 2); this commit ships the dataclass plus
constants so :meth:`api_relay_audit.client.APIClient.stream_call`
has something to populate.

## Detection approach

A malicious relay that rewrites or proxies Claude's streaming
responses can be caught at four distinct layers, even if the final
text the user sees looks correct:

1. **SSE event whitelist.** Anthropic's stream schema uses exactly
   7 event types (see :data:`KNOWN_SSE_EVENT_TYPES`). An unknown
   event type in the stream is a strong fingerprint of a relay that
   is injecting or rewriting events. Sub-PR 2's ``analyze_stream``
   penalises any unknown event.
2. **Usage-field monotonicity.** The ``message_start`` event carries
   an ``input_tokens`` count; subsequent ``message_delta`` events
   carry incremental ``output_tokens`` and a reiteration of
   ``input_tokens``. A relay that rewrites usage (to under-bill the
   caller or hide a model downgrade) often fails these invariants:
   ``output_tokens`` may go non-monotonic, or ``input_tokens`` may
   mysteriously shift between events.
3. **Thinking block signature consistency.** Claude Opus/Sonnet 4.6
   extended-thinking responses emit ``signature_delta`` events whose
   ``signature`` field must be non-empty. A relay that degrades to
   a non-thinking model and fakes the surrounding stream events may
   leave the signatures empty. :attr:`StreamSignals.empty_signature_delta_count`
   counts these.
4. **Terminal completeness.** A valid Anthropic message has exactly one
   ``message_stop`` after ``message_start``, with no later content event.
   Trailing ``ping`` keepalives are allowed. A graceful HTTP close or a
   generic ``[DONE]`` sentinel does not replace this protocol terminator.

## Attribution

The threat model and the specific list of observable signals is
inspired by hvoy.ai's ``zzsting88/relayAPI`` ``claude_detector.py``
``StreamSignals`` dataclass (verified against the source on
2026-04-11). The upstream repository has no ``LICENSE`` file, so
this module is an independent clean-room reimplementation:

- The field NAMES (``event_types``, ``message_start_model``,
  ``empty_signature_delta_count`` etc.) overlap with hvoy.ai's
  because they describe the same Anthropic SSE schema — schema
  field names and protocol event types are not copyrightable.
- The field TYPES and default factories are our own choices.
- The scoring / verdict logic in Sub-PR 2 will be tri-state
  (``clean`` / ``anomaly`` / ``inconclusive``), NOT hvoy.ai's
  weighted 0-100 score model.

See the ``reference_hvoy_relayapi`` memory file for the full
verification and the list of things we chose NOT to port
(knowledge cutoff probe, Claude Code CLI header impersonation,
``"null"`` text-block request body fingerprint).

Reference: Liu, Shou, Wen, Chen, Fang, Feng, *"Your Agent Is Mine:
Measuring Malicious Intermediary Attacks on the LLM Supply Chain"*,
arXiv:2604.08407, section 4.2. SSE whitelist / usage monotonicity
/ signature consistency are AC-1-class detections at the transport
layer.
"""

from dataclasses import dataclass, field
from typing import List, Optional


# The 7 known Anthropic SSE event types. Anything else in an
# ``event_types`` list is an "unknown event" — a potential signal
# that a relay is injecting or rewriting SSE events. Sourced from
# reading ``claude_detector.py`` lines 369-377 of
# ``zzsting88/relayAPI`` on 2026-04-11.
KNOWN_SSE_EVENT_TYPES = frozenset({
    "ping",
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
})


@dataclass
class StreamSignals:
    """Captures what a streaming Anthropic response looked like at
    the SSE event layer.

    Populated by :meth:`api_relay_audit.client.APIClient.stream_call`
    during the request; consumed by
    :func:`analyze_stream` (added in Sub-PR 2) afterwards.

    All fields default to the "nothing observed" value so that a
    stream that errored out still produces a valid, serialisable
    signals object. Downstream consumers must check
    :attr:`transport_error` before drawing conclusions about
    "clean vs anomalous" — an empty signals object with an error
    should be reported as *inconclusive*, not *clean*.

    Attributes:
        event_types: Ordered list of every SSE event type observed
            in the stream, including unknown types. Used for the
            whitelist check.
        content_block_types: Types observed in
            ``content_block_start`` events (e.g. ``"text"`` or
            ``"thinking"``), in arrival order.
        delta_types: Types observed in ``content_block_delta``
            events (e.g. ``"text_delta"``, ``"thinking_delta"``,
            ``"signature_delta"``), in arrival order.
        has_message_start: True iff at least one ``message_start``
            event was observed.
        has_content_block_start: True iff at least one
            ``content_block_start`` event was observed.
        has_content_block_delta: True iff at least one
            ``content_block_delta`` event was observed.
        has_message_delta: True iff at least one ``message_delta``
            event was observed.
        has_message_stop: True iff at least one ``message_stop``
            event was observed.
        has_text_delta: True iff at least one ``text_delta`` inside
            a ``content_block_delta`` was observed.
        thinking_start_seen: True iff a ``content_block_start`` with
            ``content_block.type == "thinking"`` was observed.
        thinking_delta_seen: True iff at least one ``thinking_delta``
            was observed inside a ``content_block_delta``.
        message_start_model: The ``message.model`` field from the
            first ``message_start`` event, or ``None`` if missing.
            A relay that routes ``claude-*`` to a non-Claude model
            often leaks the truth here.
        input_tokens: The ``input_tokens`` value from the first
            ``message_start`` event's ``usage`` block, or ``None``.
        message_delta_input_tokens_samples: Every ``input_tokens``
            value observed in ``message_delta`` events. Used to
            detect rewriting — these should all equal
            :attr:`input_tokens`.
        output_tokens_samples: Every ``output_tokens`` value
            observed in ``message_delta`` events, in arrival order.
            Used to check monotonicity (each sample should be
            greater than or equal to the previous one).
        empty_signature_delta_count: Number of ``signature_delta``
            events with an empty or whitespace-only signature field.
            > 0 is a thinking-block downgrade signal.
        transport_error: Non-``None`` iff the stream could not be
            opened or parsed cleanly (connection error, non-200
            response status, timeout). Downstream consumers should
            treat this as *inconclusive*, never *clean*.
        total_duration_seconds: Wall clock time from request start
            to stream close. Useful for detecting buffered-rewriter
            relays that delay the entire response.
        raw_event_count: Total number of events parsed from the
            stream, including unknown types. Zero means no data was
            received at all — another inconclusive signal.
    """

    # Ordered event type sequence (for whitelist check)
    event_types: List[str] = field(default_factory=list)
    # Content block types observed in content_block_start events
    content_block_types: List[str] = field(default_factory=list)
    # Delta types observed in content_block_delta events
    delta_types: List[str] = field(default_factory=list)

    # Boolean presence flags for convenient queries
    has_message_start: bool = False
    has_content_block_start: bool = False
    has_content_block_delta: bool = False
    has_message_delta: bool = False
    has_message_stop: bool = False
    has_text_delta: bool = False
    thinking_start_seen: bool = False
    thinking_delta_seen: bool = False

    # Identity and usage signals
    message_start_model: Optional[str] = None
    input_tokens: Optional[int] = None
    message_delta_input_tokens_samples: List[int] = field(default_factory=list)
    output_tokens_samples: List[int] = field(default_factory=list)

    # Thinking block anomaly counters
    empty_signature_delta_count: int = 0

    # Transport and timing
    transport_error: Optional[str] = None
    total_duration_seconds: Optional[float] = None
    raw_event_count: int = 0


# ---------------------------------------------------------------------------
# Verdict analysis (Sub-PR 2)
# ---------------------------------------------------------------------------

# Cap for how many unknown event types we report in findings output.
# hvoy.ai's claude_detector.py uses -6 as a numeric penalty cap on the
# SSE shape score; we don't use numeric scoring but we cap the list
# length at 6 to keep report output bounded even on pathological relays.
MAX_UNKNOWN_EVENTS_REPORTED = 6


def _check_usage_monotonic(signals: "StreamSignals") -> bool:
    """``output_tokens_samples`` must be monotonically non-decreasing.

    An empty list is vacuously monotonic; a single-element list is too.
    """
    samples = signals.output_tokens_samples
    if len(samples) <= 1:
        return True
    for i in range(1, len(samples)):
        if samples[i] < samples[i - 1]:
            return False
    return True


def _check_usage_consistent(signals: "StreamSignals") -> bool:
    """``message_delta`` ``input_tokens`` samples must agree with the
    ``input_tokens`` reported by the initial ``message_start``.

    A relay that rewrites usage (to hide a model downgrade or
    under-bill the caller) often fails this invariant. Returns True
    if consistent (or if there's nothing to compare)."""
    if signals.input_tokens is None:
        return True
    if not signals.message_delta_input_tokens_samples:
        return True
    return all(
        sample == signals.input_tokens
        for sample in signals.message_delta_input_tokens_samples
    )


def _check_stream_model(signals: "StreamSignals") -> bool:
    """``message_start.message.model`` should contain ``"claude"`` for
    an Anthropic-format streaming response.

    Missing ``message_start.message.model`` is itself suspicious once the
    relay has emitted substantive events: a middleware can hide a model
    downgrade simply by stripping the field instead of exposing a
    non-Claude upstream name. The "no events received" branch is handled
    earlier in :func:`analyze_stream` as inconclusive.
    """
    if not signals.message_start_model:
        return False
    return "claude" in signals.message_start_model.lower()


def _check_stream_complete(signals: "StreamSignals") -> bool:
    """Require one terminal ``message_stop`` after ``message_start``."""
    non_ping_events = [event for event in signals.event_types if event != "ping"]
    if non_ping_events.count("message_stop") != 1:
        return False
    if "message_start" not in non_ping_events:
        return False
    start_index = non_ping_events.index("message_start")
    stop_index = non_ping_events.index("message_stop")
    return start_index < stop_index == len(non_ping_events) - 1


def analyze_stream(signals: "StreamSignals") -> dict:
    """Analyze a populated :class:`StreamSignals` for integrity anomalies.

    Returns a dict with these keys:

    - ``verdict``: ``"clean"`` / ``"anomaly"`` / ``"inconclusive"``
    - ``event_shape``: ``"pass"`` / ``"partial"`` / ``"weak"``
    - ``unknown_events``: list of unknown event types (capped at
      :data:`MAX_UNKNOWN_EVENTS_REPORTED`)
    - ``usage_monotonic``: bool
    - ``usage_consistent``: bool
    - ``signature_valid``: bool
    - ``stream_complete``: bool; exactly one terminal ``message_stop`` was
      observed after ``message_start`` (trailing pings are allowed)
    - ``stream_model_name``: ``message_start.message.model`` or ``None``
    - ``stream_model_is_claude``: bool
    - ``findings``: list of human-readable reasons (empty on clean)

    Verdict priority (first match wins):

    1. **inconclusive** — ``transport_error`` is non-None, OR
       ``raw_event_count == 0``, OR only ``ping`` events were seen
       (a stream that opens but never sends ``message_start`` is
       either broken or non-Anthropic; we have no basis to judge).
    2. **anomaly** — at least one of: unknown event types present,
       usage non-monotonic, usage inconsistent, empty
       ``signature_delta`` count > 0, missing/duplicate/misordered terminal
       ``message_stop``, stream model name non-Claude.
    3. **clean** — none of the above triggered.

    The function is pure and deterministic: identical input always
    produces identical output. No I/O.
    """
    # Priority 1: inconclusive via transport error
    if signals.transport_error:
        return {
            "verdict": "inconclusive",
            "event_shape": "weak",
            "unknown_events": [],
            "usage_monotonic": True,
            "usage_consistent": True,
            "signature_valid": True,
            "stream_complete": False,
            "stream_model_name": signals.message_start_model,
            "stream_model_is_claude": True,
            "findings": [f"Stream transport error: {signals.transport_error}"],
        }

    # Priority 1b: inconclusive via no substantive events
    non_ping_events = [e for e in signals.event_types if e != "ping"]
    if signals.raw_event_count == 0 or not non_ping_events:
        return {
            "verdict": "inconclusive",
            "event_shape": "weak",
            "unknown_events": [],
            "usage_monotonic": True,
            "usage_consistent": True,
            "signature_valid": True,
            "stream_complete": False,
            "stream_model_name": signals.message_start_model,
            "stream_model_is_claude": True,
            "findings": [
                "Stream opened but produced no non-ping events — the "
                "relay is either broken or does not speak Anthropic SSE"
            ],
        }

    # Gather all anomaly signals (no early return — callers benefit
    # from knowing every reason for the verdict).
    unknown_events = sorted({
        e for e in signals.event_types if e not in KNOWN_SSE_EVENT_TYPES
    })
    unknown_events_capped = unknown_events[:MAX_UNKNOWN_EVENTS_REPORTED]

    usage_monotonic = _check_usage_monotonic(signals)
    usage_consistent = _check_usage_consistent(signals)
    signature_valid = signals.empty_signature_delta_count == 0
    stream_complete = _check_stream_complete(signals)
    stream_model_is_claude = _check_stream_model(signals)

    findings = []
    if unknown_events:
        suffix = " (+more, capped)" if len(unknown_events) > MAX_UNKNOWN_EVENTS_REPORTED else ""
        findings.append(
            f"Stream contained {len(unknown_events)} unknown SSE event "
            f"type(s): {', '.join(unknown_events_capped)}{suffix}"
        )
    if not usage_monotonic:
        findings.append(
            "output_tokens samples across message_delta events went "
            "backwards at least once — a relay is rewriting usage fields"
        )
    if not usage_consistent:
        findings.append(
            f"input_tokens at message_start ({signals.input_tokens}) "
            f"disagrees with message_delta samples "
            f"({signals.message_delta_input_tokens_samples}) — usage rewrite"
        )
    if not signature_valid:
        findings.append(
            f"{signals.empty_signature_delta_count} signature_delta event(s) "
            "had empty signatures — thinking block downgrade or rewriter"
        )
    if not stream_complete:
        stop_count = signals.event_types.count("message_stop")
        non_ping_events = [event for event in signals.event_types if event != "ping"]
        if stop_count == 0:
            findings.append(
                "Stream ended without message_stop — a truncated Anthropic "
                "response was not completed"
            )
        elif stop_count > 1:
            findings.append(
                f"Stream contained {stop_count} message_stop events — "
                "the terminal marker must appear exactly once"
            )
        elif "message_start" not in non_ping_events or (
            non_ping_events.index("message_stop")
            < non_ping_events.index("message_start")
        ):
            findings.append(
                "message_stop appeared before message_start — invalid "
                "Anthropic stream ordering"
            )
        else:
            findings.append(
                "Non-ping SSE events appeared after message_stop — the "
                "terminal marker was not final"
            )
    if not stream_model_is_claude:
        if signals.message_start_model:
            findings.append(
                f"Stream's message_start.message.model = "
                f"{signals.message_start_model!r} does not contain 'claude' — "
                "relay may be routing to a substitute model"
            )
        else:
            findings.append(
                "Stream omitted message_start.message.model entirely — "
                "relay may be stripping model identity to hide a downgrade"
            )

    anomaly = bool(
        unknown_events
        or not usage_monotonic
        or not usage_consistent
        or not signature_valid
        or not stream_complete
        or not stream_model_is_claude
    )

    # Event-shape classification (human-readable summary for reporting).
    shape_flags_seen = sum([
        signals.has_message_start,
        signals.has_content_block_start,
        signals.has_content_block_delta,
        signals.has_message_delta,
        signals.has_message_stop,
    ])
    if (
        shape_flags_seen >= 4
        and signals.has_text_delta
        and not unknown_events
        and stream_complete
    ):
        event_shape = "pass"
    elif shape_flags_seen >= 2:
        event_shape = "partial"
    else:
        event_shape = "weak"

    return {
        "verdict": "anomaly" if anomaly else "clean",
        "event_shape": event_shape,
        "unknown_events": unknown_events_capped,
        "usage_monotonic": usage_monotonic,
        "usage_consistent": usage_consistent,
        "signature_valid": signature_valid,
        "stream_complete": stream_complete,
        "stream_model_name": signals.message_start_model,
        "stream_model_is_claude": stream_model_is_claude,
        "findings": findings,
    }
