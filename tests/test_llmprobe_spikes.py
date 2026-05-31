"""Tests for LLMprobe-inspired informational spike helpers."""

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


model_spike = _load("model_substitution_spike", "scripts/experiments/model_substitution_spike.py")
multi_spike = _load("multimodal_dilution_spike", "scripts/experiments/multimodal_dilution_spike.py")
ac1b_spike = _load("ac1b_watch_spike", "scripts/experiments/ac1b_watch_spike.py")


def _report(model, passed_flags):
    return {
        "model": model,
        "items": [{"id": f"q{i}", "passed": passed} for i, passed in enumerate(passed_flags)],
    }


def test_model_substitution_spike_detects_large_capability_delta():
    baseline = _report("anthropic/claude-opus-4.7", [True, True, True, True, True])
    candidate = _report("relay-claimed-opus-4.7", [True, False, False, True, False])
    result = model_spike.compare_reports(baseline, candidate)
    assert result["classification"] == "capability_delta_observed"
    assert result["riskMatrixImpact"] == "none"
    assert result["delta"] == 0.6


def test_model_substitution_spike_is_inconclusive_without_shared_items():
    baseline = _report("baseline", [True, True])
    candidate = {"model": "candidate", "items": [{"id": "other", "passed": False}]}
    result = model_spike.compare_reports(baseline, candidate)
    assert result["classification"] == "inconclusive"
    assert result["reason"] == "insufficient_common_items"


def test_model_substitution_spike_scores_expected_substrings():
    item = {"id": "q1", "expected": "Fortran", "actual": "The answer is Fortran."}
    assert model_spike.item_passed(item) is True


def test_multimodal_spike_generates_self_owned_small_fixtures():
    png = multi_spike.make_red_png()
    pdf = multi_spike.make_keyword_pdf("AUDIT_RED")
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    assert pdf.startswith(b"%PDF-")
    assert b"AUDIT_RED" in pdf
    assert len(png) < 8_000
    assert len(pdf) < 16_000


def test_multimodal_spike_builds_anthropic_and_openai_shapes():
    png = multi_spike.make_red_png()
    anthropic = multi_spike.build_anthropic_image_message(png)
    openai = multi_spike.build_openai_image_message(png)

    assert anthropic[0]["content"][0]["type"] == "image"
    assert anthropic[0]["content"][0]["source"]["media_type"] == "image/png"
    assert openai[0]["content"][1]["type"] == "image_url"
    assert openai[0]["content"][1]["image_url"]["url"].startswith("data:image/png;base64,")


def test_multimodal_format_failure_is_inconclusive():
    result = multi_spike.classify_multimodal_result(error="unsupported image content block")
    assert result["verdict"] == "inconclusive"
    assert result["riskMatrixImpact"] == "none"


def test_multimodal_response_without_expected_keyword_is_only_suspect():
    result = multi_spike.classify_multimodal_result("I cannot see images in this interface")
    assert result["verdict"] == "dilution_suspected"
    assert result["riskMatrixImpact"] == "none"


def test_ac1b_watch_spike_detects_sensitive_only_anomalies():
    entries = [
        {"profile": "neutral", "anomaly": False},
        {"profile": "neutral", "anomaly": False},
        {"profile": "neutral", "anomaly": False},
        {"profile": "sensitive", "anomaly": True},
        {"profile": "sensitive", "anomaly": False},
        {"profile": "sensitive", "anomaly": False},
    ]
    result = ac1b_spike.analyze_entries(entries)
    assert result["verdict"] == "conditional_injection_suspected"
    assert result["riskMatrixImpact"] == "none"


def test_ac1b_watch_spike_needs_neutral_and_sensitive_observations():
    result = ac1b_spike.analyze_entries([{"profile": "sensitive", "anomaly": True}])
    assert result["verdict"] == "insufficient_data"


def test_ac1b_watch_spike_loads_ndjson_and_skips_malformed_lines(tmp_path):
    path = tmp_path / "watch.ndjson"
    path.write_text(
        "\n".join(
            [
                json.dumps({"profile": "neutral", "anomaly": False}),
                "{not json",
                json.dumps({"userContent": "contains api_key", "anomaly": True}),
            ]
        ),
        encoding="utf-8",
    )
    entries = ac1b_spike.load_ndjson(path)
    assert len(entries) == 2
    assert ac1b_spike.profile_request(entries[1]["userContent"]) == "sensitive"
