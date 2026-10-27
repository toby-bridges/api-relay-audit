"""Tool documentation drift remains enforced without a website checkout."""
import importlib.util
from pathlib import Path

def _collector():
    path = Path(__file__).resolve().parent.parent / "scripts" / "collect-metrics.py"
    spec = importlib.util.spec_from_file_location("metrics_public_doc_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_readme_drift_is_detected_without_website(tmp_path):
    module = _collector()
    module.REPO_ROOT = tmp_path
    (tmp_path / "README.md").write_text("A 13-step audit.")
    failures = module.check_public_doc_drift({"step_count_modular": 14})
    assert failures and "uses 13, expected 14" in failures[0]

def test_tool_collector_does_not_treat_website_copy_as_tool_truth(tmp_path):
    module = _collector()
    module.REPO_ROOT = tmp_path
    (tmp_path / "README.md").write_text("A 14-step audit.")
    (tmp_path / "web").mkdir()
    (tmp_path / "web/index.html").write_text("An independently versioned 99-step audit.")
    assert module.check_public_doc_drift({"step_count_modular": 14}) == []
