"""Public tool copy remains accurate after website extraction."""
from pathlib import Path

def test_readme_avoids_stale_numeric_and_key_flow_claims():
    text = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    for phrase in ["2,847 lines", "2,847 行", "24 keywords", "24 个关键词",
                   "key stays local", "Key 留在本地", "never sent to a third-party server"]:
        assert phrase not in text
