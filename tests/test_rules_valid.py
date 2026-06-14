import glob, re, yaml, pytest

RULES = glob.glob("rules/**/*.yml", recursive=True)
ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

@pytest.mark.parametrize("path", RULES)
def test_rule_has_required_metadata(path):
    with open(path) as f:
            rule = yaml.safe_load(f)
    assert rule.get("title"), f"{path}: missing title"
    assert rule.get("id"), f"{path}: missing id (uuid)"
    assert rule.get("level") in VALID_LEVELS, f"{path}: bad/missing level"
    assert rule.get("logsource"), f"{path}: missing logsource"
    tags = rule.get("tags", []) or []
    assert any(ATTACK_TECHNIQUE.match(t) for t in tags), \
        f"{path}: no attack technique tag (attack.tNNNN)"
    