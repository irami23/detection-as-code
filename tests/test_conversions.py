import glob, subprocess, pytest

RULES = glob.glob("rules/**/*.yml", recursive=True)

def convert(rule, target, pipeline):
    return subprocess.run(
        ["sigma", "convert", "-t", target, "-p", pipeline, rule],
        capture_output=True, text=True)

@pytest.mark.parametrize("rule", RULES)
def test_converts_to_splunk(rule):
    r = convert(rule, "splunk", "sysmon")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip(), "empty SPL output"

@pytest.mark.parametrize("rule", RULES)
def test_converts_to_kusto(rule):
    r = convert(rule, "kusto", "microsoft_xdr")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip(), "empty KQL output"

def test_vss_rule_emits_expected_tokens():
    r = convert("rules/windows/process_creation/"
                "proc_creation_win_vss_shadow_copy_deletion.yml",
                "splunk", "sysmon")
    spl = r.stdout.lower()
    assert "vssadmin" in spl and "delete" in spl