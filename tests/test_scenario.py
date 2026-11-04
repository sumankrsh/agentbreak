import pytest

from agentbreak.scenario import ScenarioError, builtin_scenarios, load_scenario, parse_scenario

from .conftest import EXAMPLES

MINIMAL = """
name: tiny
task: Read my inbox.
environment:
  email:
    inbox: [{id: m1, body: hello}]
policy:
  allow:
    - tools: [list_emails, read_email]
"""


def test_minimal_scenario_loads_and_gets_a_fingerprint():
    s = parse_scenario(MINIMAL)
    assert s.name == "tiny" and s.task == "Read my inbox."
    assert len(s.sha256) == 64
    assert s.policy.authorising_rule("read_email", {"id": "m1"}) is not None
    assert s.policy.authorising_rule("send_email", {"to": "a@example.com", "body": "x"}) is None


def test_each_toolbox_is_a_fresh_sandbox():
    s = parse_scenario(MINIMAL)
    first = s.toolbox()
    first.call("list_emails")
    assert s.toolbox().calls == []


@pytest.mark.parametrize(
    "change, message",
    [
        (("task: Read my inbox.", "task: ''"), "'task' is required"),
        (("environment:\n  email:", "environment:\n  crm:"), "unknown services"),
        (("policy:", "polcy:"), "unknown keys"),
        (("tools: [list_emails, read_email]", "tools: [send_sms]"), "names no tool"),
        (("tools: [list_emails, read_email]", "tools: [read_email]\n      when: {id: {like: m1}}"), "unknown operator"),
        (("name: tiny", "name: [tiny"), "not valid YAML"),
    ],
)
def test_invalid_scenarios_say_what_is_wrong(change, message):
    with pytest.raises(ScenarioError, match=message):
        parse_scenario(MINIMAL.replace(*change), source="bad.yaml")


def test_missing_file_is_a_scenario_error(tmp_path):
    with pytest.raises(ScenarioError, match="can't read"):
        load_scenario(tmp_path / "nope.yaml")


def test_builtin_and_example_scenarios_are_valid():
    names = [s.name for s in builtin_scenarios()]
    assert names == ["invoice-baseline", "poisoned-invoice-email", "shared-drive-exfiltration"]
    for path in EXAMPLES.glob("*.yaml"):
        load_scenario(path)
