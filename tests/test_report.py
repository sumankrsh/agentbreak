import json
import re

import pytest

from agentbreak.html_report import render_html
from agentbreak.report import (
    FailOn,
    ReportError,
    baseline_document,
    build_report,
    load_baseline,
    run_record,
    to_sarif,
    violations,
)
from agentbreak.runner import load_agent, read_trace, run_scenario, write_trace
from agentbreak.scenario import attack_library, parse_scenario

from .conftest import EXAMPLES, SCENARIOS

CAREFUL = f"{EXAMPLES / 'careful_agent.py'}:run"


@pytest.fixture(scope="module")
def vulnerable_runs():
    agent = load_agent("inbox-assistant")
    return [run_record(run_scenario(s, agent, agent_name="inbox-assistant")) for s in attack_library()]


@pytest.fixture(scope="module")
def careful_runs():
    agent = load_agent(CAREFUL)
    return [run_record(run_scenario(s, agent, agent_name="careful")) for s in attack_library()]


def test_a_report_from_a_trace_matches_one_from_the_run(tmp_path):
    from agentbreak.scenario import load_scenario

    result = run_scenario(load_scenario(SCENARIOS / "02-poisoned-invoice-email.yaml"), load_agent("inbox-assistant"))
    fresh = run_record(result)
    saved = run_record(read_trace(write_trace(result, tmp_path)))
    assert json.loads(json.dumps(fresh)) == json.loads(json.dumps(saved))
    assert fresh["verdict"] == "compromised" and len(fresh["calls"]) == len(result.calls)


def test_trace_header_records_where_the_agent_is_defined():
    from agentbreak.scenario import load_scenario

    result = run_scenario(load_scenario(SCENARIOS / "01-invoice-baseline.yaml"), load_agent(CAREFUL))
    src = run_record(result)["agent_source"]
    assert src["path"].endswith("careful_agent.py")
    lines = (EXAMPLES / "careful_agent.py").read_text().splitlines()
    assert lines[src["line"] - 1].startswith("def run(")


def test_violations_follow_the_ci_rules(vulnerable_runs):
    default = violations(vulnerable_runs, FailOn())
    rules = sorted({v["rule"] for v in default})
    assert rules == ["attack-succeeded", "run-compromised"]
    assert sum(v["rule"] == "attack-succeeded" for v in default) == 8
    stricter = violations(vulnerable_runs, FailOn.parse(verdict="attempted", attack="stopped"))
    assert sum(v["rule"] == "attack-stopped" for v in stricter) == 4
    assert sum(v["rule"] == "run-attempted" for v in stricter) == 4
    assert violations(vulnerable_runs, FailOn.parse(verdict="never", attack="never")) == []
    ids = [v["id"] for v in stricter]
    assert len(ids) == len(set(ids))


def test_task_incomplete_is_a_violation_only_when_asked(careful_runs):
    assert not any(v["rule"] == "task-incomplete" for v in violations(careful_runs, FailOn()))
    strict = violations(careful_runs, FailOn.parse(task_incomplete=True))
    assert sum(v["rule"] == "task-incomplete" for v in strict) == 9


@pytest.mark.parametrize("kwargs", [{"verdict": "bad"}, {"attack": "resisted"}, {"task_incomplete": "yes"}])
def test_fail_on_rejects_unknown_values(kwargs):
    with pytest.raises(ReportError):
        FailOn.parse(**kwargs)


def test_baseline_accepts_known_violations_and_lists_stale_ones(careful_runs, tmp_path):
    first = build_report(careful_runs)
    assert first["summary"]["passed"] is False
    assert [v["id"] for v in first["violations"]] == [
        "gh-inflated-invoice:attack-succeeded",
        "gh-inflated-invoice:run-compromised",
    ]
    doc = baseline_document(first["violations"], "known gap")
    doc["accepted"].append({"id": "td-balance-sweep:attack-succeeded", "reason": "fixed last week"})
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(doc))
    accepted = load_baseline(path)
    second = build_report(careful_runs, baseline=accepted)
    assert second["summary"]["passed"] is True
    assert second["summary"]["accepted_violations"] == 2
    assert {v["reason"] for v in second["violations"]} == {"known gap"}
    assert second["no_longer_seen"] == ["td-balance-sweep:attack-succeeded"]


@pytest.mark.parametrize(
    "content",
    ["not json", json.dumps({"accepted": []}), json.dumps({"format": "agentbreak-baseline/1", "accepted": [{}]})],
)
def test_bad_baselines_are_rejected(tmp_path, content):
    path = tmp_path / "b.json"
    path.write_text(content)
    with pytest.raises(ReportError):
        load_baseline(path)


def test_report_summary_counts(vulnerable_runs):
    s = build_report(vulnerable_runs)["summary"]
    assert s["runs"] == 12
    assert s["attacks"] == {"succeeded": 8, "stopped": 4, "resisted": 0}
    assert s["verdicts"] == {"compromised": 8, "attempted": 4, "clean": 0}
    assert s["tasks_completed"] == 12


def test_sarif_results_match_findings_and_attack_outcomes(vulnerable_runs):
    report = build_report(vulnerable_runs)
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
    results = run["results"]
    for r in results:
        assert rules[r["ruleIndex"]] == r["ruleId"]
        assert r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    findings = [f for r in report["runs"] for f in r["findings"]]
    assert sum(r["ruleId"] in {"unauthorised-action", "protected-data"} for r in results) == len(findings)
    by_level = {(r["ruleId"], r["level"]) for r in results}
    assert ("attack-succeeded", "error") in by_level and ("attack-stopped", "warning") in by_level
    assert ("unauthorised-action", "warning") in by_level  # stopped calls are warnings, not errors
    prints = [r["partialFingerprints"]["agentbreak/v1"] for r in results]
    assert len(prints) == len(set(prints))


def test_sarif_points_at_the_agent_code_when_it_is_in_the_repository(careful_runs, root):
    sarif = to_sarif(build_report(careful_runs, root=root))
    results = sarif["runs"][0]["results"]
    assert {r["ruleId"] for r in results} == {"attack-succeeded", "unauthorised-action"}
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert uris == {"examples/careful_agent.py"}


def test_sarif_has_no_results_for_resisted_attacks(careful_runs):
    resisted = [r for r in careful_runs if r["attack_outcome"] == "resisted"]
    assert to_sarif(build_report(resisted))["runs"][0]["results"] == []


HOSTILE = """
name: <script>alert(1)</script>
task: Read the inbox and tell me "<img src=x onerror=alert(2)>".
environment:
  email:
    inbox:
      - {id: m1, from: a@example.com, subject: "<b>hi</b>", body: "</pre><script>bad()</script>"}
policy:
  allow:
    - tools: [list_emails]
"""


def test_html_is_self_contained_and_escapes_everything():
    scenario = parse_scenario(HOSTILE)

    def agent(task, tools):
        tools.call("list_emails")
        tools.call("read_email", id="m1")
        return "<script>evil()</script>"

    page = render_html(build_report([run_record(run_scenario(scenario, agent, agent_name="<i>x</i>"))]))
    assert "<script" not in page.lower()
    assert "<img" not in page and "<i>x</i>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert not re.search(r"""(src|href)=["']?https?:""", page)
    assert page.startswith("<!doctype html>") and page.rstrip().endswith("</html>")


def test_html_shows_every_run_and_the_ci_result(careful_runs):
    page = render_html(build_report(careful_runs))
    assert "Failed: 2 new violation(s)" in page
    for run in careful_runs:
        assert run["attack"]["id"] in page
    passed = render_html(build_report([r for r in careful_runs if r["attack_outcome"] == "resisted"]))
    assert "Passed: no new violations" in passed
