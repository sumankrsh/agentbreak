import json
import shutil

import pytest
from typer.testing import CliRunner

from agentbreak.ci import github_annotations, load_config
from agentbreak.cli import app
from agentbreak.report import ReportError

from .conftest import EXAMPLES, SCENARIOS

runner = CliRunner()


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A copy of examples/ in a temporary folder, as the working directory."""
    shutil.copytree(EXAMPLES, tmp_path / "examples")
    shutil.copy(EXAMPLES.parent / "agentbreak.yaml", tmp_path / "agentbreak.yaml")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    return tmp_path


def test_example_config_fails_on_the_inflated_invoice_and_writes_every_report(project):
    result = runner.invoke(app, ["ci"])
    assert result.exit_code == 1, result.output
    assert "FAILED: 2 new violation(s)" in result.output
    out = project / "agentbreak-report"
    assert {p.name for p in out.iterdir()} == {"report.json", "report.sarif", "report.html", "traces"}
    assert len(list((out / "traces").glob("*.jsonl"))) == 13
    report = json.loads((out / "report.json").read_text())
    assert report["format"] == "agentbreak-report/1"
    assert {v["run"] for v in report["violations"]} == {"gh-inflated-invoice"}
    sarif = json.loads((out / "report.sarif").read_text())
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in sarif["runs"][0]["results"]}
    assert uris == {"examples/careful_agent.py"}


def test_write_baseline_then_pass_with_it(project):
    made = runner.invoke(app, ["ci", "--write-baseline", "baseline.json"])
    assert made.exit_code == 0, made.output
    doc = json.loads((project / "baseline.json").read_text())
    assert len(doc["accepted"]) == 2
    ok = runner.invoke(app, ["ci", "--baseline", "baseline.json"])
    assert ok.exit_code == 0, ok.output
    assert "PASSED" in ok.output and "2 accepted" in ok.output
    # a different agent brings new violations the baseline doesn't cover
    worse = runner.invoke(app, ["ci", "--baseline", "baseline.json", "-a", "inbox-assistant"])
    assert worse.exit_code == 1


def test_github_actions_annotations_and_job_summary(project, monkeypatch):
    summary = project / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    result = runner.invoke(app, ["ci"])
    assert result.exit_code == 1
    errors = [line for line in result.output.splitlines() if line.startswith("::error ")]
    assert len(errors) == 2
    assert all("file=examples/careful_agent.py,line=" in e for e in errors)
    text = summary.read_text()
    assert text.startswith("## agentbreak: Failed") and "`gh-inflated-invoice`" in text


def test_annotations_escape_newlines_and_separators():
    report = {
        "runs": [{"id": "r", "agent_source": {"path": "a,b:c.py", "line": 3}}],
        "violations": [{"run": "r", "rule": "run-compromised", "status": "new", "message": "two\nlines, 100%"}],
    }
    [line] = github_annotations(report)
    assert line == "::error file=a%2Cb%3Ac.py,line=3,title=agentbreak run-compromised::two%0Alines, 100%25"


def test_config_paths_are_relative_to_the_config_file(project):
    cfg = load_config(project / "agentbreak.yaml")
    assert cfg.agent == f"{(project / 'examples' / 'careful_agent.py').as_posix()}:run"
    assert load_config(project / "examples" / ".." / "agentbreak.yaml").output == project / "agentbreak-report"
    assert [p.name for p in cfg.scenarios] == ["reports-cleanup.yaml"]
    assert cfg.attacks == [] and cfg.output == project / "agentbreak-report"


@pytest.mark.parametrize(
    "body, message",
    [
        ("agent: x\nscenario: a.yaml\n", "unknown key"),
        ("scenarios: [missing-*.yaml]\n", "matches no files"),
        ("attacks: all\nfail_on: {verdict: sometimes}\n", "fail_on verdict"),
        ("agent: inbox-assistant\n", "give scenarios, attacks, or both"),
        ("attacks: all\nmax_calls: 0\n", "max_calls"),
        ("- not a mapping\n", "expected a mapping"),
    ],
)
def test_bad_configs_are_rejected(tmp_path, body, message):
    path = tmp_path / "agentbreak.yaml"
    path.write_text(body)
    with pytest.raises(ReportError, match=message):
        load_config(path)
    assert runner.invoke(app, ["ci", str(path)]).exit_code == 2


def test_run_writes_reports_and_keeps_its_exit_codes(tmp_path):
    poisoned = str(SCENARIOS / "02-poisoned-invoice-email.yaml")
    args = ["run", poisoned, "--no-traces", "--json", str(tmp_path / "r.json"), "--html", str(tmp_path / "r.html")]
    result = runner.invoke(app, [*args, "--sarif", str(tmp_path / "r.sarif")])
    assert result.exit_code == 1
    report = json.loads((tmp_path / "r.json").read_text())
    assert report["runs"][0]["verdict"] == "compromised"
    assert report["fail_on"] == {"verdicts": ["compromised"], "attack_outcomes": [], "task_incomplete": False}
    assert (tmp_path / "r.html").read_text().startswith("<!doctype html>")
    assert runner.invoke(app, [*args, "--fail-on", "never"]).exit_code == 0


def test_attacks_run_with_a_baseline(tmp_path):
    base = tmp_path / "b.json"
    base.write_text(
        json.dumps({"format": "agentbreak-baseline/1", "accepted": [{"id": "pe-add-payee:attack-succeeded"}]})
    )
    result = runner.invoke(app, ["attacks", "run", "pe-add-payee", "--no-traces", "--baseline", str(base)])
    assert result.exit_code == 0, result.output
    assert "1 violation(s) accepted by the baseline" in result.output
    other = runner.invoke(app, ["attacks", "run", "gh-delete-plan", "--no-traces", "--baseline", str(base)])
    assert other.exit_code == 1
    base.write_text("{}")
    assert runner.invoke(app, ["attacks", "run", "pe-add-payee", "--baseline", str(base)]).exit_code == 2


def test_report_command_rebuilds_reports_from_traces(tmp_path):
    traces = tmp_path / "traces"
    runner.invoke(app, ["attacks", "run", "-c", "goal-hijack", "-t", str(traces)])
    result = runner.invoke(app, ["report", str(traces), "--json", str(tmp_path / "r.json")])
    assert result.exit_code == 0, result.output
    assert "2 run(s): 2 compromised" in result.output
    report = json.loads((tmp_path / "r.json").read_text())
    assert sorted(r["id"] for r in report["runs"]) == ["gh-delete-plan", "gh-inflated-invoice"]
    assert runner.invoke(app, ["report", str(traces)]).exit_code == 2  # no output asked for
    (tmp_path / "empty").mkdir()
    assert runner.invoke(app, ["report", str(tmp_path / "empty"), "--json", "x.json"]).exit_code == 2
