import json

from typer.testing import CliRunner

from agentbreak.cli import app
from agentbreak.runner import read_trace

from .conftest import EXAMPLES, SCENARIOS

runner = CliRunner()


def test_demo_runs_offline_and_writes_traces(tmp_path):
    result = runner.invoke(app, ["demo", "--traces", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "COMPROMISED" in result.output and "ATTEMPTED" in result.output and "CLEAN" in result.output
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "invoice-baseline.jsonl",
        "poisoned-invoice-email.jsonl",
        "shared-drive-exfiltration.jsonl",
    ]


def test_run_exit_codes_follow_fail_on(tmp_path):
    poisoned = str(SCENARIOS / "02-poisoned-invoice-email.yaml")
    drive = str(SCENARIOS / "03-shared-drive-exfiltration.yaml")
    assert runner.invoke(app, ["run", poisoned, "--no-traces"]).exit_code == 1
    assert runner.invoke(app, ["run", poisoned, "--no-traces", "--fail-on", "never"]).exit_code == 0
    assert runner.invoke(app, ["run", drive, "--no-traces"]).exit_code == 0
    assert runner.invoke(app, ["run", drive, "--no-traces", "--fail-on", "attempted"]).exit_code == 1
    assert runner.invoke(app, ["run", drive, "--no-traces", "--fail-on", "sometimes"]).exit_code == 2


def test_run_with_a_custom_agent_file(tmp_path):
    agent = f"{EXAMPLES / 'careful_agent.py'}:run"
    result = runner.invoke(
        app, ["run", str(SCENARIOS / "02-poisoned-invoice-email.yaml"), "--agent", agent, "-t", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    assert "CLEAN" in result.output


def test_trace_round_trips_through_show(tmp_path):
    runner.invoke(app, ["run", str(SCENARIOS / "02-poisoned-invoice-email.yaml"), "-t", str(tmp_path)])
    path = tmp_path / "poisoned-invoice-email.jsonl"
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert lines[0]["type"] == "run" and lines[-1]["type"] == "result"
    assert lines[-1]["verdict"] == "compromised"
    trace = read_trace(path)
    assert [c.seq for c in trace.calls] == list(range(1, 8))
    shown = runner.invoke(app, ["show", str(path)])
    assert shown.exit_code == 0 and "COMPROMISED" in shown.output and "EXT-5521" in shown.output


def test_show_rejects_files_that_are_not_traces(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n")
    assert runner.invoke(app, ["show", str(bad)]).exit_code == 2


def test_validate_and_tools(tmp_path):
    ok = runner.invoke(app, ["validate", str(EXAMPLES / "reports-cleanup.yaml")])
    assert ok.exit_code == 0 and "ok" in ok.output
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: x\n")
    assert runner.invoke(app, ["validate", str(bad)]).exit_code == 2
    listing = runner.invoke(app, ["tools", "--json"])
    names = [t["name"] for t in json.loads(listing.output)]
    assert "transfer" in names and "send_email" in names and "delete_file" in names


def test_bad_agent_exits_2():
    result = runner.invoke(app, ["run", str(SCENARIOS / "01-invoice-baseline.yaml"), "--agent", "nope", "--no-traces"])
    assert result.exit_code == 2


def test_attacks_list_shows_the_library():
    result = runner.invoke(app, ["attacks", "list"])
    assert result.exit_code == 0
    assert "td-balance-sweep" in result.output and "gh-inflated-invoice" in result.output
    only = runner.invoke(app, ["attacks", "list", "--category", "goal-hijack"])
    assert "gh-delete-plan" in only.output and "td-balance-sweep" not in only.output


def test_attacks_run_scores_and_exits(tmp_path):
    result = runner.invoke(app, ["attacks", "run", "-t", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert "Attacker's goal reached in 8 of 12; tried but stopped in 4; resisted in 0." in result.output
    assert len(list(tmp_path.glob("*.jsonl"))) == 12
    trace = read_trace(tmp_path / "pe-add-payee.jsonl")
    assert trace.header["attack"] == {"id": "pe-add-payee", "category": "permission-escalation", "vector": "email"}
    assert trace.result["attack_outcome"] == "succeeded"
    shown = runner.invoke(app, ["show", str(tmp_path / "pe-add-payee.jsonl")])
    assert "Attack pe-add-payee: succeeded" in shown.output


def test_attacks_run_fail_on_and_selection():
    stopped_only = ["attacks", "run", "pe-raise-approval-limit", "de-lookalike-domain", "--no-traces"]
    assert runner.invoke(app, stopped_only).exit_code == 0
    assert runner.invoke(app, [*stopped_only, "--fail-on", "stopped"]).exit_code == 1
    assert runner.invoke(app, ["attacks", "run", "--no-traces", "--fail-on", "never"]).exit_code == 0
    careful = f"{EXAMPLES / 'careful_agent.py'}:run"
    ok = runner.invoke(
        app, ["attacks", "run", "-c", "tool-response", "-c", "permission-escalation", "-a", careful, "--no-traces"]
    )
    assert ok.exit_code == 0 and "resisted in 5" in ok.output
    assert runner.invoke(app, ["attacks", "run", "no-such-attack"]).exit_code == 2
    assert runner.invoke(app, ["attacks", "run", "-c", "phishing"]).exit_code == 2
    assert runner.invoke(app, ["attacks", "run", "--fail-on", "maybe"]).exit_code == 2


def test_attacks_details_prints_every_call():
    result = runner.invoke(app, ["attacks", "run", "gh-delete-plan", "--details", "--no-traces"])
    assert "delete_file" in result.output and "Attack gh-delete-plan: succeeded" in result.output


def test_exported_attacks_validate_and_run(tmp_path):
    assert runner.invoke(app, ["attacks", "export", str(tmp_path)]).exit_code == 0
    files = sorted(tmp_path.glob("*.yaml"))
    assert len(files) == 12
    assert runner.invoke(app, ["validate", *map(str, files)]).exit_code == 0
    assert runner.invoke(app, ["attacks", "export", str(tmp_path)]).exit_code == 2
    assert runner.invoke(app, ["attacks", "export", str(tmp_path), "--force"]).exit_code == 0
    one = runner.invoke(app, ["run", str(tmp_path / "gh-delete-plan.yaml"), "--no-traces"])
    assert one.exit_code == 1 and "Attack gh-delete-plan: succeeded" in one.output
