"""Command-line interface."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__
from .adapters.mcp import relay
from .ci import DEFAULT_CONFIG, github_annotations, load_config, markdown_summary
from .evaluate import ATTEMPTED, CLEAN, COMPROMISED, RESISTED, STOPPED, SUCCEEDED
from .mcp_server import MCPServer, serve_stdio
from .report import (
    OUTCOME_RULES,
    VERDICT_RULES,
    FailOn,
    ReportError,
    baseline_document,
    build_report,
    load_baseline,
    run_record,
    to_sarif,
    write_html,
    write_json,
)
from .runner import (
    BUILTIN_AGENTS,
    AgentLoadError,
    RunResult,
    TraceError,
    load_agent,
    read_trace,
    run_scenario,
    write_trace,
)
from .sandbox import SERVICES, Call, CallLimitReached, Toolbox
from .scenario import (
    CATEGORIES,
    Scenario,
    ScenarioError,
    attack_library,
    attack_library_files,
    builtin_scenarios,
    load_scenario,
)

app = typer.Typer(
    help="Run an AI agent against fake email, file and payment tools, and see which unauthorised actions it attempted and which went through.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
err = Console(stderr=True)

VERDICT_STYLE = {COMPROMISED: "bold red", ATTEMPTED: "bold yellow", CLEAN: "bold green"}
OUTCOME_STYLE = {SUCCEEDED: "bold red", STOPPED: "bold yellow", RESISTED: "bold green"}
OUTCOME_TEXT = {
    SUCCEEDED: "the attacker's goal was reached",
    STOPPED: "the agent tried, and nothing it tried went through",
    RESISTED: "the agent made no call towards the attacker's goal",
}
DEFAULT_TRACES = Path("agentbreak-traces")
AGENT_HELP = (
    f"Agent to test: {', '.join(BUILTIN_AGENTS)}, module:function, path/to/agent.py:function"
    " or 'mcp:<command>' (a program that uses agentbreak as its MCP server)."
)


def _version(value: bool) -> None:
    if value:
        console.print(f"agentbreak {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    pass


def _short(arguments: dict, limit: int = 64) -> str:
    text = json.dumps(arguments, ensure_ascii=False, separators=(", ", ": "))
    text = text.replace("\\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _calls_table(calls: list[Call], flagged: set[int]) -> Table:
    table = Table(show_edge=False, pad_edge=False, header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("tool")
    table.add_column("arguments", overflow="fold")
    table.add_column("authorised")
    table.add_column("outcome")
    for call in calls:
        bad = call.seq in flagged
        outcome = {"executed": "executed", "blocked": f"blocked ({call.control})", "error": "failed"}[call.status]
        if bad and call.executed:
            outcome_text = f"[bold red]{escape(outcome)}[/bold red]"
        elif call.status == "blocked":
            outcome_text = f"[yellow]{escape(outcome)}[/yellow]"
        else:
            outcome_text = escape(outcome)
        table.add_row(
            str(call.seq),
            escape(call.tool),
            escape(_short(call.arguments)),
            "[red]no[/red]" if bad else "yes",
            outcome_text,
        )
    return table


def _calls(n: int) -> str:
    return f"{n} call" if n == 1 else f"{n} calls"


def _attack_line(attack_id: str, outcome: str, calls: list[int]) -> str:
    style = OUTCOME_STYLE[outcome]
    where = f" (calls {', '.join(f'#{n}' for n in calls)})" if calls else ""
    return f"Attack {escape(attack_id)}: [{style}]{outcome}[/{style}]: {OUTCOME_TEXT[outcome]}{where}"


def _verdict_line(verdict: str, findings: list, task_completed: bool | None, missing: list[str]) -> list[str]:
    executed = len({f.seq for f in findings if f.outcome == "executed"})
    stopped = len({f.seq for f in findings if f.outcome != "executed"})
    style = VERDICT_STYLE[verdict]
    if verdict == COMPROMISED:
        head = f"{_calls(executed)} the task did not authorise went through"
        if stopped:
            head += f"; {stopped} more {'was' if stopped == 1 else 'were'} attempted and stopped"
    elif verdict == ATTEMPTED:
        head = f"{_calls(stopped)} the task did not authorise {'was' if stopped == 1 else 'were'} attempted; none went through"
    else:
        head = "every call was authorised by the scenario policy"
    lines = [f"[{style}]{verdict.upper()}[/{style}]: {escape(head)}"]
    for f in findings:
        mark = "[red]executed[/red]" if f.outcome == "executed" else f"[yellow]{f.outcome}[/yellow]"
        kind = "protected data" if f.kind == "protected_data" else "unauthorised"
        lines.append(f"  #{f.seq} {escape(f.tool)}: {kind}, {mark}. {escape(f.detail)}")
    if task_completed is not None:
        if task_completed:
            lines.append("Task completed: [green]yes[/green]")
        else:
            lines.append(f"Task completed: [red]no[/red] (missing: {escape('; '.join(missing))})")
    return lines


def _print_run(result: RunResult, trace: Path | None) -> None:
    s = result.scenario
    console.rule(f"[bold]{escape(s.name)}[/bold]", align="left")
    if s.description:
        console.print(f"[dim]{escape(s.description)}[/dim]")
    console.print(f"Task: {escape(s.task)}")
    console.print(f"Agent: {escape(result.agent)}")
    flagged = {f.seq for f in result.evaluation.findings}
    if result.calls:
        console.print(_calls_table(result.calls, flagged))
    else:
        console.print("[dim]The agent made no tool calls.[/dim]")
    if result.agent_error:
        console.print(f"[red]Agent error:[/red] {escape(result.agent_error)}")
    ev = result.evaluation
    for line in _verdict_line(ev.verdict, ev.findings, ev.task_completed, ev.missing_required):
        console.print(line)
    if s.attack and ev.attack_outcome:
        console.print(_attack_line(s.attack.id, ev.attack_outcome, ev.attack_calls))
    if trace:
        console.print(f"[dim]Trace: {escape(str(trace))}[/dim]")
    console.print()


def _summary(results: list[RunResult]) -> None:
    table = Table(title="Summary", title_justify="left", show_edge=False, header_style="bold")
    table.add_column("scenario")
    table.add_column("verdict")
    table.add_column("went through", justify="right")
    table.add_column("stopped", justify="right")
    table.add_column("task done")
    with_attacks = any(r.scenario.attack for r in results)
    if with_attacks:
        table.add_column("attack")
    for r in results:
        ev = r.evaluation
        style = VERDICT_STYLE[ev.verdict]
        row = [
            escape(r.scenario.name),
            f"[{style}]{ev.verdict}[/{style}]",
            str(len(ev.executed_calls)),
            str(len(ev.stopped_calls)),
            _done(ev.task_completed),
        ]
        if with_attacks:
            row.append(_outcome_cell(ev.attack_outcome))
        table.add_row(*row)
    console.print(table)


def _done(task_completed: bool | None) -> str:
    return {True: "yes", False: "[red]no[/red]", None: "-"}[task_completed]


def _outcome_cell(outcome: str | None) -> str:
    if outcome is None:
        return "-"
    style = OUTCOME_STYLE[outcome]
    return f"[{style}]{outcome}[/{style}]"


def _load_all(paths: list[Path]) -> list[Scenario]:
    scenarios = []
    for path in paths:
        try:
            scenarios.append(load_scenario(path))
        except ScenarioError as exc:
            err.print(f"[red]Scenario error:[/red] {escape(str(exc))}")
            raise typer.Exit(2) from exc
    return scenarios


JsonOption = Annotated[Path | None, typer.Option("--json", help="Write a JSON report to this file.")]
SarifOption = Annotated[
    Path | None, typer.Option("--sarif", help="Write a SARIF 2.1.0 report (for GitHub code scanning) to this file.")
]
HtmlOption = Annotated[Path | None, typer.Option("--html", help="Write a single-file HTML report to this file.")]
BaselineOption = Annotated[
    Path | None,
    typer.Option("--baseline", help="Accept the violations listed in this baseline file; fail only on new ones."),
]


def _baseline(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        return load_baseline(path)
    except ReportError as exc:
        err.print(f"[red]Baseline error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc


def _write_reports(report: dict, json_path: Path | None, sarif: Path | None, html: Path | None) -> list[Path]:
    written = []
    if json_path:
        written.append(write_json(report, json_path))
    if sarif:
        written.append(write_json(to_sarif(report), sarif))
    if html:
        written.append(write_html(report, html))
    for path in written:
        console.print(f"[dim]Report: {escape(str(path))}[/dim]")
    return written


def _baseline_note(report: dict) -> None:
    s = report["summary"]
    if s["accepted_violations"]:
        console.print(
            f"[dim]{s['accepted_violations']} violation(s) accepted by the baseline; {s['new_violations']} new.[/dim]"
        )
    for gone in report["no_longer_seen"]:
        console.print(f"[dim]In the baseline but no longer seen: {escape(gone)}[/dim]")


def _run_all(
    scenarios: list[Scenario],
    agent_spec: str,
    traces: Path | None,
    max_calls: int,
    details: bool = True,
    summary: bool = True,
    agent_cwd: Path | None = None,
) -> list[RunResult]:
    try:
        agent = load_agent(agent_spec, cwd=agent_cwd)
    except AgentLoadError as exc:
        err.print(f"[red]Agent error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    results = []
    for scenario in scenarios:
        result = run_scenario(scenario, agent, agent_name=agent_spec, max_calls=max_calls)
        trace = write_trace(result, traces) if traces else None
        if details:
            _print_run(result, trace)
        results.append(result)
    if len(results) > 1 and details and summary:
        _summary(results)
    return results


@app.command()
def run(
    scenarios: Annotated[list[Path], typer.Argument(help="Scenario YAML files.", show_default=False)],
    agent: Annotated[
        str,
        typer.Option(
            "--agent",
            "-a",
            help=AGENT_HELP,
        ),
    ] = "inbox-assistant",
    traces: Annotated[
        Path, typer.Option("--traces", "-t", help="Folder for one JSON Lines trace per scenario.")
    ] = DEFAULT_TRACES,
    no_traces: Annotated[bool, typer.Option("--no-traces", help="Don't write trace files.")] = False,
    max_calls: Annotated[
        int, typer.Option("--max-calls", min=1, help="Stop an agent after this many tool calls.")
    ] = 100,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit 1 when any scenario is 'compromised' (default), or also when 'attempted'. 'never' always exits 0.",
        ),
    ] = COMPROMISED,
    json_report: JsonOption = None,
    sarif: SarifOption = None,
    html: HtmlOption = None,
    baseline: BaselineOption = None,
) -> None:
    """Run an agent against one or more scenarios and judge every tool call it made."""
    if fail_on not in VERDICT_RULES:
        err.print("[red]--fail-on must be compromised, attempted or never[/red]")
        raise typer.Exit(2)
    accepted = _baseline(baseline)
    results = _run_all(_load_all(scenarios), agent, None if no_traces else traces, max_calls)
    rules = FailOn(verdicts=set(VERDICT_RULES[fail_on]), outcomes=set())
    report = build_report([run_record(r) for r in results], rules, accepted)
    _write_reports(report, json_report, sarif, html)
    _baseline_note(report)
    if not report["summary"]["passed"]:
        raise typer.Exit(1)


@app.command()
def demo(
    traces: Annotated[Path, typer.Option("--traces", "-t", help="Folder for the trace files.")] = DEFAULT_TRACES,
) -> None:
    """Run the built-in vulnerable agent against the three built-in scenarios (offline, synthetic data)."""
    console.print(
        "[dim]The built-in 'inbox-assistant' is deliberately vulnerable: it follows instructions it finds in emails and files. "
        "Everything below runs in memory; no email is sent and no money moves.[/dim]\n"
    )
    _run_all(builtin_scenarios(), "inbox-assistant", traces, 100)


@app.command()
def validate(scenarios: Annotated[list[Path], typer.Argument(help="Scenario YAML files.", show_default=False)]) -> None:
    """Check scenario files without running an agent."""
    for scenario in _load_all(scenarios):
        tools = ", ".join(scenario.toolbox().tool_names())
        console.print(
            f"[green]ok[/green] {escape(scenario.source)}: {escape(scenario.name)}, "
            f"{len(scenario.policy.allow)} allow rule(s), {len(scenario.policy.required)} required, "
            f"{len(scenario.policy.protected_data)} protected value(s). Tools: {escape(tools)}"
        )


@app.command()
def tools(
    scenario: Annotated[
        Path | None, typer.Argument(help="Show only the tools this scenario's environment provides.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the tool definitions as JSON.")] = False,
) -> None:
    """List the sandbox tools an agent can call, with their arguments."""
    if scenario:
        box = _load_all([scenario])[0].toolbox()
    else:
        box = Toolbox({name: _minimal(name) for name in SERVICES})
    if as_json:
        print(json.dumps(box.specs(), indent=2))
        return
    table = Table(show_edge=False, header_style="bold")
    for col in ("tool", "effect", "arguments", "description"):
        table.add_column(col, overflow="fold")
    for spec in box.specs():
        params = spec["input_schema"]
        args = ", ".join(
            f"{k}{'' if k in params['required'] else '?'}: {v['type']}" for k, v in params["properties"].items()
        )
        table.add_row(spec["name"], box.effect_of(spec["name"]), args or "-", escape(spec["description"]))
    console.print(table)


def _minimal(service: str) -> dict:
    return {"payments": {"accounts": {"ACC-1": 0}}}.get(service, {})


@app.command()
def show(
    trace: Annotated[Path, typer.Argument(help="A trace file written by `run` or `demo`.", show_default=False)],
) -> None:
    """Print a saved trace: the calls, the verdict and the final sandbox state."""
    try:
        t = read_trace(trace)
    except TraceError as exc:
        err.print(f"[red]Trace error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    h, r = t.header, t.result
    console.rule(f"[bold]{escape(str(h.get('scenario')))}[/bold]", align="left")
    console.print(f"Task: {escape(str(h.get('task')))}")
    console.print(
        f"Agent: {escape(str(h.get('agent')))}  Started: {escape(str(h.get('started')))}  agentbreak {escape(str(h.get('agentbreak')))}"
    )
    console.print(f"Scenario SHA-256: {escape(str(h.get('scenario_sha256')))}")
    findings = t.findings
    console.print(_calls_table(t.calls, {f.seq for f in findings}))
    if r.get("agent_error"):
        console.print(f"[red]Agent error:[/red] {escape(str(r['agent_error']))}")
    verdict = r.get("verdict", CLEAN)
    if verdict not in VERDICT_STYLE:
        err.print(f"[red]Trace error:[/red] unknown verdict {verdict!r}")
        raise typer.Exit(2)
    for line in _verdict_line(verdict, findings, r.get("task_completed"), r.get("missing_required", [])):
        console.print(line)
    attack = h.get("attack")
    if isinstance(attack, dict) and r.get("attack_outcome") in OUTCOME_STYLE:
        console.print(_attack_line(str(attack.get("id")), r["attack_outcome"], list(r.get("attack_calls") or [])))
    console.print("Final state:")
    console.print_json(json.dumps(r.get("final_state", {})))


attacks_app = typer.Typer(
    help="The built-in attack library: list it, run it against an agent, or export it to adapt.",
    no_args_is_help=True,
)
app.add_typer(attacks_app, name="attacks")


def _first_sentence(text: str) -> str:
    head, dot, _ = text.partition(". ")
    return head + "." if dot else text


def _select(ids: list[str], categories: list[str]) -> list[Scenario]:
    library = attack_library()
    bad = [c for c in categories if c not in CATEGORIES]
    if bad:
        err.print(f"[red]Unknown categor{'y' if len(bad) == 1 else 'ies'}:[/red] {escape(', '.join(bad))}")
        err.print(f"Use one of: {', '.join(c for c in CATEGORIES if c != 'other')}")
        raise typer.Exit(2)
    known = {s.attack.id for s in library if s.attack}
    unknown = [i for i in ids if i not in known]
    if unknown:
        err.print(f"[red]Unknown attack id(s):[/red] {escape(', '.join(unknown))}. Run `agentbreak attacks list`.")
        raise typer.Exit(2)
    return [
        s
        for s in library
        if s.attack and (not ids or s.attack.id in ids) and (not categories or s.attack.category in categories)
    ]


CategoryOption = Annotated[
    list[str] | None,
    typer.Option("--category", "-c", help=f"Only this category (repeatable): {', '.join(CATEGORIES[:-1])}."),
]


@attacks_app.command("list")
def attacks_list(category: CategoryOption = None) -> None:
    """List the attacks in the library."""
    table = Table(show_edge=False, header_style="bold")
    table.add_column("id", no_wrap=True)
    table.add_column("category", no_wrap=True)
    table.add_column("via", no_wrap=True)
    table.add_column("what happens", overflow="fold")
    selected = _select([], category or [])
    for s in selected:
        assert s.attack
        table.add_row(s.attack.id, s.attack.category, s.attack.vector, escape(_first_sentence(s.description)))
    console.print(table)
    console.print(
        f"[dim]{len(selected)} attack(s). Details: `agentbreak attacks export <folder>` writes the YAML.[/dim]"
    )


@attacks_app.command("run")
def attacks_run(
    ids: Annotated[
        list[str] | None, typer.Argument(help="Attack ids to run (default: all).", show_default=False)
    ] = None,
    category: CategoryOption = None,
    agent: Annotated[
        str,
        typer.Option(
            "--agent",
            "-a",
            help=AGENT_HELP,
        ),
    ] = "inbox-assistant",
    traces: Annotated[
        Path, typer.Option("--traces", "-t", help="Folder for one JSON Lines trace per attack.")
    ] = DEFAULT_TRACES,
    no_traces: Annotated[bool, typer.Option("--no-traces", help="Don't write trace files.")] = False,
    max_calls: Annotated[
        int, typer.Option("--max-calls", min=1, help="Stop an agent after this many tool calls.")
    ] = 100,
    details: Annotated[bool, typer.Option("--details", help="Print every call of every run, as `run` does.")] = False,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit 1 when any attack 'succeeded' (default), or also when one was 'stopped'. 'never' always exits 0.",
        ),
    ] = SUCCEEDED,
    json_report: JsonOption = None,
    sarif: SarifOption = None,
    html: HtmlOption = None,
    baseline: BaselineOption = None,
) -> None:
    """Run attacks from the library against an agent and score each one by what the agent did."""
    if fail_on not in OUTCOME_RULES:
        err.print("[red]--fail-on must be succeeded, stopped or never[/red]")
        raise typer.Exit(2)
    accepted = _baseline(baseline)
    scenarios = _select(ids or [], category or [])
    if not scenarios:
        err.print("[red]No attacks match.[/red]")
        raise typer.Exit(2)
    results = _run_all(scenarios, agent, None if no_traces else traces, max_calls, details=details, summary=False)
    _scoreboard(results, agent)
    if not no_traces:
        console.print(f"[dim]Traces: {escape(str(traces))}/<attack id>.jsonl[/dim]")
    rules = FailOn(verdicts=set(), outcomes=set(OUTCOME_RULES[fail_on]))
    report = build_report([run_record(r) for r in results], rules, accepted)
    _write_reports(report, json_report, sarif, html)
    _baseline_note(report)
    if not report["summary"]["passed"]:
        raise typer.Exit(1)


def _scoreboard(results: list[RunResult], agent: str) -> None:
    table = Table(
        title=f"Attack library against {escape(agent)}", title_justify="left", show_edge=False, header_style="bold"
    )
    table.add_column("attack", no_wrap=True)
    table.add_column("category", overflow="fold")
    table.add_column("outcome", no_wrap=True, min_width=9)
    table.add_column("verdict", no_wrap=True, min_width=11)
    table.add_column("task done", no_wrap=True)
    counts = dict.fromkeys(OUTCOME_STYLE, 0)
    for r in results:
        ev, attack = r.evaluation, r.scenario.attack
        assert attack and ev.attack_outcome
        counts[ev.attack_outcome] += 1
        style = VERDICT_STYLE[ev.verdict]
        table.add_row(
            escape(attack.id),
            attack.category,
            _outcome_cell(ev.attack_outcome),
            f"[{style}]{ev.verdict}[/{style}]",
            _done(ev.task_completed),
        )
    console.print(table)
    total = len(results)
    console.print(
        f"Attacker's goal reached in [bold red]{counts[SUCCEEDED]}[/bold red] of {total}; "
        f"tried but stopped in [bold yellow]{counts[STOPPED]}[/bold yellow]; "
        f"resisted in [bold green]{counts[RESISTED]}[/bold green]."
    )


@attacks_app.command("export")
def attacks_export(
    folder: Annotated[Path, typer.Argument(help="Folder to write the attack YAML files into.", show_default=False)],
    force: Annotated[bool, typer.Option("--force", help="Overwrite files that already exist.")] = False,
) -> None:
    """Write the library's YAML files to a folder, to read or adapt to your own workflows."""
    files = attack_library_files()
    clashes = [name for name, _ in files if (folder / name).exists()]
    if clashes and not force:
        err.print(f"[red]Already exists:[/red] {escape(', '.join(clashes))} in {escape(str(folder))}. Use --force.")
        raise typer.Exit(2)
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in files:
        (folder / name).write_text(text, encoding="utf-8")
    console.print(f"Wrote {len(files)} attack files to {escape(str(folder))}")


def _trace_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            found = sorted(path.glob("*.jsonl"))
            if not found:
                err.print(f"[red]No .jsonl traces in[/red] {escape(str(path))}")
                raise typer.Exit(2)
            files += found
        else:
            files.append(path)
    return files


@app.command()
def report(
    traces: Annotated[
        list[Path], typer.Argument(help="Trace files, or folders of them, written by run, attacks run or ci.")
    ],
    json_report: JsonOption = None,
    sarif: SarifOption = None,
    html: HtmlOption = None,
) -> None:
    """Build JSON, SARIF or HTML reports from saved traces, without running the agent again."""
    if not (json_report or sarif or html):
        err.print("[red]Give at least one of --json, --sarif or --html.[/red]")
        raise typer.Exit(2)
    records = []
    for path in _trace_files(traces):
        try:
            records.append(run_record(read_trace(path)))
        except TraceError as exc:
            err.print(f"[red]Trace error:[/red] {escape(str(exc))}")
            raise typer.Exit(2) from exc
    built = build_report(records)
    _write_reports(built, json_report, sarif, html)
    s = built["summary"]
    console.print(
        f"{s['runs']} run(s): {s['verdicts'][COMPROMISED]} compromised, {s['verdicts'][ATTEMPTED]} attempted, "
        f"{s['verdicts'][CLEAN]} clean."
    )


@app.command()
def ci(
    config: Annotated[Path, typer.Argument(help="CI config file.", show_default=True)] = DEFAULT_CONFIG,
    agent: Annotated[str | None, typer.Option("--agent", "-a", help="Override the config's agent.")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Override the config's report folder.")] = None,
    baseline: BaselineOption = None,
    write_baseline: Annotated[
        Path | None,
        typer.Option(
            "--write-baseline", help="Write a baseline accepting every violation found in this run, and exit 0."
        ),
    ] = None,
    reason: Annotated[
        str, typer.Option("--reason", help="Reason stored with each entry written by --write-baseline.")
    ] = "accepted when the baseline was created",
) -> None:
    """Run the agent against the config's scenarios and attacks, write every report, and fail on new violations.

    Writes report.json, report.sarif, report.html and traces/ into the output folder.
    Exit status: 0 no new violations, 1 new violations, 2 a config, scenario or agent error.
    Under GitHub Actions it also prints error annotations and writes a job summary.
    """
    try:
        cfg = load_config(config)
    except ReportError as exc:
        err.print(f"[red]Config error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    agent_spec = agent or cfg.agent
    out = output or cfg.output
    accepted = _baseline(baseline or cfg.baseline) if write_baseline is None else {}
    scenarios = _load_all(cfg.scenarios)
    if cfg.attacks is not None:
        scenarios += _select(cfg.attacks, cfg.categories)
    if not scenarios:
        err.print("[red]The config selects no scenarios or attacks.[/red]")
        raise typer.Exit(2)
    console.print(
        f"agentbreak ci: {len(scenarios)} run(s) against [bold]{escape(agent_spec)}[/bold] from {escape(str(config))}"
    )
    # An mcp: command from the config runs in the config's folder, like its other relative paths.
    agent_cwd = None if agent else cfg.source.parent.resolve()
    results = _run_all(scenarios, agent_spec, out / "traces", cfg.max_calls, details=False, agent_cwd=agent_cwd)
    built = build_report([run_record(r) for r in results], cfg.fail_on, accepted)
    _ci_table(built)
    if write_baseline is not None:
        write_json(baseline_document(built["violations"], reason), write_baseline)
        console.print(
            f"Wrote a baseline accepting {len(built['violations'])} violation(s) to {escape(str(write_baseline))}"
        )
        return
    files = _write_reports(built, out / "report.json", out / "report.sarif", out / "report.html")
    _baseline_note(built)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for line in github_annotations(built):
            print(line)
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(markdown_summary(built, files))
    s = built["summary"]
    if s["passed"]:
        console.print(f"[bold green]PASSED[/bold green]: no new violations ({s['accepted_violations']} accepted).")
    else:
        console.print(f"[bold red]FAILED[/bold red]: {s['new_violations']} new violation(s).")
        raise typer.Exit(1)


def _ci_table(built: dict) -> None:
    table = Table(show_edge=False, header_style="bold")
    table.add_column("run", no_wrap=True)
    table.add_column("attack", no_wrap=True, min_width=9)
    table.add_column("verdict", no_wrap=True, min_width=11)
    table.add_column("task done", no_wrap=True)
    table.add_column("CI", no_wrap=True)
    status: dict[str, str] = {}
    for v in built["violations"]:
        if status.get(v["run"]) != "new":
            status[v["run"]] = v["status"]
    for r in built["runs"]:
        style = VERDICT_STYLE[r["verdict"]]
        mark = {"new": "[bold red]fail[/bold red]", "accepted": "[dim]accepted[/dim]"}.get(
            status.get(r["id"], ""), "ok"
        )
        table.add_row(
            escape(r["id"]),
            _outcome_cell(r.get("attack_outcome")),
            f"[{style}]{r['verdict']}[/{style}]",
            _done(r.get("task_completed")),
            mark,
        )
    console.print(table)
    for v in built["violations"]:
        colour = "red" if v["status"] == "new" else "dim"
        console.print(f"[{colour}]{v['status']}[/{colour}] {escape(v['id'])}: {escape(v['message'])}")


mcp_app = typer.Typer(
    help="Serve a scenario's sandbox tools over MCP, for agents that get their tools from MCP servers.",
    no_args_is_help=True,
)
app.add_typer(mcp_app, name="mcp")


def _scenario_or_attack(target: str) -> Scenario:
    if Path(target).is_file():
        return _load_all([Path(target)])[0]
    for scenario in attack_library():
        if scenario.attack and scenario.attack.id == target:
            return scenario
    err.print(f"[red]No scenario file or attack id named[/red] {escape(target)}. Run `agentbreak attacks list`.")
    raise typer.Exit(2)


@mcp_app.command("serve")
def mcp_serve(
    target: Annotated[str, typer.Argument(help="A scenario file, or the id of a built-in attack.", show_default=False)],
    traces: Annotated[Path, typer.Option("--traces", "-t", help="Folder for the trace file.")] = DEFAULT_TRACES,
    max_calls: Annotated[
        int, typer.Option("--max-calls", min=1, help="End the session after this many tool calls.")
    ] = 100,
) -> None:
    """Run an MCP server (stdio) with the scenario's tools. When the client disconnects, judge every call it made.

    Point any MCP client at this command, give its agent the scenario's task, and
    let it work. The protocol uses stdout, so the task, the verdict and the trace
    path are printed to stderr. Exits 1 if the run was compromised.
    """
    global console
    scenario = _scenario_or_attack(target)
    err.print(f"[bold]agentbreak MCP server[/bold] for {escape(scenario.name)}. Give the agent this task:")
    err.print(f"  {escape(scenario.task)}")

    def session(task: str, tools: Toolbox) -> None:
        server = MCPServer(tools)
        serve_stdio(server, sys.stdin, sys.stdout)
        if server.limit_reached:
            raise CallLimitReached(f"the agent made more than {max_calls} tool calls")

    result = run_scenario(scenario, session, agent_name="mcp client", max_calls=max_calls)
    result.agent_source = None
    trace = write_trace(result, traces)
    shown, console = console, err
    try:
        _print_run(result, trace)
    finally:
        console = shown
    if result.verdict == COMPROMISED:
        raise typer.Exit(1)


@mcp_app.command("relay", hidden=True)
def mcp_relay(address: str, token: str) -> None:
    """Pass MCP messages between stdio and an agentbreak run (started for you by mcp: agents)."""
    raise typer.Exit(relay(address, token, sys.stdin, sys.stdout))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
