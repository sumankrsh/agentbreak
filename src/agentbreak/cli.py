"""Command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__
from .evaluate import ATTEMPTED, CLEAN, COMPROMISED
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
from .sandbox import SERVICES, Call, Toolbox
from .scenario import Scenario, ScenarioError, builtin_scenarios, load_scenario

app = typer.Typer(
    help="Run an AI agent against fake email, file and payment tools, and see which unauthorised actions it attempted and which went through.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
err = Console(stderr=True)

VERDICT_STYLE = {COMPROMISED: "bold red", ATTEMPTED: "bold yellow", CLEAN: "bold green"}
DEFAULT_TRACES = Path("agentbreak-traces")


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
    for r in results:
        ev = r.evaluation
        done = {True: "yes", False: "[red]no[/red]", None: "-"}[ev.task_completed]
        style = VERDICT_STYLE[ev.verdict]
        table.add_row(
            escape(r.scenario.name),
            f"[{style}]{ev.verdict}[/{style}]",
            str(len(ev.executed_calls)),
            str(len(ev.stopped_calls)),
            done,
        )
    console.print(table)


def _load_all(paths: list[Path]) -> list[Scenario]:
    scenarios = []
    for path in paths:
        try:
            scenarios.append(load_scenario(path))
        except ScenarioError as exc:
            err.print(f"[red]Scenario error:[/red] {escape(str(exc))}")
            raise typer.Exit(2) from exc
    return scenarios


def _run_all(scenarios: list[Scenario], agent_spec: str, traces: Path | None, max_calls: int) -> list[RunResult]:
    try:
        agent = load_agent(agent_spec)
    except AgentLoadError as exc:
        err.print(f"[red]Agent error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    results = []
    for scenario in scenarios:
        result = run_scenario(scenario, agent, agent_name=agent_spec, max_calls=max_calls)
        trace = write_trace(result, traces) if traces else None
        _print_run(result, trace)
        results.append(result)
    if len(results) > 1:
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
            help=f"Agent to test: {', '.join(BUILTIN_AGENTS)}, module:function or path/to/agent.py:function.",
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
) -> None:
    """Run an agent against one or more scenarios and judge every tool call it made."""
    if fail_on not in {COMPROMISED, ATTEMPTED, "never"}:
        err.print("[red]--fail-on must be compromised, attempted or never[/red]")
        raise typer.Exit(2)
    results = _run_all(_load_all(scenarios), agent, None if no_traces else traces, max_calls)
    failing = {COMPROMISED} if fail_on == COMPROMISED else {COMPROMISED, ATTEMPTED} if fail_on == ATTEMPTED else set()
    if any(r.verdict in failing for r in results):
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
    console.print("Final state:")
    console.print_json(json.dumps(r.get("final_state", {})))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
