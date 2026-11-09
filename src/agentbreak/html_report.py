"""A single-file HTML report: no scripts, no external files, readable offline and in light or dark mode."""

from __future__ import annotations

import json
from html import escape
from typing import Any

from .evaluate import ATTEMPTED, CLEAN, COMPROMISED, RESISTED, STOPPED, SUCCEEDED

CSS = """
:root {
  --bg: #ffffff; --fg: #1d2330; --muted: #5d6675; --line: #dde1e8; --panel: #f5f7fa;
  --bad: #b42318; --bad-bg: #fdecea; --warn: #8a5a00; --warn-bg: #fff4dc; --ok: #146c43; --ok-bg: #e6f4ec;
  --code: #f0f2f5;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14171c; --fg: #e4e7ec; --muted: #9aa3b2; --line: #2c323c; --panel: #1b1f26;
    --bad: #ff8a80; --bad-bg: #3a1d1b; --warn: #ffcf70; --warn-bg: #3a2d12; --ok: #7bd8a5; --ok-bg: #16301f;
    --code: #222831;
  }
}
:root[data-theme="dark"] {
  --bg: #14171c; --fg: #e4e7ec; --muted: #9aa3b2; --line: #2c323c; --panel: #1b1f26;
  --bad: #ff8a80; --bad-bg: #3a1d1b; --warn: #ffcf70; --warn-bg: #3a2d12; --ok: #7bd8a5; --ok-bg: #16301f;
  --code: #222831;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1080px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 1.6rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 32px 0 8px; }
p.meta { color: var(--muted); margin: 0 0 16px; }
.banner { padding: 12px 16px; border-radius: 8px; margin: 16px 0; font-weight: 600; }
.banner.fail { background: var(--bad-bg); color: var(--bad); }
.banner.pass { background: var(--ok-bg); color: var(--ok); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
.tile b { display: block; font-size: 1.5rem; }
.tile span { color: var(--muted); font-size: .85rem; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .85rem; }
pre { background: var(--code); padding: 10px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap;
  word-break: break-word; }
td code { word-break: break-word; }
code.nw { white-space: nowrap; word-break: normal; }
.tag { display: inline-block; padding: 0 8px; border-radius: 999px; font-size: .8rem; font-weight: 600;
  white-space: nowrap; }
.bad { background: var(--bad-bg); color: var(--bad); }
.warn { background: var(--warn-bg); color: var(--warn); }
.ok { background: var(--ok-bg); color: var(--ok); }
.plain { background: var(--panel); color: var(--muted); }
details { border: 1px solid var(--line); border-radius: 8px; margin: 8px 0; background: var(--panel); }
summary { cursor: pointer; padding: 10px 12px; font-weight: 600; }
details > div { padding: 0 12px 12px; background: var(--bg); border-radius: 0 0 8px 8px; }
ul { padding-left: 20px; }
footer { color: var(--muted); font-size: .85rem; margin-top: 40px; }
"""

TAG = {
    COMPROMISED: "bad",
    ATTEMPTED: "warn",
    CLEAN: "ok",
    SUCCEEDED: "bad",
    STOPPED: "warn",
    RESISTED: "ok",
    "new": "bad",
    "accepted": "plain",
}


def _tag(value: Any, cls: str | None = None) -> str:
    if value is None:
        return '<span class="tag plain">-</span>'
    return f'<span class="tag {cls or TAG.get(str(value), "plain")}">{escape(str(value))}</span>'


def _done(value: Any) -> str:
    return {True: _tag("yes", "ok"), False: _tag("no", "bad")}.get(value, _tag(None))


def _sentence(text: Any) -> str:
    text = str(text or "")
    return text[:1].upper() + text[1:] + "." if text else ""


def _json(value: Any, limit: int | None = None) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if limit and len(text) > limit:
        text = text[: limit - 3] + "..."
    return escape(text)


def _tile(number: Any, label: str) -> str:
    return f'<div class="tile"><b>{escape(str(number))}</b><span>{escape(label)}</span></div>'


def _calls_table(run: dict[str, Any]) -> str:
    calls = run.get("calls") or []
    if not calls:
        return "<p>The agent made no tool calls.</p>"
    flagged = {f.get("seq") for f in run.get("findings") or []}
    goal = set(run.get("attack_calls") or [])
    rows = []
    for c in calls:
        status = c.get("status")
        outcome = {"executed": "executed", "blocked": f"blocked ({c.get('control')})", "error": "failed"}.get(
            status, str(status)
        )
        bad = c.get("seq") in flagged
        cls = "bad" if bad and status == "executed" else "warn" if status == "blocked" or bad else "plain"
        notes = []
        if bad:
            notes.append(_tag("not authorised", "bad"))
        if c.get("seq") in goal:
            notes.append('<span class="tag warn">attacker&#x27;s goal</span>')
        rows.append(
            "<tr>"
            f"<td>{escape(str(c.get('seq')))}</td>"
            f'<td><code class="nw">{escape(str(c.get("tool")))}</code></td>'
            f"<td><code>{_json(c.get('arguments', {}), 400)}</code></td>"
            f'<td><span class="tag {cls}">{escape(outcome)}</span></td>'
            f"<td>{' '.join(notes) or 'yes'}</td>"
            "</tr>"
        )
    return (
        '<div class="scroll"><table><thead><tr><th>#</th><th>tool</th><th>arguments</th><th>outcome</th>'
        "<th>authorised</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _run_section(run: dict[str, Any], violation_ids: dict[str, list[dict[str, Any]]]) -> str:
    attack = run.get("attack") or {}
    head = f"{escape(str(run.get('id')))} &middot; {_tag(run.get('verdict'))}"
    if run.get("attack_outcome"):
        head += f" &middot; attack {_tag(run.get('attack_outcome'))}"
    parts = [f"<details><summary>{head}</summary><div>"]
    meta = [f"<b>Task:</b> {escape(str(run.get('task')))}"]
    if attack:
        meta.append(
            f"<b>Attack:</b> <code>{escape(str(attack.get('id')))}</code>, category "
            f"<code>{escape(str(attack.get('category')))}</code>, via <code>{escape(str(attack.get('vector')))}</code>"
        )
    meta.append(f"<b>Agent:</b> <code>{escape(str(run.get('agent')))}</code>")
    meta.append(f"<b>Scenario:</b> <code>{escape(str(run.get('scenario_source')))}</code>")
    meta.append(f"<b>Scenario SHA-256:</b> <code>{escape(str(run.get('scenario_sha256')))}</code>")
    parts.append("<p>" + "<br>".join(meta) + "</p>")
    parts.append(_calls_table(run))
    findings = run.get("findings") or []
    if findings:
        items = "".join(
            f"<li>#{escape(str(f.get('seq')))} <code>{escape(str(f.get('tool')))}</code>: "
            f"{'protected data' if f.get('kind') == 'protected_data' else 'unauthorised'}, "
            f"{_tag(f.get('outcome'), 'bad' if f.get('outcome') == 'executed' else 'warn')}. "
            f"{escape(_sentence(f.get('detail')))}</li>"
            for f in findings
        )
        parts.append(f"<p><b>Findings</b></p><ul>{items}</ul>")
    else:
        parts.append("<p>Every call was authorised by the scenario policy.</p>")
    if run.get("task_completed") is not None:
        line = f"<b>Task completed:</b> {_done(run.get('task_completed'))}"
        if run.get("missing_required"):
            line += f" (missing: {escape('; '.join(run['missing_required']))})"
        parts.append(f"<p>{line}</p>")
    ci = violation_ids.get(str(run.get("id")), [])
    if ci:
        parts.append(
            "<p><b>CI:</b> " + ", ".join(f"{_tag(v['status'])} <code>{escape(v['id'])}</code>" for v in ci) + "</p>"
        )
    if run.get("agent_error"):
        parts.append(f"<p><b>Agent error:</b> <code>{escape(str(run['agent_error']))}</code></p>")
    if run.get("answer"):
        parts.append(f"<p><b>Agent's answer</b></p><pre>{escape(str(run['answer']))}</pre>")
    parts.append(
        "<p><b>Final sandbox state</b></p>"
        f"<pre>{escape(json.dumps(run.get('final_state', {}), indent=2, ensure_ascii=False))}</pre>"
    )
    parts.append("</div></details>")
    return "".join(parts)


def render_html(report: dict[str, Any]) -> str:
    s = report["summary"]
    runs = report["runs"]
    by_run: dict[str, list[dict[str, Any]]] = {}
    for v in report["violations"]:
        by_run.setdefault(v["run"], []).append(v)
    agents = ", ".join(report.get("agents") or [])
    out = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>agentbreak report</title><style>{CSS}</style></head><body><main>",
        "<h1>agentbreak report</h1>",
        f'<p class="meta">Agent: <code>{escape(agents)}</code> &middot; generated {escape(str(report["generated"]))} '
        f"&middot; agentbreak {escape(str(report['agentbreak']))}</p>",
    ]
    if s["passed"]:
        note = f", {s['accepted_violations']} accepted by the baseline" if s["accepted_violations"] else ""
        out.append(f'<div class="banner pass">Passed: no new violations of the CI rules{escape(note)}.</div>')
    else:
        out.append(f'<div class="banner fail">Failed: {s["new_violations"]} new violation(s) of the CI rules.</div>')
    tiles = [_tile(s["runs"], "runs")]
    if any(s["attacks"].values()):
        tiles += [
            _tile(s["attacks"][SUCCEEDED], "attacks succeeded"),
            _tile(s["attacks"][STOPPED], "attacks stopped"),
            _tile(s["attacks"][RESISTED], "attacks resisted"),
        ]
    tiles += [
        _tile(s["verdicts"][COMPROMISED], "runs compromised"),
        _tile(s["verdicts"][ATTEMPTED], "runs attempted"),
        _tile(s["verdicts"][CLEAN], "runs clean"),
        _tile(s["tasks_completed"], "tasks completed"),
    ]
    out.append(f'<div class="tiles">{"".join(tiles)}</div>')

    out.append("<h2>Results</h2>")
    rows = "".join(
        "<tr>"
        f'<td><code class="nw">{escape(str(r["id"]))}</code></td>'
        f"<td>{escape(str((r.get('attack') or {}).get('category') or '-'))}</td>"
        f"<td>{_tag(r.get('attack_outcome'))}</td>"
        f"<td>{_tag(r.get('verdict'))}</td>"
        f"<td>{len({f['seq'] for f in r.get('findings') or [] if f.get('outcome') == 'executed'})}</td>"
        f"<td>{len({f['seq'] for f in r.get('findings') or [] if f.get('outcome') != 'executed'})}</td>"
        f"<td>{_done(r.get('task_completed'))}</td>"
        "</tr>"
        for r in runs
    )
    out.append(
        '<div class="scroll"><table><thead><tr><th>run</th><th>category</th><th>attack</th><th>verdict</th>'
        "<th>went through</th><th>stopped</th><th>task done</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
    )

    out.append("<h2>CI rules</h2>")
    rules = report["fail_on"]
    kinds = []
    if rules["attack_outcomes"]:
        kinds.append(f"an attack that {escape(' or '.join(rules['attack_outcomes']))}")
    if rules["verdicts"]:
        kinds.append(f"a run that was {escape(' or '.join(rules['verdicts']))}")
    if rules["task_incomplete"]:
        kinds.append("a run whose task was not completed")
    if kinds:
        listed = kinds[0] if len(kinds) == 1 else ", ".join(kinds[:-1]) + " or " + kinds[-1]
        out.append(f"<p>A violation is {listed}.</p>")
    else:
        out.append("<p>No CI rules are set, so nothing counts as a violation.</p>")
    if report["violations"]:
        items = "".join(
            f"<li>{_tag(v['status'])} <code>{escape(v['id'])}</code>: {escape(v['message'])}"
            + (f" <i>Accepted: {escape(v['reason'])}</i>" if v.get("reason") else "")
            + "</li>"
            for v in report["violations"]
        )
        out.append(f"<ul>{items}</ul>")
    else:
        out.append("<p>No violations.</p>")
    if report.get("no_longer_seen"):
        gone = ", ".join(f"<code>{escape(i)}</code>" for i in report["no_longer_seen"])
        out.append(f"<p>In the baseline but no longer seen (can be removed from it): {gone}</p>")

    out.append("<h2>Runs</h2>")
    out.append("".join(_run_section(r, by_run) for r in runs))
    out.append(
        "<footer>Every result above comes from tool calls recorded in agentbreak's sandbox. "
        "The tools are fake: no email was sent, no file changed and no money moved.</footer>"
    )
    out.append("</main></body></html>")
    return "\n".join(out) + "\n"
