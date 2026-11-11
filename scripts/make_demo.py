"""Record real CLI output into docs/demo.svg.

Run from the project root:  python scripts/make_demo.py

It copies agentbreak.yaml and examples/ into a temporary folder and runs two
commands there: `agentbreak ci` (the example careful agent against an example
scenario and the attack library; it exits 1 because one attack gets through),
then the same run against the hardened agent that fixes it (exits 0). It saves
what the terminal showed.
"""

from __future__ import annotations

import io
import os
import shlex
import shutil
import tempfile
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from agentbreak import cli

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    console = Console(record=True, width=96, file=io.StringIO(), force_terminal=True)
    cli.console = console
    workdir = Path(tempfile.mkdtemp())
    shutil.copy(ROOT / "agentbreak.yaml", workdir / "agentbreak.yaml")
    shutil.copytree(ROOT / "examples", workdir / "examples")
    os.chdir(workdir)
    for command, expected in (("agentbreak ci", 1), ("agentbreak ci --agent examples/hardened_agent.py:run", 0)):
        console.print(f"[bold green]$[/bold green] [bold]{command}[/bold]")
        result = CliRunner().invoke(cli.app, shlex.split(command)[1:])
        if result.exit_code != expected:
            os.chdir(ROOT)
            raise SystemExit(f"{command} exited {result.exit_code}, expected {expected}\n{result.output}")
        console.print(f"[dim]exit status {result.exit_code}[/dim]\n")
    os.chdir(ROOT)
    shutil.rmtree(workdir, ignore_errors=True)
    (ROOT / "docs").mkdir(exist_ok=True)
    console.save_svg(str(ROOT / "docs" / "demo.svg"), title="agentbreak")
    print("wrote docs/demo.svg")


if __name__ == "__main__":
    main()
