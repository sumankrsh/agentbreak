"""Record real CLI output into docs/demo.svg.

Run from the project root:  python scripts/make_demo.py

It copies agentbreak.yaml and examples/ into a temporary folder, runs
`agentbreak ci` there (the example careful agent against an example scenario
and the attack library) and saves what the terminal showed. That command exits
1 by design: one attack gets past the careful agent.
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
    command = "agentbreak ci"
    console.print(f"[bold green]$[/bold green] [bold]{command}[/bold]")
    result = CliRunner().invoke(cli.app, shlex.split(command)[1:])
    os.chdir(ROOT)
    shutil.rmtree(workdir, ignore_errors=True)
    if result.exit_code not in (0, 1) or result.exception and not isinstance(result.exception, SystemExit):
        raise SystemExit(result.output)
    (ROOT / "docs").mkdir(exist_ok=True)
    console.save_svg(str(ROOT / "docs" / "demo.svg"), title="agentbreak")
    print("wrote docs/demo.svg")


if __name__ == "__main__":
    main()
