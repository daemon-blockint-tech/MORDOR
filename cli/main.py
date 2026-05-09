from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.live import Live

from cli.client import MordorClient

app = typer.Typer(
    name="mordor",
    help="Malware Orchestration & Reverse engineering Detection Operations Runtime",
    no_args_is_help=True,
)
console = Console()

PHASE_EMOJI = {
    "fingerprint": "🔍",
    "filter": "🔎",
    "hypothesize": "🧠",
    "map_structure": "🗺️",
    "deep_analysis": "⚡",
    "validate": "✅",
    "report": "📋",
}


def _run_direct(binary: str, tier: str):
    """Run analysis directly via GandalfOrchestrator (no server needed)."""
    from agents.gandalf import GandalfOrchestrator

    path = Path(binary)
    if not path.exists():
        console.print(f"[red]Error:[/] binary not found: {binary}")
        raise typer.Exit(1)

    orchestrator = GandalfOrchestrator()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )

    phase_task = progress.add_task("[cyan]Initializing...", total=7)
    phase_order = ["fingerprint", "filter", "hypothesize", "map_structure", "deep_analysis", "validate", "report"]
    phase_idx = 0

    with Live(progress, refresh_per_second=4, console=console) as live:  # noqa: F841
        for event in orchestrator.stream(binary, tier=tier):
            if isinstance(event, dict):
                for node_name in event:
                    if node_name in phase_order:
                        idx = phase_order.index(node_name) + 1
                        if idx > phase_idx:
                            phase_idx = idx
                            progress.update(phase_task, completed=idx, description=f"[cyan]{PHASE_EMOJI.get(node_name, '')} {node_name.upper()}")

                    if node_name == "report":
                        progress.update(phase_task, completed=7, description="[green]✓ COMPLETE")

    console.print()
    final = orchestrator.run(binary, tier=tier)
    report_text = final.get("artifacts", {}).get("final_report", "")
    if report_text:
        console.print(Panel(Markdown(report_text[:2000] + ("..." if len(report_text) > 2000 else "")), title="[bold]Report[/]", border_style="green"))
    else:
        console.print("[green]✓ Analysis complete![/]")
    console.print(f"\nArtifacts: [underline]cases/{final.get('sha256', '')}/[/]")
    console.print(f"Confidence: [bold]{final.get('confidence_overall', 0):.0f}%[/]")


def _run_client(binary: str, tier: str, server: str):
    """Run analysis via remote API server."""
    client = MordorClient(server)
    path = Path(binary)

    if not path.exists():
        console.print(f"[red]Error:[/] binary not found: {binary}")
        raise typer.Exit(1)

    with console.status(f"[bold cyan]Uploading {path.name}...[/]"):
        result = client.analyze(binary, tier)

    case_id = result["case_id"]

    with Live(refresh_per_second=2, console=console) as live:
        last_phase = None
        while True:
            status = client.get_case(case_id)
            phase = status.get("phase", "")
            progress = status.get("progress", 0)

            if phase != last_phase:
                last_phase = phase
                emoji = PHASE_EMOJI.get(phase, "")
                live.update(Markdown(f"{emoji} **{phase.upper()}** — `{progress:.0f}%`"))

            if status.get("status") in ("completed", "failed"):
                break

            import time
            time.sleep(1)

    final = client.get_case(case_id)
    if final.get("status") == "completed":
        console.print("\n[bold green]✓ Analysis complete![/]")
        report = client.get_report(case_id)
        console.print(Panel(Markdown(report[:2000] + ("..." if len(report) > 2000 else "")), title="[bold]Report[/]", border_style="green"))
    else:
        console.print(f"\n[red]✗ Analysis failed:[/] {final.get('error', 'unknown error')}")


@app.command()
def analyze(
    binary: str = typer.Argument(..., help="Path to binary to analyze"),
    tier: str = typer.Option("standard", "--tier", "-t", help="Analysis depth: quick, standard, deep"),
    server: str = typer.Option("", "--server", "-s", help="MORDOR API server URL (omit for direct local mode)"),
):
    """Analyze a binary file"""
    if server:
        _run_client(binary, tier, server)
    else:
        _run_direct(binary, tier)


@app.command()
def upload(
    binary: str = typer.Argument(..., help="Path to binary"),
    tier: str = typer.Option("standard", "--tier", "-t"),
    server: str = typer.Option("http://127.0.0.1:8765", "--server", "-s"),
):
    """Upload binary and return case ID immediately (no wait)"""
    result = MordorClient(server).analyze(binary, tier)
    console.print(result["case_id"])


@app.command()
def cases(
    server: str = typer.Option("http://127.0.0.1:8765", "--server", "-s"),
):
    """List all analyzed cases"""
    client = MordorClient(server)
    try:
        all_cases = client.list_cases()
    except Exception as e:
        console.print(f"[red]Error connecting to {server}:[/] {e}")
        raise typer.Exit(1)

    if not all_cases:
        console.print("No cases found.")
        return

    table = Table(title="MORDOR Cases")
    table.add_column("Case ID", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Phase", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Confidence", style="blue")

    for c in all_cases:
        conf_val = c.get("confidence")
        conf = f"{conf_val:.0f}%" if conf_val is not None else "-"
        file_type = c.get("file_type") or "-"
        table.add_row(
            c["case_id"][:16],
            file_type[:20],
            c.get("phase", "-"),
            c.get("status", "-"),
            conf,
        )

    console.print(table)


@app.command()
def status(
    case_id: str = typer.Argument(..., help="Case ID"),
    server: str = typer.Option("http://127.0.0.1:8765", "--server", "-s"),
):
    """Show analysis status for a case"""
    client = MordorClient(server)
    try:
        s = client.get_case(case_id)
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    console.print(f"[bold]Case:[/] {case_id}")
    console.print(f"  Status:     {s.get('status', '-')}")
    console.print(f"  Phase:      {s.get('phase', '-')}")
    console.print(f"  Progress:   {s.get('progress', 0):.0f}%")
    console.print(f"  Confidence: {s.get('confidence', 0):.0f}%")
    if s.get("error"):
        console.print(f"  [red]Error:[/]   {s['error']}")


@app.command()
def report(
    case_id: str = typer.Argument(..., help="Case ID"),
    server: str = typer.Option("http://127.0.0.1:8765", "--server", "-s"),
):
    """Show final report for a case"""
    client = MordorClient(server)
    try:
        report_text = client.get_report(case_id)
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    console.print(Markdown(report_text))


@app.command()
def artifacts(
    case_id: str = typer.Argument(..., help="Case ID"),
    server: str = typer.Option("http://127.0.0.1:8765", "--server", "-s"),
):
    """List artifacts for a case"""
    client = MordorClient(server)
    try:
        arts = client.list_artifacts(case_id)
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    if not arts:
        console.print("No artifacts found.")
        return

    table = Table(title=f"Artifacts — {case_id[:16]}...")
    table.add_column("Name", style="cyan")
    table.add_column("Size", style="yellow")
    table.add_column("Type", style="green")

    for a in arts:
        table.add_row(a["name"], f"{a['size']:,} B", a["type"])

    console.print(table)


@app.command()
def tui(
    binary: str = typer.Argument(None, help="Path to binary (omit for server-based case manager)"),
    tier: str = typer.Option("standard", "--tier", "-t", help="Analysis depth: quick, standard, deep"),
    server: str = typer.Option("http://127.0.0.1:8765", "--server", "-s"),
):
    """Launch the Terminal UI (Textual) — provide a binary for direct local analysis"""
    import os
    os.environ["MORDOR_API_URL"] = server
    from cli.tui import run_tui

    if binary:
        path = Path(binary)
        if not path.exists():
            console.print(f"[red]Error:[/] binary not found: {binary}")
            raise typer.Exit(1)
        run_tui(binary_path=binary, tier=tier)
    else:
        run_tui()


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h"),
    port: int = typer.Option(8765, "--port", "-p"),
    reload: bool = typer.Option(False, "--reload", "-r"),
):
    """Start the MORDOR API server"""
    import uvicorn
    console.print("[bold cyan]MORDOR API Server[/]")
    console.print(f"  Listening on: [underline]http://{host}:{port}[/]")
    console.print(f"  Docs:         [underline]http://{host}:{port}/docs[/]")
    console.print()
    uvicorn.run("api.server:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
