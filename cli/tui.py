from __future__ import annotations

from pathlib import Path

import httpx
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, ProgressBar, RichLog, Static

from cli.client import MordorClient

API_DEFAULT = "http://127.0.0.1:8765"

PHASE_ORDER = ["fingerprint", "filter", "hypothesize", "map_structure", "deep_analysis", "validate", "report"]


PHASE_EMOJI = {
    "fingerprint": "🔍",
    "filter": "🔎",
    "hypothesize": "🧠",
    "map_structure": "🗺️",
    "deep_analysis": "⚡",
    "validate": "✅",
    "report": "📋",
}

PHASE_LABELS = {
    "fingerprint": "1/6 FINGERPRINT",
    "filter": "2/6 FILTER & GROUP",
    "hypothesize": "3/6 HYPOTHESIZE",
    "map_structure": "4/6 MAP STRUCTURE",
    "deep_analysis": "5/6 DEEP ANALYSIS",
    "validate": "6/6 VALIDATE",
    "report": "REPORT",
    "done": "DONE",
}


class PhaseProgress(Static):
    phase = reactive("")
    progress = reactive(0.0)
    status = reactive("")

    def render(self) -> Text:
        label = PHASE_LABELS.get(self.phase, self.phase.upper())
        bar_len = 20
        filled = int(bar_len * self.progress / 100)
        bar = "█" * filled + "░" * (bar_len - filled)

        style = "bold green" if self.status == "completed" else "bold yellow" if self.status == "running" else "dim white"
        return Text(f"{label}  [{bar}] {self.progress:.0f}%", style=style)


class EventLog(RichLog):
    def on_mount(self):
        self.write("[bold cyan]MORDOR Analysis Terminal[/]")
        self.write("Waiting for analysis...")


class CaseSelector(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label("[bold]MORDOR — Case Manager[/]", classes="title"),
            DataTable(id="case-table"),
            Horizontal(
                Button("Select", variant="primary", id="select"),
                Button("Refresh", id="refresh"),
                Button("Back", id="back"),
            ),
        )
        yield Footer()

    def on_mount(self):
        table = self.query_one("#case-table", DataTable)
        table.add_columns("Case ID", "Phase", "Status", "Confidence")
        self._load_cases()

    def _load_cases(self):
        try:
            client = MordorClient()
            cases = client.list_cases()
            table = self.query_one("#case-table", DataTable)
            table.clear()
            for c in cases:
                conf = f"{c.get('confidence', 0):.0f}%" if c.get('confidence') else "-"
                table.add_row(
                    c["case_id"][:16] + "...",
                    c.get("phase", "-"),
                    c.get("status", "-"),
                    conf,
                )
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "refresh":
            self._load_cases()
        elif event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "select":
            table = self.query_one("#case-table", DataTable)
            if table.cursor_row is not None:
                row = table.get_row_at(table.cursor_row)
                case_id = row[0].replace("...", "")
                self.app.push_screen(CaseDetailScreen(case_id))


class CaseDetailScreen(Screen):
    def __init__(self, case_id: str):
        super().__init__()
        self.case_id = case_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label(f"[bold]Case: {self.case_id}[/]", classes="title"),
            Static(id="case-detail"),
            Horizontal(
                Button("Report", variant="primary", id="report"),
                Button("Refresh", id="refresh"),
                Button("Back", id="back"),
            ),
        )
        yield Footer()

    def on_mount(self):
        self._refresh()

    def _refresh(self):
        try:
            client = MordorClient()
            status = client.get_case(self.case_id)
            detail = self.query_one("#case-detail", Static)
            lines = [
                f"Status: {status.get('status', '-')}",
                f"Phase: {status.get('phase', '-')}",
                f"Progress: {status.get('progress', 0):.0f}%",
                f"Confidence: {status.get('confidence', 0):.0f}%",
                f"Phases completed: {', '.join(status.get('phases_completed', [])) or 'none'}",
            ]
            detail.update("\n".join(lines))
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "refresh":
            self._refresh()
        elif event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "report":
            self.app.push_screen(ReportScreen(self.case_id))


class ReportScreen(Screen):
    def __init__(self, case_id: str):
        super().__init__()
        self.case_id = case_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            RichLog(id="report-content", wrap=True, highlight=True),
            Button("Back", id="back"),
        )
        yield Footer()

    def on_mount(self):
        try:
            client = MordorClient()
            report = client.get_report(self.case_id)
            log = self.query_one("#report-content", RichLog)
            log.clear()
            log.write(report)
        except Exception:
            self.query_one("#report-content", RichLog).write("(Report not yet available)")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "back":
            self.app.pop_screen()


class AnalyzeScreen(Screen):
    def __init__(self, binary_path: str, tier: str = "standard"):
        super().__init__()
        self.binary_path = binary_path
        self.tier = tier

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Label(f"[bold]Analyzing:[/] {Path(self.binary_path).name}", classes="title"),
            Static(f"Tier: {self.tier.upper()}", id="tier-info"),
            PhaseProgress(id="phase-progress"),
            ProgressBar(total=100, id="progress-bar", show_eta=False),
            EventLog(id="event-log"),
            RichLog(id="signals", highlight=True, wrap=True, max_lines=10),
            Horizontal(
                Button("View Report", variant="primary", id="view-report", disabled=True),
                Button("Back", id="back"),
            ),
        )
        yield Footer()

    def on_mount(self):
        self._case_id = None
        self._run_analysis()

    @work(thread=True)
    def _run_analysis(self):
        try:
            client = MordorClient()
            phase_progress = self.query_one("#phase-progress", PhaseProgress)
            progress_bar = self.query_one("#progress-bar", ProgressBar)
            event_log = self.query_one("#event-log", EventLog)
            result = client.analyze(self.binary_path, self.tier)
            case_id = result.get("case_id")
            self._case_id = case_id

            self.call_from_thread(
                lambda: event_log.write(f"[green]✓[/] Analysis started: {case_id[:16]}...")
            )

            for event in client.stream_events(case_id):
                phase = event.get("phase", "")
                progress = event.get("progress", 0)

                self.call_from_thread(lambda p=phase, pr=progress: phase_progress.update(phase=p, progress=pr))
                self.call_from_thread(lambda pr=progress: progress_bar.update(progress=pr))

                if progress > 0 and int(progress) % 25 == 0:
                    label = PHASE_LABELS.get(phase, phase)
                    self.call_from_thread(lambda lbl=label: event_log.write(f"[cyan]→[/] {lbl}"))

            self.call_from_thread(lambda: event_log.write("[bold green]✓ Analysis complete![/]"))
            self.call_from_thread(lambda: self.query_one("#view-report", Button).remove_class("disabled"))

        except Exception as exc:
            self.call_from_thread(
                lambda e=exc: self.query_one("#event-log", EventLog).write(f"[red]✗ Error:[/] {e}")
            )

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "view-report" and self._case_id:
            self.app.push_screen(ReportScreen(self._case_id))


class AnalyzeScreenDirect(Screen):
    def __init__(self, binary_path: str, tier: str = "standard"):
        super().__init__()
        self.binary_path = binary_path
        self.tier = tier
        self._final_state = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Label(f"[bold]Analyzing:[/] {Path(self.binary_path).name}", classes="title"),
            Static(f"Tier: {self.tier.upper()}  |  Mode: [cyan]Direct[/]", id="tier-info"),
            PhaseProgress(id="phase-progress"),
            ProgressBar(total=100, id="progress-bar", show_eta=False),
            EventLog(id="event-log"),
            RichLog(id="signals", highlight=True, wrap=True, max_lines=10),
            Horizontal(
                Button("View Report", variant="primary", id="view-report", disabled=True),
                Button("Back", id="back"),
            ),
        )
        yield Footer()

    def on_mount(self):
        self._run_analysis()

    def _update_phase(self, phase: str, phase_progress, progress_bar, event_log, phase_idx):
        if phase in PHASE_ORDER:
            idx = PHASE_ORDER.index(phase) + 1
            if idx > phase_idx[0]:
                phase_idx[0] = idx
                pct = (idx / len(PHASE_ORDER)) * 100
                phase_progress.update(phase=phase, progress=pct)
                progress_bar.update(progress=pct)
                emoji = PHASE_EMOJI.get(phase, "→")
                label = PHASE_LABELS.get(phase, phase.upper())
                event_log.write(f"[cyan]{emoji}[/] {label}")

    @work(thread=True)
    def _run_analysis(self):
        from agents.gandalf import GandalfOrchestrator

        try:
            orchestrator = GandalfOrchestrator()
            phase_progress = self.query_one("#phase-progress", PhaseProgress)
            progress_bar = self.query_one("#progress-bar", ProgressBar)
            event_log = self.query_one("#event-log", EventLog)
            phase_idx = [0]

            self.call_from_thread(
                lambda: event_log.write(f"[cyan]→[/] Starting direct analysis via GandalfOrchestrator...")
            )

            for event in orchestrator.stream(self.binary_path, tier=self.tier):
                if isinstance(event, dict):
                    for node_name in event:
                        if node_name in PHASE_ORDER:
                            self.call_from_thread(
                                lambda p=node_name: self._update_phase(p, phase_progress, progress_bar, event_log, phase_idx)
                            )

            self._final_state = orchestrator.run(self.binary_path, tier=self.tier)
            self.call_from_thread(lambda: event_log.write("[bold green]✓ Analysis complete![/]"))
            self.call_from_thread(lambda: self.query_one("#view-report", Button).remove_class("disabled"))

        except Exception as exc:
            self.call_from_thread(
                lambda: self.query_one("#event-log", EventLog).write(f"[red]✗ Error:[/] {exc}")
            )

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "view-report" and self._final_state:
            report_text = self._final_state.get("artifacts", {}).get("final_report", "")
            sha = self._final_state.get("sha256", "")
            self.app.push_screen(ReportScreenDirect(report_text or "(No report generated)", sha))


class ReportScreenDirect(Screen):
    def __init__(self, report_text: str, case_sha: str = ""):
        super().__init__()
        self.report_text = report_text
        self.case_sha = case_sha

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label(f"[bold]Analysis Report[/]" + (f" — {self.case_sha[:16]}..." if self.case_sha else ""), classes="title"),
            RichLog(id="report-content", wrap=True, highlight=True),
            Button("Back", id="back"),
        )
        yield Footer()

    def on_mount(self):
        log = self.query_one("#report-content", RichLog)
        log.clear()
        log.write(self.report_text)

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "back":
            self.app.pop_screen()


class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label("[bold cyan]╔══════════════════════════════╗\n"
                  "║        M O R D O R             ║\n"
                  "║  Malware Analysis Pipeline     ║\n"
                  "╚══════════════════════════════╝[/]", classes="title"),
            Static("", id="subtitle"),
            Vertical(
                Button("🔍 Analyze a Binary", variant="primary", id="analyze"),
                Button("📂 View Past Cases", id="cases"),
                Button("⚙ Settings", id="settings"),
                Button("❌ Quit", id="quit"),
            ),
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "analyze":
            self._prompt_binary()
        elif event.button.id == "cases":
            self.app.push_screen(CaseSelector())
        elif event.button.id == "settings":
            self.app.push_screen(SettingsScreen())
        elif event.button.id == "quit":
            self.app.exit()

    def _prompt_binary(self):

        class BinaryInput(Screen):
            def compose(self):
                yield Container(
                    Label("Enter path to binary:"),
                    Input(placeholder="/path/to/malware.exe", id="binary-input"),
                    Horizontal(
                        Button("Submit", variant="primary", id="submit"),
                        Button("Cancel", id="cancel"),
                    ),
                )

            def on_button_pressed(self, e: Button.Pressed):
                if e.button.id == "submit":
                    path = self.query_one("#binary-input", Input).value
                    if path:
                        self.app.pop_screen()
                        self.app.push_screen(TierSelectScreen(path))
                else:
                    self.app.pop_screen()

        self.app.push_screen(BinaryInput())


class TierSelectScreen(Screen):
    def __init__(self, binary_path: str):
        super().__init__()
        self.binary_path = binary_path

    def compose(self) -> ComposeResult:
        yield Container(
            Label(f"[bold]Binary:[/] {Path(self.binary_path).name}"),
            Label("Select analysis depth:"),
            Button("⚡ Quick (tool only)", id="quick"),
            Button("📊 Standard (full)", variant="primary", id="standard"),
            Button("🔬 Deep (full + extra)", id="deep"),
            Button("Back", id="back"),
        )

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id in ("quick", "standard", "deep"):
            self.app.push_screen(AnalyzeScreen(self.binary_path, event.button.id))
        elif event.button.id == "back":
            self.app.pop_screen()


class SettingsScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label("[bold]Settings[/]", classes="title"),
            Label("API Server URL:"),
            Input(value=API_DEFAULT, id="api-url"),
            Label("Analysis defaults:"),
            Horizontal(
                Button("Test Connection", id="test"),
                Button("Save", variant="primary", id="save"),
                Button("Back", id="back"),
            ),
            Static(id="settings-status"),
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "test":
            url = self.query_one("#api-url", Input).value
            try:
                httpx.get(f"{url}/v1/health", timeout=5)
                self.query_one("#settings-status", Static).update(f"[green]✓ Connected to {url}[/]")
            except Exception as e:
                self.query_one("#settings-status", Static).update(f"[red]✗ {e}[/]")
        elif event.button.id == "back":
            self.app.pop_screen()


class MordorTUI(App):
    TITLE = "MORDOR — Malware Analysis Pipeline"
    SUB_TITLE = "One does not simply walk into Mordor"
    CSS = """
    Screen {
        align: center middle;
    }
    Container {
        width: 80%;
        height: auto;
        margin: 1;
    }
    Vertical {
        width: 60%;
        height: auto;
        margin: 1 2;
    }
    Button {
        margin: 1 0;
        width: 100%;
    }
    .title {
        text-align: center;
        margin: 1;
    }
    PhaseProgress {
        margin: 1 0;
    }
    ProgressBar {
        margin: 0 1;
    }
    #event-log {
        height: 10;
        border: solid $primary;
        margin: 1 0;
    }
    #signals {
        height: 6;
        border: solid $secondary;
        margin: 1 0;
    }
    DataTable {
        height: 60%;
    }
    Input {
        margin: 1 0;
    }
    #case-detail {
        margin: 1;
        padding: 1;
        border: solid $primary;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("a", "analyze", "Analyze"),
        Binding("c", "cases", "Cases"),
    ]

    def compose(self) -> ComposeResult:
        yield MainScreen()

    def action_quit(self):
        self.exit()

    def action_analyze(self):
        self.push_screen(MainScreen())

    def action_cases(self):
        self.push_screen(CaseSelector())


def run_tui(binary_path: str | None = None, tier: str = "standard"):
    if binary_path:
        class DirectApp(App):
            TITLE = "MORDOR — Direct Analysis"
            SUB_TITLE = "One does not simply walk into Mordor"
            CSS = MordorTUI.CSS
            BINDINGS = [
                Binding("q", "quit", "Quit", priority=True),
            ]

            def compose(self) -> ComposeResult:
                yield AnalyzeScreenDirect(binary_path, tier)

            def action_quit(self):
                self.exit()

        app = DirectApp()
    else:
        app = MordorTUI()
    app.run()
