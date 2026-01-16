from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static


class ArgusApp(App):
    """TUI placeholder v1: verifica che `argus` apra la TUI."""

    BINDINGS = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            "👁 ARGUS — TUI placeholder (v1)\n\n"
            "Se vedi questa schermata, `argus` sta aprendo la TUI correttamente.\n"
            "Premi 'q' per uscire.",
            id="body",
        )
        yield Footer()
