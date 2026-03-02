"""
Terminal and file output reporter.
Produces rich tables, markdown, and JSON output.
"""
from typing import Any, Dict

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich import box


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "UNKNOWN":  "dim white",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "UNKNOWN":  "⚪",
}


class Reporter:
    def __init__(self, console: Console):
        self.console = console

    # ── Rich Table Output ──────────────────────────────────────────────────
    def print_table(self, result: Dict[str, Any]) -> None:
        valid   = result.get("valid", False)
        error   = result.get("error")
        br      = result.get("blast_radius", {})
        perms   = result.get("permissions", {})
        identity = result.get("identity", {})
        severity = br.get("severity", "UNKNOWN")

        # ── Status header ────────────────────────────────────────────────────
        if valid:
            status_text = Text("✔  CREDENTIAL VALID", style="bold green")
        else:
            status_text = Text("✘  CREDENTIAL INVALID / EXPIRED", style="bold red")

        self.console.print()
        self.console.print(Panel(
            status_text,
            title=f"[bold]{result.get('provider', '?')} — {result.get('cred_type', '?')}[/bold]",
            border_style="green" if valid else "red",
        ))

        if error:
            self.console.print(f"\n[red]Error:[/red] {error}\n")
            if not valid:
                return

        # ── Identity table ───────────────────────────────────────────────────
        if identity:
            id_table = Table(title="Identity", box=box.ROUNDED, border_style="cyan", show_header=True)
            id_table.add_column("Field",  style="dim", width=22)
            id_table.add_column("Value",  style="cyan")
            for k, v in identity.items():
                if isinstance(v, (dict, list)):
                    continue
                id_table.add_row(k.replace("_", " ").title(), str(v))
            self.console.print(id_table)

        # ── Blast radius ─────────────────────────────────────────────────────
        if br:
            sev_color = SEVERITY_COLORS.get(severity, "white")
            sev_icon  = SEVERITY_ICONS.get(severity, "⚪")

            br_table = Table(
                title=f"Blast Radius Assessment  {sev_icon} [{sev_color}]{severity}[/{sev_color}]",
                box=box.ROUNDED,
                border_style=sev_color,
                show_header=True,
            )
            br_table.add_column("Item",    style="dim", width=28)
            br_table.add_column("Detail",  style="white")

            for k, v in br.items():
                if k in ("severity", "summary"):
                    continue
                if isinstance(v, bool):
                    val = "[red]YES[/red]" if v else "[green]NO[/green]"
                elif isinstance(v, list):
                    val = "\n".join(f"• {i}" for i in v[:8]) if v else "[dim]none[/dim]"
                else:
                    val = str(v) if v else "[dim]—[/dim]"
                br_table.add_row(k.replace("_", " ").title(), val)

            self.console.print()
            self.console.print(br_table)
            if br.get("summary"):
                self.console.print(
                    Panel(br["summary"], title="Summary", border_style=sev_color, padding=(0, 1))
                )

        # ── Permissions ───────────────────────────────────────────────────────
        if perms and isinstance(perms, dict):
            perm_table = Table(title="Permissions", box=box.ROUNDED, border_style="yellow", show_header=True)
            perm_table.add_column("Category", style="dim", width=28)
            perm_table.add_column("Items",    style="yellow")

            for k, v in perms.items():
                if isinstance(v, list) and v:
                    perm_table.add_row(
                        k.replace("_", " ").title(),
                        "\n".join(f"• {i}" for i in v[:12]),
                    )
                elif isinstance(v, str):
                    perm_table.add_row(k.replace("_", " ").title(), v)

            self.console.print()
            self.console.print(perm_table)

        # ── Remediation ───────────────────────────────────────────────────────
        remediation = result.get("remediation", {})
        if remediation and valid:
            rem_lines = []
            for k, v in remediation.items():
                rem_lines.append(f"[bold]{k.replace('_',' ').title()}:[/bold] {v}")
            self.console.print()
            self.console.print(Panel(
                "\n".join(rem_lines),
                title="[bold red]⚠  Remediation[/bold red]",
                border_style="red",
                padding=(0, 1),
            ))

        self.console.print()

    # ── Markdown Output ────────────────────────────────────────────────────
    def to_markdown(self, result: Dict[str, Any]) -> str:
        lines = []
        provider = result.get("provider", "Unknown")
        cred_type = result.get("cred_type", "unknown")
        valid     = result.get("valid", False)
        br        = result.get("blast_radius", {})
        perms     = result.get("permissions", {})
        identity  = result.get("identity", {})
        severity  = br.get("severity", "UNKNOWN")

        lines.append(f"# CloudKeyRotator Report — {provider}")
        lines.append("")
        lines.append(f"**Status:** {'✅ VALID' if valid else '❌ INVALID'}  ")
        lines.append(f"**Provider:** {provider}  ")
        lines.append(f"**Type:** {cred_type}  ")
        lines.append(f"**Severity:** {SEVERITY_ICONS.get(severity, '⚪')} {severity}  ")
        lines.append("")

        if result.get("error"):
            lines.append(f"> ⚠️  **Error:** {result['error']}")
            lines.append("")

        if identity:
            lines.append("## Identity")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            for k, v in identity.items():
                if not isinstance(v, (dict, list)):
                    lines.append(f"| {k.replace('_',' ').title()} | {v} |")
            lines.append("")

        if br:
            lines.append("## Blast Radius")
            lines.append(f"**Summary:** {br.get('summary', '—')}")
            lines.append("")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            for k, v in br.items():
                if k == "summary":
                    continue
                if isinstance(v, list):
                    v = ", ".join(str(i) for i in v[:5])
                lines.append(f"| {k.replace('_',' ').title()} | {v} |")
            lines.append("")

        if perms and isinstance(perms, dict):
            lines.append("## Permissions")
            for k, v in perms.items():
                if isinstance(v, list) and v:
                    lines.append(f"**{k.replace('_',' ').title()}:**")
                    for item in v[:15]:
                        lines.append(f"- {item}")
                    lines.append("")

        remediation = result.get("remediation", {})
        if remediation and valid:
            lines.append("## Remediation")
            for k, v in remediation.items():
                lines.append(f"**{k.replace('_',' ').title()}:** `{v}`")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by CloudKeyRotator — for authorized security testing only.*")

        return "\n".join(lines)
