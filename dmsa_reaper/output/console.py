from __future__ import annotations

from rich.console import Console
from rich.table import Table

from dmsa_reaper.models import Confidence, PathCandidate

console = Console()

_CONFIDENCE_STYLE = {
    Confidence.high: "green",
    Confidence.medium: "yellow",
    Confidence.low: "red",
}


def print_paths(paths: list[PathCandidate]) -> None:
    table = Table(title="dMSA-Reaper Paths", show_lines=False)
    table.add_column("ID", style="bold", no_wrap=True)
    table.add_column("Primitive", no_wrap=True)
    table.add_column("Conf", no_wrap=True)
    table.add_column("Exec", no_wrap=True)
    table.add_column("Principal", no_wrap=True)
    table.add_column("Target / dMSA")
    table.add_column("Container")
    table.add_column("Required Rights")

    for p in paths:
        conf_style = _CONFIDENCE_STYLE.get(p.confidence, "")
        rights_summary = "\n".join(p.required_rights) if p.required_rights else "-"
        exec_col = "[green]yes[/green]" if p.executable else "[red]no[/red]"

        # Build the Target/dMSA cell.
        if p.target_dn:
            target_col = p.target_dn
        elif p.dmsa_dn and not p.requires_operator_target:
            target_col = p.dmsa_dn
        elif p.requires_operator_target:
            if p.candidate_targets_count:
                target_col = (
                    f"[dim]needs --target-dn "
                    f"({p.candidate_targets_count} candidate(s))[/dim]"
                )
            else:
                target_col = "[dim]needs --target-dn[/dim]"
        elif p.dmsa_dn:
            target_col = p.dmsa_dn
        else:
            target_col = "-"

        container_col = p.container_dn or "-"
        table.add_row(
            p.id,
            p.primitive,
            f"[{conf_style}]{p.confidence.value}[/{conf_style}]" if conf_style else p.confidence.value,
            exec_col,
            p.principal,
            target_col,
            container_col,
            rights_summary,
        )

    console.print(table)
