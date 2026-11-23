"""Typer command-line interface for ``irr-analysis``."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated

import typer

from .core import (
    AdvertisedRoute,
    find_uncovered_routes,
    load_advertised_routes,
    load_route_filters,
)

app = typer.Typer(
    add_completion=False,
    help="Compare advertised BGP routes with bgpq4-generated filters.",
    no_args_is_help=True,
)


def parse_csv_paths(value: str, option_name: str) -> list[Path]:
    """Parse and validate a comma-separated CLI file list."""

    paths = [Path(item.strip()).expanduser() for item in value.split(",") if item.strip()]
    if not paths:
        raise typer.BadParameter(
            "provide at least one file name",
            param_hint=option_name,
        )

    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise typer.BadParameter(
            f"file(s) not found: {', '.join(missing)}",
            param_hint=option_name,
        )
    return paths


def print_report(uncovered: list[AdvertisedRoute]) -> None:
    """Render the human-readable uncovered-route report."""

    typer.echo(f"\n{len(uncovered)} uncovered routes found\n")
    if not uncovered:
        return

    customer_counts = Counter(
        route.customer_asn or "LOCAL/UNKNOWN" for route in uncovered
    )

    typer.echo("Missing Routes By Customer ASN")
    typer.echo("-" * 40)
    for customer, count in customer_counts.most_common():
        label = customer if customer == "LOCAL/UNKNOWN" else f"AS{customer}"
        typer.echo(f"{label}: {count}")

    typer.echo()
    for route in uncovered:
        customer = (
            f"AS{route.customer_asn}"
            if route.customer_asn is not None
            else "LOCAL/UNKNOWN"
        )
        typer.echo(
            f"{route.network} - No covering route filter entry "
            f"- Customer {customer} - AS-Path {route.as_path or 'N/A'}"
        )


@app.command()
def main(
    filters: Annotated[
        str,
        typer.Option(
            "--filters",
            "-f",
            help="Comma-separated bgpq4-generated filter file names.",
            metavar="FILE[,FILE...]",
        ),
    ],
    advertised: Annotated[
        str,
        typer.Option(
            "--advertised",
            "-a",
            help="Comma-separated advertised-route file names.",
            metavar="FILE[,FILE...]",
        ),
    ],
    fail_on_uncovered: Annotated[
        bool,
        typer.Option(
            "--fail-on-uncovered",
            help="Exit with status 1 when uncovered routes are found.",
        ),
    ] = False,
) -> None:
    """Compare advertised routes with trusted IRR/RPKI filter data."""

    filter_files = parse_csv_paths(filters, "--filters")
    advertised_files = parse_csv_paths(advertised, "--advertised")

    advertised_routes = load_advertised_routes(advertised_files)
    route_filters = load_route_filters(filter_files)

    typer.echo(
        f"Loaded {len(advertised_routes)} unique advertised routes "
        f"from {len(advertised_files)} file(s)"
    )
    typer.echo(
        f"Loaded {len(route_filters)} unique route-filter entries "
        f"from {len(filter_files)} file(s)"
    )

    uncovered = find_uncovered_routes(advertised_routes, route_filters)
    print_report(uncovered)

    if fail_on_uncovered and uncovered:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
