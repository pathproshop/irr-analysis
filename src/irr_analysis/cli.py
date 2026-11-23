"""Typer command-line interface for ``irr-analysis``."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated

import typer

from .core import (
    DEFAULT_MAX_LENGTH,
    AdvertisedRoute,
    analyze_coverage,
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


def _customer_label(route: AdvertisedRoute) -> str:
    """Return the report label for a route's customer ASN."""

    if route.customer_asn is None:
        return "LOCAL/UNKNOWN"
    return f"AS{route.customer_asn}"


def _print_section(
    title: str,
    reason: str,
    routes: list[AdvertisedRoute],
) -> None:
    """Render a per-customer summary and one detail line per route."""

    customer_counts = Counter(_customer_label(route) for route in routes)

    typer.echo(title)
    typer.echo("-" * 40)
    for customer, count in customer_counts.most_common():
        typer.echo(f"{customer}: {count}")

    typer.echo()
    for route in routes:
        typer.echo(
            f"{route.network} - {reason} "
            f"- Customer {_customer_label(route)} "
            f"- AS-Path {route.as_path or 'N/A'}"
        )


def print_report(
    uncovered: list[AdvertisedRoute],
    too_specific: list[AdvertisedRoute],
    max_len_v4: int,
    max_len_v6: int,
) -> None:
    """Render the human-readable coverage report."""

    typer.echo(f"\n{len(uncovered)} uncovered routes found")
    typer.echo(
        f"{len(too_specific)} too-specific routes found "
        f"(longer than /{max_len_v4} IPv4 or /{max_len_v6} IPv6)\n"
    )

    if uncovered:
        _print_section(
            "Missing Routes By Customer ASN",
            "No covering route filter entry",
            uncovered,
        )

    if too_specific:
        if uncovered:
            typer.echo()
        _print_section(
            "Too-Specific Routes By Customer ASN",
            "Covered, but longer than the maximum accepted prefix length",
            too_specific,
        )
        typer.echo(
            "\nToo-specific routes are rejected by a length-limited filter "
            "unless another policy,\nsuch as a blackhole community match, "
            "accepts them."
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
    max_len_v4: Annotated[
        int,
        typer.Option(
            "--max-len-v4",
            min=0,
            max=32,
            help="Longest IPv4 prefix accepted beneath a filter entry.",
        ),
    ] = DEFAULT_MAX_LENGTH[4],
    max_len_v6: Annotated[
        int,
        typer.Option(
            "--max-len-v6",
            min=0,
            max=128,
            help="Longest IPv6 prefix accepted beneath a filter entry.",
        ),
    ] = DEFAULT_MAX_LENGTH[6],
    fail_on_too_specific: Annotated[
        bool,
        typer.Option(
            "--fail-on-too-specific",
            help="Exit with status 1 when too-specific routes are found.",
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

    result = analyze_coverage(
        advertised_routes,
        route_filters,
        max_length={4: max_len_v4, 6: max_len_v6},
    )
    print_report(result.uncovered, result.too_specific, max_len_v4, max_len_v6)

    if fail_on_uncovered and result.uncovered:
        raise typer.Exit(code=1)
    if fail_on_too_specific and result.too_specific:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
