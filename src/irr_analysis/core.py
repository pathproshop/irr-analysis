"""Core parsing and coverage-analysis functions.

The functions in this module contain no CLI-specific behavior. Keeping parsing
and analysis separate from presentation makes the code testable and allows it
to be reused by other automation later.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, TypeAlias


IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network

# BGP origin codes and common output markers that are not ASNs. Removing only
# known markers is safer than accepting every numeric-looking column as an ASN.
BGP_MARKERS = {
    "i",
    "e",
    "?",
    "I",
    "E",
    "*>i",
    "*>",
    "*",
    ">",
    "best",
}

# Plain 16-bit and 32-bit ASNs are expected in the current reports. ASDOT is
# accepted as well so older platform output such as "1.10" can be retained.
ASN_RE = re.compile(r"^(?:[0-9]+|[0-9]+\.[0-9]+)$")


# Longest prefix an upstream normally accepts beneath a registered covering
# prefix. Generated filters are commonly applied as "upto /24" for IPv4 and
# "upto /48" for IPv6, so anything longer is rejected unless a separate policy
# (for example a blackhole community match) accepts it.
DEFAULT_MAX_LENGTH: dict[int, int] = {4: 24, 6: 48}


@dataclass(frozen=True, slots=True)
class AdvertisedRoute:
    """Information retained for one advertised prefix."""

    network: IPNetwork
    source_file: Path
    raw_line: str
    as_path: str
    customer_asn: str | None


@dataclass(frozen=True, slots=True)
class CoverageResult:
    """Advertised routes that a generated filter set would not accept.

    ``uncovered`` routes have no covering filter entry at all.
    ``too_specific`` routes fall inside a filter entry but are longer than the
    maximum accepted prefix length and are not listed exactly.
    """

    uncovered: list[AdvertisedRoute]
    too_specific: list[AdvertisedRoute]


def parse_network_token(token: str) -> IPNetwork | None:
    """Return an IP network parsed from *token*, or ``None`` if invalid.

    ``strict=False`` normalizes a token containing host bits instead of dropping
    the line. Router output should normally contain canonical prefixes, but the
    relaxed behavior is more useful for operational analysis.
    """

    # Common generated configurations may append punctuation to a prefix.
    candidate = token.strip(";,[]()")
    try:
        return ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None


def find_network(parts: list[str]) -> tuple[int, IPNetwork] | None:
    """Find the first IP prefix in a whitespace-tokenized input line."""

    for index, field in enumerate(parts):
        network = parse_network_token(field)
        if network is not None:
            return index, network
    return None


def _is_asn(token: str) -> bool:
    """Return whether *token* resembles a plain or ASDOT ASN."""

    normalized = token.upper().removeprefix("AS")
    return bool(ASN_RE.fullmatch(normalized))


def _normalize_asn(token: str) -> str:
    """Return an ASN without an optional leading ``AS``."""

    return token.upper().removeprefix("AS")


def extract_path_data(parts: list[str], prefix_index: int) -> tuple[str, str | None]:
    """Extract report-compatible AS-path text and a probable customer ASN.

    Junos advertised-route output contains ``Self``, followed by MED and then
    the path. To preserve the existing report format, the returned AS-path text
    begins at the MED while customer attribution uses the following numeric
    token.

    IOS XR layouts vary by release and command. For lines without ``Self``, the
    function performs conservative best-effort extraction from tokens after the
    prefix. Coverage analysis remains valid even when customer attribution is
    unavailable.
    """

    try:
        self_index = parts.index("Self", prefix_index + 1)
    except ValueError:
        self_index = -1

    if self_index >= 0:
        # Expected Junos shape: PREFIX Self MED [ASN ...] ORIGIN.
        path_tokens = parts[self_index + 1 :]
        customer_asn = None
        if len(path_tokens) >= 2 and _is_asn(path_tokens[1]):
            customer_asn = _normalize_asn(path_tokens[1])
        return " ".join(path_tokens), customer_asn

    # Best-effort XR/fallback mode. Keep the original post-prefix text for
    # troubleshooting, then find plausible ASNs after ignoring known markers.
    path_tokens = parts[prefix_index + 1 :]
    plausible_asns = [
        _normalize_asn(token.rstrip("ie?"))
        for token in path_tokens
        if token not in BGP_MARKERS and _is_asn(token.rstrip("ie?"))
    ]

    # Output immediately after a prefix often includes weight/metric/local-pref.
    # Choosing the last plausible numeric field is safer for a one-AS path and
    # remains best-effort until a command-specific XR sample is validated.
    customer_asn = plausible_asns[-1] if plausible_asns else None
    return " ".join(path_tokens), customer_asn


def read_advertised_routes_file(filename: str | Path) -> dict[str, AdvertisedRoute]:
    """Read one Junos or IOS XR advertised-route text file.

    Lines without a valid IPv4 or IPv6 prefix are ignored. The dictionary key is
    the canonical string form of the network.
    """

    path = Path(filename)
    routes: dict[str, AdvertisedRoute] = {}

    with path.open("r", encoding="utf-8") as file_handle:
        for raw_line in file_handle:
            parts = raw_line.split()
            if not parts:
                continue

            found = find_network(parts)
            if found is None:
                continue

            prefix_index, network = found
            as_path, customer_asn = extract_path_data(parts, prefix_index)
            routes[str(network)] = AdvertisedRoute(
                network=network,
                source_file=path,
                raw_line=raw_line.strip(),
                as_path=as_path,
                customer_asn=customer_asn,
            )

    return routes


def read_route_filter_file(filename: str | Path) -> set[IPNetwork]:
    """Read and deduplicate prefixes from one bgpq4-generated file.

    The first valid prefix found on each line is accepted. This handles plain
    ``%n/%l`` output and common configuration lines containing extra keywords.
    """

    path = Path(filename)
    filters: set[IPNetwork] = set()

    with path.open("r", encoding="utf-8") as file_handle:
        for raw_line in file_handle:
            parts = raw_line.split()
            if not parts:
                continue
            found = find_network(parts)
            if found is not None:
                _, network = found
                filters.add(network)

    return filters


def load_advertised_routes(
    filenames: Iterable[str | Path],
) -> dict[str, AdvertisedRoute]:
    """Load advertised routes from multiple files.

    If a prefix occurs more than once, the final file's record wins. This
    mirrors the original script and keeps one report record per unique prefix.
    """

    routes: dict[str, AdvertisedRoute] = {}
    for filename in filenames:
        routes.update(read_advertised_routes_file(filename))
    return routes


def load_route_filters(filenames: Iterable[str | Path]) -> set[IPNetwork]:
    """Load and deduplicate route filters from multiple files."""

    filters: set[IPNetwork] = set()
    for filename in filenames:
        filters.update(read_route_filter_file(filename))
    return filters


def find_uncovered_routes(
    advertised_routes: dict[str, AdvertisedRoute],
    route_filters: Iterable[IPNetwork],
) -> list[AdvertisedRoute]:
    """Return advertisements without a same-family covering filter prefix."""

    # Partitioning by IP version avoids invalid IPv4/IPv6 comparisons and cuts
    # the number of containment checks for mixed-family input.
    filters_by_version: dict[int, list[IPNetwork]] = {4: [], 6: []}
    for route_filter in route_filters:
        filters_by_version[route_filter.version].append(route_filter)

    uncovered = []
    for route in advertised_routes.values():
        same_family_filters = filters_by_version[route.network.version]
        if not any(route.network.subnet_of(item) for item in same_family_filters):
            uncovered.append(route)

    return sorted(uncovered, key=_sort_key)


def _sort_key(route: AdvertisedRoute) -> tuple[int, int, int]:
    """Order routes by family, then address, then prefix length."""

    return (
        route.network.version,
        int(route.network.network_address),
        route.network.prefixlen,
    )


def analyze_coverage(
    advertised_routes: dict[str, AdvertisedRoute],
    route_filters: Iterable[IPNetwork],
    max_length: dict[int, int] | None = None,
) -> CoverageResult:
    """Classify advertisements against filters and a prefix-length ceiling.

    A route is accepted when it matches a filter entry exactly, or when it
    falls inside a filter entry and its prefix length does not exceed the
    ceiling for its address family. This models filters applied as
    ``upto /24`` (IPv4) and ``upto /48`` (IPv6).

    Routes inside a filter entry but longer than the ceiling are returned as
    ``too_specific`` rather than ``uncovered``. Communities are not visible in
    advertised-route output, so a legitimate blackhole host route cannot be
    told apart from a leaked more-specific; reporting them separately leaves
    that judgment to the operator.
    """

    ceilings = dict(DEFAULT_MAX_LENGTH)
    if max_length:
        ceilings.update(max_length)

    filters_by_version: dict[int, list[IPNetwork]] = {4: [], 6: []}
    exact: set[IPNetwork] = set()
    for route_filter in route_filters:
        filters_by_version[route_filter.version].append(route_filter)
        exact.add(route_filter)

    uncovered: list[AdvertisedRoute] = []
    too_specific: list[AdvertisedRoute] = []

    for route in advertised_routes.values():
        network = route.network
        if network in exact:
            continue

        same_family_filters = filters_by_version[network.version]
        if not any(network.subnet_of(item) for item in same_family_filters):
            uncovered.append(route)
        elif network.prefixlen > ceilings[network.version]:
            too_specific.append(route)

    return CoverageResult(
        uncovered=sorted(uncovered, key=_sort_key),
        too_specific=sorted(too_specific, key=_sort_key),
    )
