"""Regression tests for dual-stack parsing and coverage behavior."""

import ipaddress

from irr_analysis.core import (
    analyze_coverage,
    extract_path_data,
    find_uncovered_routes,
    read_advertised_routes_file,
    read_route_filter_file,
)


def test_junos_ipv6_customer_asn_and_path():
    parts = "* 3fff:100::/32 Self 75 64496 I".split()
    as_path, customer = extract_path_data(parts, prefix_index=1)
    assert as_path == "75 64496 I"
    assert customer == "64496"


def test_junos_local_route_is_unknown():
    parts = "* 2001:db8:100::/40 Self 0 I".split()
    as_path, customer = extract_path_data(parts, prefix_index=1)
    assert as_path == "0 I"
    assert customer is None


def test_read_advertised_routes_dual_stack(tmp_path):
    source = tmp_path / "advertised.txt"
    source.write_text(
        "* 198.51.100.0/24 Self 75 64498 I\n"
        "* 3fff:100::/32 Self 75 64496 I\n",
        encoding="utf-8",
    )
    routes = read_advertised_routes_file(source)
    assert set(routes) == {"198.51.100.0/24", "3fff:100::/32"}


def test_filter_reader_scans_for_prefix(tmp_path):
    source = tmp_path / "filters.txt"
    source.write_text(
        "2001:288::/32\n"
        "route-filter 3fff:100::/32 exact;\n",
        encoding="utf-8",
    )
    filters = read_route_filter_file(source)
    assert filters == {
        ipaddress.ip_network("2001:288::/32"),
        ipaddress.ip_network("3fff:100::/32"),
    }


def test_coverage_is_address_family_aware(tmp_path):
    source = tmp_path / "advertised.txt"
    source.write_text(
        "* 10.0.1.0/24 Self 75 64500 I\n"
        "* 2001:db8:1::/48 Self 75 64501 I\n",
        encoding="utf-8",
    )
    routes = read_advertised_routes_file(source)
    filters = {
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("2001:db8::/32"),
    }
    assert find_uncovered_routes(routes, filters) == []


def test_uncovered_route_is_reported(tmp_path):
    source = tmp_path / "advertised.txt"
    source.write_text(
        "* 3fff:100::/32 Self 75 64496 I\n",
        encoding="utf-8",
    )
    routes = read_advertised_routes_file(source)
    filters = {ipaddress.ip_network("2001:db8::/32")}
    uncovered = find_uncovered_routes(routes, filters)
    assert [str(route.network) for route in uncovered] == ["3fff:100::/32"]


def _routes(tmp_path, *lines):
    source = tmp_path / "advertised.txt"
    source.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return read_advertised_routes_file(source)


def test_route_at_ceiling_is_accepted(tmp_path):
    routes = _routes(
        tmp_path,
        "* 198.51.100.0/24 Self 75 64496 I",
        "* 2001:db8:1::/48 Self 75 64496 I",
    )
    filters = {
        ipaddress.ip_network("198.51.0.0/16"),
        ipaddress.ip_network("2001:db8::/32"),
    }
    result = analyze_coverage(routes, filters)
    assert result.uncovered == []
    assert result.too_specific == []


def test_route_longer_than_ceiling_is_too_specific(tmp_path):
    routes = _routes(
        tmp_path,
        "* 198.51.100.7/32 Self 75 64496 I",
        "* 2001:db8:1:1::/64 Self 75 64496 I",
    )
    filters = {
        ipaddress.ip_network("198.51.0.0/16"),
        ipaddress.ip_network("2001:db8::/32"),
    }
    result = analyze_coverage(routes, filters)
    assert result.uncovered == []
    assert [str(route.network) for route in result.too_specific] == [
        "198.51.100.7/32",
        "2001:db8:1:1::/64",
    ]


def test_exact_filter_entry_is_accepted_at_any_length(tmp_path):
    routes = _routes(tmp_path, "* 198.51.100.128/25 Self 75 64496 I")
    filters = {
        ipaddress.ip_network("198.51.0.0/16"),
        ipaddress.ip_network("198.51.100.128/25"),
    }
    result = analyze_coverage(routes, filters)
    assert result.uncovered == []
    assert result.too_specific == []


def test_uncovered_takes_priority_over_length(tmp_path):
    routes = _routes(tmp_path, "* 3fff:100::1/128 Self 75 64496 I")
    filters = {ipaddress.ip_network("2001:db8::/32")}
    result = analyze_coverage(routes, filters)
    assert [str(route.network) for route in result.uncovered] == ["3fff:100::1/128"]
    assert result.too_specific == []


def test_custom_ceiling_overrides_default(tmp_path):
    routes = _routes(tmp_path, "* 198.51.100.0/25 Self 75 64496 I")
    filters = {ipaddress.ip_network("198.51.0.0/16")}
    assert analyze_coverage(routes, filters).too_specific != []
    relaxed = analyze_coverage(routes, filters, max_length={4: 25})
    assert relaxed.too_specific == []
