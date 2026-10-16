"""Testes da calculadora de sub-redes (lógica de negócio, sem CLI)."""

import json

import pytest

from netops_toolkit.network import SubnetError, calculate_subnet, parse_network


class TestIPv4:
    def test_slash_24(self):
        info = calculate_subnet("192.168.10.0/24")

        assert info.version == 4
        assert info.network == "192.168.10.0/24"
        assert info.network_address == "192.168.10.0"
        assert info.netmask == "255.255.255.0"
        assert info.wildcard_mask == "0.0.0.255"
        assert info.broadcast_address == "192.168.10.255"
        assert info.total_addresses == 256
        assert info.usable_hosts == 254
        assert info.first_usable == "192.168.10.1"
        assert info.last_usable == "192.168.10.254"
        assert info.address_type == "private"
        assert info.host_bits_set is False

    def test_slash_30(self):
        info = calculate_subnet("10.0.0.4/30")

        assert info.netmask == "255.255.255.252"
        assert info.broadcast_address == "10.0.0.7"
        assert info.total_addresses == 4
        assert info.usable_hosts == 2
        assert info.first_usable == "10.0.0.5"
        assert info.last_usable == "10.0.0.6"

    def test_slash_31_point_to_point_has_no_broadcast(self):
        info = calculate_subnet("10.0.0.0/31")

        assert info.netmask == "255.255.255.254"
        assert info.broadcast_address is None
        assert info.total_addresses == 2
        assert info.usable_hosts == 2
        assert info.first_usable == "10.0.0.0"
        assert info.last_usable == "10.0.0.1"
        assert any("RFC 3021" in note for note in info.notes)

    def test_slash_32_single_host(self):
        info = calculate_subnet("192.0.2.10/32")

        assert info.netmask == "255.255.255.255"
        assert info.broadcast_address is None
        assert info.total_addresses == 1
        assert info.usable_hosts == 1
        assert info.first_usable == info.last_usable == "192.0.2.10"
        assert info.address_type == "documentation"

    def test_slash_0(self):
        info = calculate_subnet("0.0.0.0/0")

        assert info.total_addresses == 2**32
        assert info.usable_hosts == 2**32 - 2
        assert info.netmask == "0.0.0.0"

    def test_host_bits_set_is_accepted_and_reported(self):
        info = calculate_subnet("192.168.10.77/24")

        assert info.network == "192.168.10.0/24"
        assert info.host_bits_set is True
        assert any("192.168.10.0/24" in note for note in info.notes)

    def test_surrounding_whitespace_is_ignored(self):
        assert calculate_subnet("  192.168.10.0/24 ").network == "192.168.10.0/24"


class TestIPv6:
    def test_slash_64(self):
        info = calculate_subnet("2001:db8:abcd:12::/64")

        assert info.version == 6
        assert info.network == "2001:db8:abcd:12::/64"
        assert info.exploded == "2001:0db8:abcd:0012:0000:0000:0000:0000/64"
        assert info.total_addresses == 2**64
        assert info.first_address == "2001:db8:abcd:12::"
        assert info.last_address == "2001:db8:abcd:12:ffff:ffff:ffff:ffff"
        assert info.address_type == "documentation"
        assert any("SLAAC" in note for note in info.notes)

    def test_ipv4_only_concepts_are_not_applied(self):
        info = calculate_subnet("2001:db8::/64")

        assert info.broadcast_address is None
        assert info.netmask is None
        assert info.wildcard_mask is None
        assert info.usable_hosts is None
        assert info.first_usable is None
        assert info.last_usable is None

    def test_slash_127_and_128(self):
        assert calculate_subnet("2001:db8::/127").total_addresses == 2
        assert calculate_subnet("2001:db8::1/128").total_addresses == 1

    def test_link_local(self):
        assert calculate_subnet("fe80::/64").address_type == "link_local"

    def test_unique_local_is_private(self):
        assert calculate_subnet("fd00:1234::/48").address_type == "private"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10.0.0.0/8", "private"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link_local"),
        ("224.0.0.0/4", "multicast"),
        ("100.64.0.0/10", "shared"),
        ("198.51.100.0/24", "documentation"),
        ("::1/128", "loopback"),
        ("0.0.0.0/0", "default"),
        ("::/0", "default"),
        ("240.0.0.0/4", "reserved"),
        ("0.0.0.0/1", "other"),
        ("8.8.8.0/24", "global"),
    ],
)
def test_address_type_classification(text, expected):
    assert calculate_subnet(text).address_type == expected


class TestInvalidInput:
    @pytest.mark.parametrize(
        "text",
        ["192.168.10.0/33", "2001:db8::/129", "10.0.0.0/-1", "10.0.0.0/abc", "10.0.0.0/"],
    )
    def test_invalid_prefix(self, text):
        with pytest.raises(SubnetError, match="prefixo inválido"):
            calculate_subnet(text)

    def test_netmask_notation_is_rejected(self):
        with pytest.raises(SubnetError, match="prefixo inválido"):
            calculate_subnet("192.168.10.0/255.255.255.0")

    @pytest.mark.parametrize(
        "text",
        [
            "256.1.1.1/24",
            "192.168.1/24",
            "192.168.01.1/24",
            "abc/24",
            "2001:db8:::1/64",
            "/24",
        ],
    )
    def test_malformed_address(self, text):
        with pytest.raises(SubnetError, match="endereço IP inválido"):
            calculate_subnet(text)

    @pytest.mark.parametrize("text", ["192.168.10.0", "10.0.0.0/8/8", ""])
    def test_missing_or_extra_prefix_separator(self, text):
        with pytest.raises(SubnetError, match="formato endereço/prefixo"):
            calculate_subnet(text)

    def test_error_is_a_value_error(self):
        with pytest.raises(ValueError):
            parse_network("not-an-ip/24")


class TestJson:
    def test_ipv4_json_round_trip(self):
        data = json.loads(calculate_subnet("192.168.10.0/24").to_json())

        assert data["network"] == "192.168.10.0/24"
        assert data["usable_hosts"] == 254
        assert data["broadcast_address"] == "192.168.10.255"
        assert isinstance(data["notes"], list)

    def test_ipv6_json_uses_null_for_ipv4_fields(self):
        data = json.loads(calculate_subnet("2001:db8::/64").to_json())

        assert data["version"] == 6
        assert data["broadcast_address"] is None
        assert data["usable_hosts"] is None
        assert data["total_addresses"] == 2**64

    def test_json_has_stable_keys(self):
        ipv4_keys = set(calculate_subnet("10.0.0.0/8").to_dict())
        ipv6_keys = set(calculate_subnet("2001:db8::/64").to_dict())

        assert ipv4_keys == ipv6_keys
