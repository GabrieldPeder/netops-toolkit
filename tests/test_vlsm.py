"""Testes do planejamento VLSM (lógica, sem CLI)."""

import ipaddress
import json

import pytest

from netops_toolkit.vlsm import SubnetNeed, VlsmError, parse_need, plan_vlsm


def needs(**hosts):
    return [SubnetNeed(name, count) for name, count in hosts.items()]


class TestParseNeed:
    def test_valid(self):
        assert parse_need("vendas=100") == SubnetNeed("vendas", 100)

    def test_whitespace_and_equals_in_name(self):
        assert parse_need(" filial=sp = 30 ") == SubnetNeed("filial=sp", 30)

    @pytest.mark.parametrize("text", ["vendas", "=10", "vendas=", "vendas=0", "vendas=-1", "a=1.5"])
    def test_invalid(self, text):
        with pytest.raises(VlsmError):
            parse_need(text)

    def test_name_too_long(self):
        with pytest.raises(VlsmError, match="nome muito longo"):
            parse_need("x" * 65 + "=10")


class TestPlan:
    def test_classic_example(self):
        plan = plan_vlsm("10.0.0.0/22", needs(vendas=200, ti=50, rh=20, wan=2))

        assert [(a.name, a.network) for a in plan.allocations] == [
            ("vendas", "10.0.0.0/24"),
            ("ti", "10.0.1.0/26"),
            ("rh", "10.0.1.64/27"),
            ("wan", "10.0.1.96/30"),
        ]
        vendas = plan.allocations[0]
        assert vendas.netmask == "255.255.255.0"
        assert vendas.first_usable == "10.0.0.1"
        assert vendas.last_usable == "10.0.0.254"
        assert vendas.broadcast_address == "10.0.0.255"
        assert vendas.usable_hosts == 254
        assert vendas.spare_hosts == 54

    def test_input_order_does_not_matter(self):
        first = plan_vlsm("10.0.0.0/22", needs(wan=2, rh=20, vendas=200))
        second = plan_vlsm("10.0.0.0/22", needs(vendas=200, rh=20, wan=2))

        assert first.allocations == second.allocations

    def test_ties_keep_input_order(self):
        plan = plan_vlsm("10.0.0.0/24", needs(b=10, a=10))

        assert [a.name for a in plan.allocations] == ["b", "a"]

    @pytest.mark.parametrize(
        ("hosts", "prefix"),
        [(1, 30), (2, 30), (3, 29), (6, 29), (7, 28), (14, 28), (62, 26), (126, 25), (254, 24)],
    )
    def test_smallest_prefix_that_fits(self, hosts, prefix):
        plan = plan_vlsm("10.0.0.0/16", needs(x=hosts))

        assert plan.allocations[0].prefix_length == prefix

    def test_255_hosts_needs_slash_23(self):
        plan = plan_vlsm("10.0.0.0/16", needs(x=255))

        assert plan.allocations[0].prefix_length == 23

    def test_use_31_for_point_to_point(self):
        plan = plan_vlsm("10.0.0.0/24", needs(wan1=2, wan2=1), use_31=True)

        first = plan.allocations[0]
        assert first.prefix_length == 31
        assert first.broadcast_address is None
        assert first.usable_hosts == 2
        assert (first.first_usable, first.last_usable) == ("10.0.0.0", "10.0.0.1")
        assert any("RFC 3021" in note for note in plan.notes)

    def test_use_31_does_not_affect_larger_needs(self):
        plan = plan_vlsm("10.0.0.0/24", needs(lan=3), use_31=True)

        assert plan.allocations[0].prefix_length == 29

    def test_exact_fit_has_no_free_blocks(self):
        plan = plan_vlsm("192.168.1.0/24", needs(a=126, b=126))

        assert plan.free_blocks == ()
        assert plan.utilization_percent == 100.0

    def test_free_blocks_cover_the_rest(self):
        plan = plan_vlsm("10.0.0.0/22", needs(vendas=200, ti=50))

        assert plan.free_blocks == ("10.0.1.64/26", "10.0.1.128/25", "10.0.2.0/23")
        free = sum(ipaddress.ip_network(block).num_addresses for block in plan.free_blocks)
        assert plan.allocated_addresses + free == plan.total_addresses

    def test_allocations_do_not_overlap_and_stay_inside_block(self):
        plan = plan_vlsm("172.16.0.0/20", needs(a=500, b=250, c=120, d=60, e=30, f=2, g=2))
        block = ipaddress.ip_network(plan.block)
        networks = [ipaddress.ip_network(a.network) for a in plan.allocations]

        assert all(network.subnet_of(block) for network in networks)
        for index, network in enumerate(networks):
            assert not any(network.overlaps(other) for other in networks[index + 1 :])

    def test_host_bits_in_block_are_accepted_with_note(self):
        plan = plan_vlsm("10.0.0.77/24", needs(a=10))

        assert plan.block == "10.0.0.0/24"
        assert any("10.0.0.0/24" in note for note in plan.notes)


class TestErrors:
    def test_does_not_fit(self):
        with pytest.raises(VlsmError, match=r"384 endereços.*256"):
            plan_vlsm("192.168.1.0/24", needs(a=200, b=100))

    def test_need_larger_than_block(self):
        with pytest.raises(VlsmError, match="não cabem"):
            plan_vlsm("10.0.0.0/30", needs(a=10))

    def test_ipv6_is_rejected(self):
        with pytest.raises(VlsmError, match="apenas para IPv4"):
            plan_vlsm("2001:db8::/48", needs(a=10))

    def test_invalid_block(self):
        with pytest.raises(VlsmError, match="prefixo inválido"):
            plan_vlsm("10.0.0.0/33", needs(a=10))

    def test_duplicate_names_are_case_insensitive(self):
        with pytest.raises(VlsmError, match="nome repetido"):
            plan_vlsm("10.0.0.0/24", needs(vendas=10, Vendas=5))

    def test_no_needs(self):
        with pytest.raises(VlsmError, match="ao menos uma"):
            plan_vlsm("10.0.0.0/24", [])


def test_json_structure():
    data = json.loads(plan_vlsm("10.0.0.0/22", needs(vendas=200, wan=2)).to_json())

    assert data["block"] == "10.0.0.0/22"
    assert data["free_addresses"] == 1024 - 256 - 4
    assert data["allocations"][1] == {
        "name": "wan",
        "hosts_requested": 2,
        "network": "10.0.1.0/30",
        "prefix_length": 30,
        "netmask": "255.255.255.252",
        "first_usable": "10.0.1.1",
        "last_usable": "10.0.1.2",
        "broadcast_address": "10.0.1.3",
        "usable_hosts": 2,
        "spare_hosts": 0,
    }
