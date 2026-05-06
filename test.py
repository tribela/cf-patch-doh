#!/usr/bin/env python3
"""Unit tests for cf-patch-doh.

Tests internal logic without requiring a running HTTP server.
Network calls (fetch_dns, _get_icn_ips) are mocked.
"""
import struct
from unittest.mock import AsyncMock, patch

import dnslib
import pytest
from dnslib import DNSRecord, HTTPS, QTYPE, RR

from cf_patch_doh.dns_utils import (
    TtlCache,
    _pack_ipv4s,
    _pack_ipv6s,
    _unpack_ipv4s,
    _unpack_ipv6s,
    is_cloudflare_sync,
    make_answer,
    patch_response,
    should_bypass,
)
from cf_patch_doh.cloudflare import CF_NETWORKS

# =============================================================================
# Helper function tests
# =============================================================================


class TestIpPackUnpack:
    def test_unpack_ipv4s(self):
        data = struct.pack("!4B", 1, 2, 3, 4) + struct.pack("!4B", 5, 6, 7, 8)
        assert _unpack_ipv4s(data) == ["1.2.3.4", "5.6.7.8"]

    def test_unpack_ipv4s_empty(self):
        assert _unpack_ipv4s(b"") == []

    def test_pack_ipv4s(self):
        result = _pack_ipv4s(["1.2.3.4", "5.6.7.8"])
        assert result == struct.pack("!4B", 1, 2, 3, 4) + struct.pack("!4B", 5, 6, 7, 8)

    def test_pack_ipv4s_empty(self):
        assert _pack_ipv4s([]) == b""

    def test_ipv4_roundtrip(self):
        ips = ["10.0.0.1", "192.168.1.1", "172.16.0.1"]
        assert _unpack_ipv4s(_pack_ipv4s(ips)) == ips

    def test_unpack_ipv6s(self):
        from ipaddress import ip_address

        data = ip_address("2001:db8::1").packed + ip_address("::1").packed
        assert _unpack_ipv6s(data) == ["2001:db8::1", "::1"]

    def test_unpack_ipv6s_empty(self):
        assert _unpack_ipv6s(b"") == []

    def test_pack_ipv6s(self):
        from ipaddress import ip_address

        ips = ["2001:db8::1", "::1"]
        expected = ip_address("2001:db8::1").packed + ip_address("::1").packed
        assert _pack_ipv6s(ips) == expected

    def test_ipv6_roundtrip(self):
        ips = ["2001:db8::1", "2606:4700::1", "::1"]
        assert _unpack_ipv6s(_pack_ipv6s(ips)) == ips


# =============================================================================
# Cloudflare IP detection tests
# =============================================================================


class TestIsCloudflareSync:
    """is_cloudflare_sync checks if an IP belongs to Cloudflare's networks."""

    def test_cf_ipv4(self):
        """104.16.0.1 is within CF_NETWORKS (104.16.0.0/13)."""
        assert is_cloudflare_sync("104.16.0.1") is True

    def test_cf_ipv4_boundary(self):
        """104.23.255.255 is within 104.16.0.0/13."""
        assert is_cloudflare_sync("104.23.255.255") is True

    def test_non_cf_ipv4(self):
        assert is_cloudflare_sync("8.8.8.8") is False

    def test_non_cf_ipv4_private(self):
        assert is_cloudflare_sync("10.0.0.1") is False

    def test_cf_ipv6(self):
        """2606:4700::1 is within CF_NETWORKS (2606:4700::/32)."""
        assert is_cloudflare_sync("2606:4700::1") is True

    def test_non_cf_ipv6(self):
        assert is_cloudflare_sync("2001:db8::1") is False

    def test_edge_case_first_network(self):
        """103.21.244.1 is within the first CF network entry."""
        assert is_cloudflare_sync("103.21.244.1") is True

    def test_edge_case_last_network(self):
        """198.41.128.1 is within the last CF network entry."""
        assert is_cloudflare_sync("198.41.128.1") is True


# =============================================================================
# should_bypass tests
# =============================================================================


def _make_record(domain: str, rr: list = None) -> DNSRecord:
    q = DNSRecord.question(domain)
    if rr:
        q.rr = rr
    return q


class TestShouldBypass:
    """should_bypass checks if a domain should skip CF IP patching."""

    def test_exact_match(self):
        record = _make_record("cloudflare.com")
        assert should_bypass(record) is True

    def test_subdomain_suffix_match(self):
        """Domains ending with '.pacloudflare.com' are bypassed."""
        record = _make_record("something.pacloudflare.com")
        assert should_bypass(record) is True

    def test_non_bypassed_domain(self):
        record = _make_record("example.com")
        assert should_bypass(record) is False

    def test_cf_internal_service(self):
        record = _make_record("speed.cloudflare.com")
        assert should_bypass(record) is True

    def test_letsencrypt(self):
        record = _make_record("prod.api.letsencrypt.org")
        assert should_bypass(record) is True

    def test_letsencrypt_wildcard_no_match(self):
        """api.letsencrypt.org is not in BYPASS_LIST."""
        record = _make_record("api.letsencrypt.org")
        assert should_bypass(record) is False

    def test_cname_to_bypass_domain(self):
        """Record with CNAME pointing to a bypass domain."""
        cname_rr = RR(
            "example.com",
            QTYPE.CNAME,
            rdata=dnslib.CNAME("cloudflare.com"),
        )
        record = _make_record("example.com", rr=[cname_rr])
        assert should_bypass(record) is True

    def test_cname_to_bypass_suffix(self):
        """CNAME to a domain ending with '.cdn.cloudflare.net'."""
        cname_rr = RR(
            "cdn.example.com",
            QTYPE.CNAME,
            rdata=dnslib.CNAME("assets.cdn.cloudflare.net"),
        )
        record = _make_record("cdn.example.com", rr=[cname_rr])
        assert should_bypass(record) is True

    def test_cname_to_normal_domain(self):
        """CNAME to a non-bypass domain should not bypass."""
        cname_rr = RR(
            "example.com",
            QTYPE.CNAME,
            rdata=dnslib.CNAME("other-cdn.example.com"),
        )
        record = _make_record("example.com", rr=[cname_rr])
        assert should_bypass(record) is False


# =============================================================================
# TtlCache tests
# =============================================================================


class TestTtlCache:
    """TtlCache is a time-aware cache with max_size and max_ttl."""

    def test_get_set(self):
        cache = TtlCache(max_size=10)
        cache.store("key", "value")
        assert cache.get("key") == "value"

    def test_get_missing(self):
        cache = TtlCache(max_size=10)
        assert cache.get("nonexistent") is None

    def test_get_missing_default(self):
        cache = TtlCache(max_size=10)
        assert cache.get("nonexistent", "default") == "default"

    def test_expire(self):
        """Item expires after its TTL."""
        fake_time = [100.0]

        def mock_timer():
            return fake_time[0]

        cache = TtlCache(max_size=10, max_ttl=600, timer=mock_timer)
        cache.store("a", "b", ttl=1)
        assert cache.get("a") == "b"
        fake_time[0] = 102.0  # 2 seconds later
        assert cache.get("a") is None

    def test_max_ttl_cap(self):
        """Item's TTL is capped by max_ttl."""
        fake_time = [100.0]

        def mock_timer():
            return fake_time[0]

        cache = TtlCache(max_size=10, max_ttl=5, timer=mock_timer)
        cache.store("a", "b", ttl=100)  # tries 100s but capped at 5
        assert cache.get("a") == "b"
        fake_time[0] = 106.0  # 6 seconds later
        assert cache.get("a") is None

    def test_max_size_eviction(self):
        """When max_size exceeded, oldest items are evicted."""
        fake_time = [100.0]

        def mock_timer():
            return fake_time[0]

        cache = TtlCache(max_size=3, max_ttl=600, timer=mock_timer)
        for i in range(10):
            fake_time[0] += 1  # each store is 1s apart
            cache.store(str(i), str(i))

        # Only the 3 most recent should survive
        survivors = [cache.get(str(i)) for i in range(10)]
        assert [v for v in survivors if v is not None] == ["7", "8", "9"]

    def test_default_ttl(self):
        """Without explicit ttl, max_ttl is used."""
        fake_time = [100.0]

        def mock_timer():
            return fake_time[0]

        cache = TtlCache(max_size=10, max_ttl=10, timer=mock_timer)
        cache.store("a", "b")  # no ttl specified
        assert cache.get("a") == "b"
        fake_time[0] = 111.0  # 11 seconds later
        assert cache.get("a") is None

    def test_dict_interface(self):
        cache = TtlCache(max_size=10)
        cache["key"] = "value"
        assert cache["key"] == "value"

    def test_dict_interface_missing(self):
        cache = TtlCache(max_size=10)
        with pytest.raises(KeyError):
            _ = cache["nonexistent"]

    def test_dict_del(self):
        cache = TtlCache(max_size=10)
        cache.store("key", "value")
        del cache["key"]
        assert cache.get("key") is None

    def test_del_nonexistent(self):
        """Deleting a nonexistent key should not raise."""
        cache = TtlCache(max_size=10)
        del cache["nonexistent"]  # should not raise

    def test_len(self):
        cache = TtlCache(max_size=10)
        assert len(cache) == 0
        cache.store("a", "b")
        assert len(cache) == 1

    def test_zero_max_size(self):
        """Cache with max_size=0 evicts everything immediately on store."""
        cache = TtlCache(max_size=0, max_ttl=600)
        cache.store("a", "b")
        # On store, len > max_size triggers expire which removes all
        assert cache.get("a") is None


# =============================================================================
# make_answer tests
# =============================================================================


class TestMakeAnswer:
    def test_basic_answer(self):
        record = DNSRecord.question("example.com")
        rr = RR("example.com", QTYPE.A, rdata=dnslib.A("1.2.3.4"), ttl=300)
        answer = make_answer(record, [rr])
        assert len(answer.rr) == 1
        assert str(answer.rr[0].rdata) == "1.2.3.4"
        assert answer.rr[0].ttl == 300

    def test_empty_answer(self):
        record = DNSRecord.question("example.com")
        answer = make_answer(record, [])
        assert answer.rr == []

    def test_multiple_rr(self):
        record = DNSRecord.question("example.com")
        rrs = [
            RR("example.com", QTYPE.A, rdata=dnslib.A("1.2.3.4"), ttl=300),
            RR("example.com", QTYPE.AAAA, rdata=dnslib.AAAA("::1"), ttl=300),
        ]
        answer = make_answer(record, rrs)
        assert len(answer.rr) == 2

    def test_response_is_reply(self):
        """Response should be a reply with QR bit set."""
        record = DNSRecord.question("example.com")
        rr = RR("example.com", QTYPE.A, rdata=dnslib.A("1.2.3.4"), ttl=300)
        answer = make_answer(record, [rr])
        assert answer.header.qr == 1  # QR bit = 1 means response


# =============================================================================
# patch_response tests
# =============================================================================


class _MockTimer:
    """Mock timer that returns a fixed time or advances on call."""

    def __init__(self, start=1000.0):
        self._time = start

    def __call__(self):
        return self._time

    def advance(self, seconds: float):
        self._time += seconds


def _build_dns_response(domain: str, qtype: str, rrs: list) -> DNSRecord:
    """Build a synthetic DNS response record.

    Mimics what you'd get back from a real upstream DNS server.
    """
    q = DNSRecord.question(domain, qtype)
    response = q.reply()
    for rr in rrs:
        response.add_answer(rr)
    return response


# Convenience A / AAAA RR factories
def a_rr(domain: str, ip: str, ttl: int = 300) -> RR:
    return RR(domain, QTYPE.A, rdata=dnslib.A(ip), ttl=ttl)


def aaaa_rr(domain: str, ip: str, ttl: int = 300) -> RR:
    return RR(domain, QTYPE.AAAA, rdata=dnslib.AAAA(ip), ttl=ttl)


def https_rr(domain: str, params: list, ttl: int = 300) -> RR:
    return RR(domain, QTYPE.HTTPS, rdata=HTTPS(0, ".", params), ttl=ttl)


class TestPatchResponse:
    """patch_response replaces CF IPs in DNS responses with ICN IPs.

    It depends on:
      - _get_icn_ips() - fetches current ICN IPs from namu.wiki
      - fetch_dns()    - fetches DNS records from upstream

    Both are mocked in these tests.
    """

    @pytest.mark.asyncio
    async def test_no_cf_ip_no_change(self):
        """Non-CF response should be returned unchanged."""
        record = _build_dns_response("example.com", "A", [
            a_rr("example.com", "1.2.3.4"),
        ])

        result = await patch_response(record)
        assert str(result.rr[0].rdata) == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_cf_a_record_patched(self):
        """A record with CF IP should have IP replaced with ICN IP."""
        record = _build_dns_response("example.com", "A", [
            a_rr("example.com", "104.16.0.1"),  # CF IP
            a_rr("example.com", "104.16.0.2"),  # CF IP
        ])

        fake_icn_v4 = ["203.0.113.1", "203.0.113.2"]
        fake_icn_v6 = ["2001:db8::1"]

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(fake_icn_v4, fake_icn_v6))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                a_rr("namu.wiki", "203.0.113.1", ttl=600),
                a_rr("namu.wiki", "203.0.113.2", ttl=600),
            ]
            result = await patch_response(record)

        # IPs should be replaced with fetched ICN IPs
        assert len(result.rr) == 2
        assert str(result.rr[0].rdata) == "203.0.113.1"
        assert str(result.rr[1].rdata) == "203.0.113.2"

    @pytest.mark.asyncio
    async def test_bypass_domain_no_change(self):
        """Bypassed domains should not be patched even with CF IPs."""
        record = _build_dns_response("cloudflare.com", "A", [
            a_rr("cloudflare.com", "104.16.0.1"),
        ])

        result = await patch_response(record)
        assert str(result.rr[0].rdata) == "104.16.0.1"

    @pytest.mark.asyncio
    async def test_cf_aaaa_record_patched(self):
        """AAAA record with CF IPv6 should be patched."""
        record = _build_dns_response("example.com", "AAAA", [
            aaaa_rr("example.com", "2606:4700::1"),  # CF IPv6
        ])

        fake_icn_v4 = ["203.0.113.1"]
        fake_icn_v6 = ["2001:db8::1"]

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(fake_icn_v4, fake_icn_v6))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                aaaa_rr("namu.wiki", "2001:db8::1", ttl=600),
            ]
            result = await patch_response(record)

        assert len(result.rr) == 1
        assert str(result.rr[0].rdata) == "2001:db8::1"

    @pytest.mark.asyncio
    async def test_non_cf_aaaa_unchanged(self):
        """AAAA record without CF IP should remain unchanged."""
        record = _build_dns_response("example.com", "AAAA", [
            aaaa_rr("example.com", "2001:db8::1"),
        ])

        result = await patch_response(record)
        assert str(result.rr[0].rdata) == "2001:db8::1"

    @pytest.mark.asyncio
    async def test_cf_https_ipv4_hint_patched(self):
        """HTTPS record with CF IPv4 hints should have hints replaced."""
        record = _build_dns_response("example.com", "HTTPS", [
            https_rr("example.com", [
                (4, _pack_ipv4s(["104.16.0.1", "104.16.0.2"])),  # CF IPs as ipv4hint
                (5, b"\x00\x01secret"),  # echconfig (passthrough)
            ]),
        ])

        fake_icn_v4 = ["203.0.113.10", "203.0.113.11"]
        fake_icn_v6 = ["2001:db8::1"]

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(fake_icn_v4, fake_icn_v6))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                a_rr("namu.wiki", "203.0.113.10", ttl=600),
            ]
            result = await patch_response(record)

        https_rr_result = result.rr[0]
        params = https_rr_result.rdata.params
        # ipv4hint (4) should be replaced with ICN IPs
        ipv4hint_val = dict(params)[4]
        assert _unpack_ipv4s(ipv4hint_val) == ["203.0.113.10", "203.0.113.11"]

        # echconfig (5) should be preserved
        assert dict(params)[5] == b"\x00\x01secret"

    @pytest.mark.asyncio
    async def test_cf_https_ipv6_hint_patched(self):
        """HTTPS record with CF IPv6 hints should have hints replaced."""
        record = _build_dns_response("example.com", "HTTPS", [
            https_rr("example.com", [
                (6, _pack_ipv6s(["2606:4700::1"])),  # CF IPv6
            ]),
        ])

        fake_icn_v4 = ["203.0.113.1"]
        fake_icn_v6 = ["2001:db8::10"]

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(fake_icn_v4, fake_icn_v6))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                aaaa_rr("namu.wiki", "2001:db8::10", ttl=600),
            ]
            result = await patch_response(record)

        https_rr_result = result.rr[0]
        ipv6hint_val = dict(https_rr_result.rdata.params)[6]
        assert _unpack_ipv6s(ipv6hint_val) == ["2001:db8::10"]

    @pytest.mark.asyncio
    async def test_https_no_cf_hints_unchanged(self):
        """HTTPS record without CF hints in params should not be modified."""
        record = _build_dns_response("example.com", "HTTPS", [
            https_rr("example.com", [
                (4, _pack_ipv4s(["1.2.3.4"])),  # non-CF IP
            ]),
        ])

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(["203.0.113.1"], ["2001:db8::1"]))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                a_rr("namu.wiki", "203.0.113.1", ttl=600),
            ]
            result = await patch_response(record)

        # IPs should remain unchanged since original hints are not CF
        ipv4hint_val = dict(result.rr[0].rdata.params)[4]
        assert _unpack_ipv4s(ipv4hint_val) == ["1.2.3.4"]

    @pytest.mark.asyncio
    async def test_non_cf_a_with_cf_https_still_patches_https(self):
        """A record might be non-CF but HTTPS could still have CF hints."""
        record = _build_dns_response("example.com", "A", [
            a_rr("example.com", "1.2.3.4"),  # non-CF A record
            https_rr("example.com", [
                (4, _pack_ipv4s(["104.16.0.1"])),  # CF hint in HTTPS
            ]),
        ])

        fake_icn_v4 = ["203.0.113.10"]
        fake_icn_v6 = ["2001:db8::1"]

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(fake_icn_v4, fake_icn_v6))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                a_rr("namu.wiki", "203.0.113.1", ttl=600),
            ]
            result = await patch_response(record)

        # A record stays unchanged
        assert str(result.rr[0].rdata) == "1.2.3.4"
        # HTTPS hint gets patched
        https_params = dict(result.rr[1].rdata.params)
        assert _unpack_ipv4s(https_params[4]) == ["203.0.113.10"]

    @pytest.mark.asyncio
    async def test_skip_non_cf_https_record(self):
        """HTTPS record with no CF network hints should be skipped entirely."""
        record = _build_dns_response("example.com", "HTTPS", [
            https_rr("example.com", [
                (4, _pack_ipv4s(["1.2.3.4"])),  # non-CF
            ]),
        ])

        # Even with ICN IPs available, no fetch_dns should be called
        # since the record has no CF IPs
        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips") as mock_icn,
            patch("cf_patch_doh.dns_utils.fetch_dns") as mock_fetch,
        ):
            result = await patch_response(record)

        mock_icn.assert_not_called()
        mock_fetch.assert_not_called()
        assert result is record  # returned as-is

    @pytest.mark.asyncio
    async def test_only_https_svcb_rr_checked(self):
        """HTTPS params with CF hints should be patched for ICN IPs."""
        record = DNSRecord.question("example.com", "A")
        response = record.reply()
        response.add_answer(https_rr("example.com", [
            (4, _pack_ipv4s(["104.16.0.1"])),
        ]))

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(["203.0.113.1"], []))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                a_rr("namu.wiki", "203.0.113.1", ttl=600),
            ]
            result = await patch_response(response)

        params = dict(result.rr[0].rdata.params)
        assert _unpack_ipv4s(params[4]) == ["203.0.113.1"]

    @pytest.mark.asyncio
    async def test_ttl_capped_at_600_on_patched_a(self):
        """Patched A records should have ttl=max(answer.ttl, 600)."""
        record = _build_dns_response("example.com", "A", [
            a_rr("example.com", "104.16.0.1", ttl=30),
        ])

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(["203.0.113.1"], []))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                a_rr("namu.wiki", "203.0.113.1", ttl=120),
            ]
            result = await patch_response(record)

        assert result.rr[0].ttl == 600  # max(120, 600)

    @pytest.mark.asyncio
    async def test_ttl_capped_at_600_large(self):
        """Patched records preserve high TTL."""
        record = _build_dns_response("example.com", "A", [
            a_rr("example.com", "104.16.0.1", ttl=30),
        ])

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(["203.0.113.1"], []))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                a_rr("namu.wiki", "203.0.113.1", ttl=3600),
            ]
            result = await patch_response(record)

        assert result.rr[0].ttl == 3600  # max(3600, 600)

    @pytest.mark.asyncio
    async def test_https_icn_v4_empty_no_replacement(self):
        """When no ICN IPv4 available, IPv4 hint should remain unchanged."""
        record = _build_dns_response("example.com", "HTTPS", [
            https_rr("example.com", [
                (4, _pack_ipv4s(["104.16.0.1"])),
            ]),
        ])

        fake_icn_v4 = []  # no IPv4 ICN IPs
        fake_icn_v6 = ["2001:db8::1"]

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips", AsyncMock(return_value=(fake_icn_v4, fake_icn_v6))),
            patch("cf_patch_doh.dns_utils.fetch_dns", new_callable=AsyncMock) as mock_fetch,
        ):
            mock_fetch.return_value = [
                aaaa_rr("namu.wiki", "2001:db8::1", ttl=600),
            ]
            result = await patch_response(record)

        params = dict(result.rr[0].rdata.params)
        # IPv4 hint should be unchanged since we have no ICN v4 IPs
        assert _unpack_ipv4s(params[4]) == ["104.16.0.1"]

    @pytest.mark.asyncio
    async def test_https_hints_not_cf_should_not_trigger_fetch(self):
        """If HTTPS hints are not CF IPs, no fetch or ICN lookup should happen."""
        record = _build_dns_response("example.com", "HTTPS", [
            https_rr("example.com", [
                (4, _pack_ipv4s(["1.2.3.4"])),  # non-CF
            ]),
        ])

        with (
            patch("cf_patch_doh.dns_utils._get_icn_ips") as mock_icn,
            patch("cf_patch_doh.dns_utils.fetch_dns") as mock_fetch,
        ):
            result = await patch_response(record)

        mock_icn.assert_not_called()
        mock_fetch.assert_not_called()
        assert result is record


# =============================================================================
# Cache integration tests (fetch_dns / get_cache / store_cache)
# =============================================================================


class TestCacheIntegration:
    """Tests for the global CACHED_QUERY integration with fetch_dns."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear the global cache before each test."""
        from cf_patch_doh.dns_utils import CACHED_QUERY

        CACHED_QUERY.storage.clear()
        yield

    @pytest.mark.asyncio
    async def test_fetch_dns_caches_result(self):
        """fetch_dns should cache and return cached on second call."""
        fake_response = DNSRecord.question("example.com").reply()
        fake_response.add_answer(a_rr("example.com", "1.2.3.4", ttl=300))

        with patch(
            "cf_patch_doh.dns_utils.httpx.AsyncClient",
        ) as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=MockResponse(bytes(fake_response.pack())),
            )

            from cf_patch_doh.dns_utils import fetch_dns

            result1 = await fetch_dns("example.com", "A", "https://upstream.test/dns-query")
            assert len(result1) == 1
            assert str(result1[0].rdata) == "1.2.3.4"

            # Second call should use cache, not hit the network
            mock_client.return_value.__aenter__.return_value.post.reset_mock()
            result2 = await fetch_dns("example.com", "A", "https://upstream.test/dns-query")
            assert len(result2) == 1
            mock_client.return_value.__aenter__.return_value.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_fetch_dns_different_upstream_different_cache(self):
        """Different upstreams should have separate cache entries."""
        fake_response1 = DNSRecord.question("example.com").reply()
        fake_response1.add_answer(a_rr("example.com", "1.2.3.4", ttl=300))
        fake_response2 = DNSRecord.question("example.com").reply()
        fake_response2.add_answer(a_rr("example.com", "5.6.7.8", ttl=300))

        from cf_patch_doh.dns_utils import fetch_dns

        with patch(
            "cf_patch_doh.dns_utils.httpx.AsyncClient",
        ) as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=MockResponse(bytes(fake_response1.pack())),
            )
            r1 = await fetch_dns("example.com", "A", "https://upstream1.test/dns-query")
            assert str(r1[0].rdata) == "1.2.3.4"

        with patch(
            "cf_patch_doh.dns_utils.httpx.AsyncClient",
        ) as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=MockResponse(bytes(fake_response2.pack())),
            )
            r2 = await fetch_dns("example.com", "A", "https://upstream2.test/dns-query")
            assert str(r2[0].rdata) == "5.6.7.8"


class MockResponse:
    """Minimal mock for httpx.Response used in tests."""

    def __init__(self, content: bytes):
        self.content = content
