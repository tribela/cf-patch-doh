import json
import time
from datetime import timedelta
from typing import Callable, Generic, TypeVar

import httpx
import asyncwhois

from dnslib import DNSRecord, QTYPE, RR


MAX_CACHE_SIZE = 1000

BYPASS_LIST = {
    'prod.api.letsencrypt.org',
    'cloudflare.com',
    'speed.cloudflare.com',
    'shops.myshopify.com',
    '.cdn.cloudflare.net',
    '.pacloudflare.com',
}

DEFAULT_UPSTREAM = 'https://1.1.1.1/dns-query'

T = TypeVar('T')
V = TypeVar('V')


class TtlCache(Generic[T, V]):
    def __init__(self, max_size: int, max_ttl: int | float = 600, timer: Callable = time.monotonic):
        self.max_size = max_size
        self.max_ttl = max_ttl
        self.timer = timer
        self.storage = dict()

    def __setitem__(self, key: T, value: V):
        expire = self.timer() + self.max_ttl
        tup = (expire, value)
        self.storage.__setitem__(key, tup)
        if len(self.storage) >= self.max_size:
            self.expire()

    def __getitem__(self, key: T) -> V:
        (expire, value) = self.storage.__getitem__(key)
        if expire < self.timer():
            del self[key]
            raise KeyError(key)
        return value

    def __delitem__(self, key: T):
        try:
            del self.storage[key]
        except KeyError:
            pass

    def __len__(self) -> int:
        return len(self.storage)

    def get(self, key: T, default=None) -> V | None:
        try:
            return self[key]
        except KeyError:
            return default

    def store(self, key: T, value: V, ttl: int | float | None = None):
        if ttl is None:
            ttl = self.max_ttl
        ttl = min(ttl, self.max_ttl)

        expire = self.timer() + ttl
        tup = (expire, value)
        self.storage.__setitem__(key, tup)

    def expire(self):
        now = self.timer()
        elems = [
            (expire, key, value)
            for key, (expire, value) in self.storage.items()
        ]
        elems.sort(key=lambda x: x[0])

        keys_to_delete = [
            key
            for index, (expire, key, _value) in enumerate(elems)
            if now >= expire or index >= self.max_size
        ]

        for key in keys_to_delete:
            del self[key]


# (Domain, Type, upstream): RRs
CACHED_QUERY: TtlCache[tuple[str, str, str], list] = TtlCache(max_size=MAX_CACHE_SIZE)
# IP: is_cloudflare
CACHED_IPS: TtlCache[str, bool] = TtlCache(max_size=MAX_CACHE_SIZE)


def store_cache(domain: str, type_: str, upstream: str, answer: list[RR]):
    key = (domain, type_, upstream)
    try:
        ttl = next(
            a.ttl
            for a in answer
            if a.rtype in (QTYPE.A, QTYPE.AAAA))
    except StopIteration:
        ttl = 300

    CACHED_QUERY.store(key, answer, ttl=ttl)


def get_cache(domain: str, type_: str, upstream: str | None) -> list[RR] | None:
    if upstream is None:
        upstream = DEFAULT_UPSTREAM

    key = (domain, type_, upstream)
    return CACHED_QUERY.get(key)


def make_answer(record: DNSRecord, answer: list[RR]):
    response = record.reply()
    for rr in answer:
        response.add_answer(rr)

    return response


def should_bypass(record: DNSRecord):
    query_domain = record.q.qname.idna().rstrip('.')
    if any(
            query_domain.endswith(bypass) if bypass[0] == '.' else query_domain == bypass
            for bypass in BYPASS_LIST):
        return True

    for rr in record.rr:
        if rr.rtype in (QTYPE.CNAME, QTYPE.NS):
            domain = str(rr.rdata).rstrip('.')
            if any(
                    domain.endswith(bypass) if bypass[0] == '.' else domain == bypass
                    for bypass in BYPASS_LIST):
                return True

    return False


async def patch_response(record: DNSRecord):
    query_domain = record.q.qname.idna().rstrip('.')
    type_ = QTYPE[record.q.qtype]

    if should_bypass(record):
        return record

    try:
        first_ip = next(
            str(rr.rdata)
            for rr in record.rr
            if rr.rtype in (QTYPE.A, QTYPE.AAAA)
        )
        if await is_cloudflare(first_ip) is False:
            return record
    except StopIteration:
        return record
    else:
        record.rr = []
        that_response = await fetch_dns('namu.wiki', type_, DEFAULT_UPSTREAM)
        for answer in that_response:
            rr = RR(
                rname=query_domain,
                rtype=answer.rtype,
                rdata=answer.rdata,
                ttl=max(answer.ttl, 600),
            )
            record.add_answer(rr)
        return record


async def fetch_dns(domain: str, type_: str, upstream: str | None = None) -> list[RR]:
    if upstream is None:
        upstream = DEFAULT_UPSTREAM

    if answer := get_cache(domain, type_, upstream):
        return answer

    request = DNSRecord.question(domain, type_)
    async with httpx.AsyncClient() as client:
        res = await client.post(
            upstream,
            headers={
                'Content-Type': 'application/dns-message',
            },
            data=bytes(request.pack()),
            timeout=5,
        )
        res = res.content

    answer = DNSRecord.parse(res)
    store_cache(domain, type_, upstream, answer.rr)
    return answer.rr


async def is_cloudflare(ip: str) -> bool:
    if result := CACHED_IPS.get(ip):
        return result
    try:
        _rawstr, whois_dict = await asyncwhois.aio_whois(ip)
        result = whois_dict.get('net_name') == 'CLOUDFLARENET'
        ttl = timedelta(hours=1).total_seconds()
        CACHED_IPS.store(ip, result, ttl=ttl)
        return result
    except (asyncwhois.errors.GeneralError) as e:
        print(f"Error while checking {ip}: {e}")
        CACHED_IPS.store(ip, False, ttl=60)
        return False
