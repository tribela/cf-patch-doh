import json
from datetime import datetime, timedelta
from typing import Callable

import httpx
import asyncwhois

from dnslib import DNSRecord, QTYPE, RR


MAX_CACHE_SIZE = 1000

BYPASS_LIST = {
    'prod.api.letsencrypt.org',
    'cloudflare.com',
    'speed.cloudflare.com',
    'shops.myshopify.com',
}

DEFAULT_UPSTREAM = 'https://1.1.1.1/dns-query'


class TtlCache(dict):
    def __init__(self, max_size: int, key: Callable):
        self.max_size = max_size
        self.key = key
        super().__init__()

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if len(self) >= self.max_size:
            self.expire()

    def __getitem__(self, key):
        self.expire()
        value = super().__getitem__(key)
        return value

    def expire(self):
        now = datetime.now()
        elems = [
            (key, value, self.key(value))
            for key, value in super().items()
        ]
        elems.sort(key=lambda x: x[2])

        keys_to_delete = [
            key
            for index, (key, _value, expire) in enumerate(elems)
            if now >= expire or index >= self.max_size
        ]

        for key in keys_to_delete:
            del self[key]


# (Domain, Type, upstream): (expire_timestamp, RRs)
CACHED_QUERY = TtlCache(
    max_size=MAX_CACHE_SIZE,
    key=lambda value: value[0],
)
# IP: (expire_timestamp, is_cloudflare)
CACHED_IPS = TtlCache(
    max_size=MAX_CACHE_SIZE,
    key=lambda value: value[0],
)


def store_cache(domain: str, type_: str, upstream: str, answer: list[RR]):
    key = (domain, type_, upstream)
    try:
        ttl = next(
            a.ttl
            for a in answer
            if a.rtype in (QTYPE.A, QTYPE.AAAA))
    except StopIteration:
        ttl = 300
    expire_timestamp = datetime.now() + timedelta(seconds=ttl)

    global CACHED_QUERY
    CACHED_QUERY[key] = (expire_timestamp, answer)


def get_cache(domain: str, type_: str, upstream: str | None) -> list[RR] | None:
    global CACHED_QUERY

    if upstream is None:
        upstream = DEFAULT_UPSTREAM

    key = (domain, type_, upstream)
    if result := CACHED_QUERY.get(key):
        _expire_timestamp, answer = result
        return answer


def make_answer(record: DNSRecord, answer: list[RR]):
    response = record.reply()
    for rr in answer:
        response.add_answer(rr)

    return response


async def patch_response(record: DNSRecord):
    query_domain = record.q.qname.idna().rstrip('.')
    type_ = QTYPE[record.q.qtype]

    if query_domain in BYPASS_LIST:
        return record

    for rr in record.rr:
        if rr.rtype in (QTYPE.CNAME, QTYPE.NS):
            domain = str(rr.rdata).rstrip('.')
            if domain in BYPASS_LIST:
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
    global CACHED_IPS
    if cached_values := CACHED_IPS.get(ip):
        _expire, result = cached_values
        return result
    try:
        _rawstr, whois_dict = await asyncwhois.aio_whois(ip)
        result = whois_dict['net_name'] == 'CLOUDFLARENET'
        CACHED_IPS[ip] = (datetime.now() + timedelta(minutes=60), result)
        return result
    except (asyncwhois.errors.GeneralError) as e:
        print(f"Error while checking {ip}: {e}")
        CACHED_IPS[ip] = (datetime.now() + timedelta(minutes=1), False)
        return False
