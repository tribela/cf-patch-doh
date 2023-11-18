import json
from datetime import datetime, timedelta

import httpx

from dnslib import DNSRecord, QTYPE, RR


CACHED_QUERY = {}  # (Domain, Type, upstream): (expire_timestamp, RRs)
CACHED_IPS = {}  # IP: (expire_timestamp, is_cloudflare)

BYPASS_LIST = {
    'prod.api.letsencrypt.org',
    'cloudflare.com',
    'speed.cloudflare.com',
    'shops.myshopify.com',
}

DEFAULT_UPSTREAM = 'https://1.1.1.1/dns-query'


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
    now = datetime.now()
    if key not in CACHED_QUERY:
        return
    expire_timestamp, answer = CACHED_QUERY.get(key)

    if now > expire_timestamp:
        # del CACHED_QUERY[key]

        # delete other expired keys
        CACHED_QUERY = {
            key: (expire, answer, upstream)
            for key, (expire, answer) in CACHED_QUERY.items()
            if now < expire
        }
        return

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
        now = datetime.now()
        expire, result = cached_values
        if now < expire:
            return result
        else:
            # del CACHED_IPS[ip]

            # Cleanup expired keys
            CACHED_IPS = {
                ip: (expire, result)
                for ip, (expire, result) in CACHED_IPS.items()
                if now < expire
            }
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(
                'https://ifconfig.co/json',
                params={
                    'ip': ip,
                },
                timeout=1,
            )

            data = res.json()
            result = data.get('asn_org') == 'CLOUDFLARENET' and "hostname" not in data
            CACHED_IPS[ip] = (datetime.now() + timedelta(minutes=60), result)
            return result
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        print(f"Error while checking {ip}: {e}")
        CACHED_IPS[ip] = (datetime.now() + timedelta(minutes=1), False)
        return False
