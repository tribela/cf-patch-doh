import json
from datetime import datetime, timedelta

import httpx

from dnslib import DNSRecord, QTYPE, RR


CACHED_QUERY = {}  # (Domain, Type): (expire_timestamp, RRs)
CACHED_IPS = {}  # IP: (expire_timestamp, is_cloudflare)


def store_cache(domain: str, type_: str, answer: list[RR]):
    key = (domain, type_)
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


def get_cache(domain: str, type_: str) -> list[RR] | None:
    key = (domain, type_)
    now = datetime.now()
    if key not in CACHED_QUERY:
        return
    expire_timestamp, answer = CACHED_QUERY.get(key)

    if now > expire_timestamp:
        # TODO: delete other expired keys
        del CACHED_QUERY[key]
        return

    return answer


def make_answer(record: DNSRecord, answer: list[RR]):
    response = record.reply()
    for rr in answer:
        response.add_answer(rr)

    return response


async def patch_response(record: DNSRecord):
    domain = record.q.qname.idna().rstrip('.')
    type_ = QTYPE[record.q.qtype]

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
        that_response = await fetch_dns('namu.wiki', type_)
        for answer in that_response:
            rr = RR(
                rname=domain,
                rtype=answer.rtype,
                rdata=answer.rdata,
                ttl=max(answer.ttl, 600),
            )
            record.add_answer(rr)


async def fetch_dns(domain: str, type_: str) -> list[RR]:
    if answer := get_cache(domain, type_):
        return answer

    request = DNSRecord.question(domain, type_)
    async with httpx.AsyncClient() as client:
        res = await client.post(
            'https://1.1.1.1/dns-query',
            headers={
                'Content-Type': 'application/dns-message',
            },
            data=bytes(request.pack()),
            timeout=5,
        )
        res = res.content

    answer = DNSRecord.parse(res)
    store_cache(domain, type_, answer.rr)
    return answer.rr


async def is_cloudflare(ip: str) -> bool:
    if cached_values := CACHED_IPS.get(ip):
        expire, result = cached_values
        if datetime.now() < expire:
            return result
        else:
            del CACHED_IPS[ip]
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
            result = data.get('asn_org') == 'CLOUDFLARENET'
            CACHED_IPS[ip] = (datetime.now() + timedelta(minutes=60), result)
            return result
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        print(f"Error while checking {ip}: {e}")
        CACHED_IPS[ip] = (datetime.now() + timedelta(minutes=1), False)
        return False
