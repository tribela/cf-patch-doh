#!/usr/bin/env python3
import base64
import os

import dnslib
import httpx

domains = [
    'qdon.space',
    'google.com',
    'namu.wiki',
    'kr1.chat.si.riotgames.com',
]

server = os.getenv('DOH_SERVER', 'http://localhost:8000/dns-query')


def test_post(domain):
    q = dnslib.DNSRecord.question(domain)

    body = bytes(q.pack())

    res = httpx.post(
        server,
        headers={
            "Content-Type": "application/dns-message",
        },
        data=body,
        timeout=5,
    )

    resp = dnslib.DNSRecord.parse(res.content)
    print(resp)
    print(res.elapsed.total_seconds())


def test_get(domain):
    q = dnslib.DNSRecord.question(domain)

    params = {
        'dns': base64.b64encode(q.pack()).decode()
    }

    res = httpx.get(
        server,
        headers={
            "Content-Type": "application/dns-message",
        },
        params=params,
        timeout=5,
    )

    resp = dnslib.DNSRecord.parse(res.content)
    print(resp)
    print(res.elapsed.total_seconds())


def test_upstream_path(domain):
    q = dnslib.DNSRecord.question(domain)

    body = bytes(q.pack())

    upstream_encoded = 'https%3A%2F%2F1.0.0.1%2Fdns-query'

    res = httpx.post(
        f'{server}/{upstream_encoded}',
        headers={
            "Content-Type": "application/dns-message",
        },
        data=body,
    )

    resp = dnslib.DNSRecord.parse(res.content)
    print(resp)
    print(res.elapsed.total_seconds())


for domain in domains * 3:
    print(domain)
    test_post(domain)
    test_get(domain)
    test_upstream_path(domain)
    print()
