#!/usr/bin/env python3
import os

import dnslib
import httpx

domains = [
    'qdon.space',
    'beta.qdon.space',
    'blog.qdon.space',
    'bucket.qdon.space',
    'google.com',
    'namu.wiki',
]

server = os.getenv('DOH_SERVER', 'http://localhost:8000/dns-query')


def test_normal(domain):
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


def test_upstream_param(domain):
    q = dnslib.DNSRecord.question(domain)

    body = bytes(q.pack())

    res = httpx.post(
        server,
        headers={
            "Content-Type": "application/dns-message",
        },
        data=body,
        params={
            'upstream': 'https://1.0.0.1/dns-query',
        },
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
    test_normal(domain)
    test_upstream_param(domain)
    test_upstream_path(domain)
    print()
