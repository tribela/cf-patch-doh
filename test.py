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

for domain in domains:
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
