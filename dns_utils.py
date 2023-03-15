from datetime import datetime, timedelta

import httpx

from dnslib import DNSQuestion, DNSRecord, QTYPE, RD, RR

CACHED_QUERY = {}  # (Domain, Type): (expire_timestamp, answer)


def store_cache(domain: str, type_: str, answer: dict):
    key = (domain, type_)
    expire_timestamp = datetime.now() + timedelta(seconds=answer['Answer'][0]['TTL'])

    CACHED_QUERY[key] = (expire_timestamp, answer)


def get_cache(domain: str, type_: str) -> dict:
    key = (domain, type_)
    now = datetime.now()
    if key not in CACHED_QUERY:
        return None
    expire_timestamp, answer = CACHED_QUERY.get(key)

    if now > expire_timestamp:
        # TODO: delete other expired keys
        del CACHED_QUERY[key]
        return None

    return answer


def wireformat_to_json(wireformat: bytes) -> dict:
    # Convert wireformat into DNS Over HTTPS json
    dns_record = DNSRecord.parse(wireformat)
    is_request = dns_record.header.qr == 0

    if is_request:
        raise ValueError("We don't support request yet")

    return {
        'Questions': [
            {
                'Name': str(q.qname),
                'Type': QTYPE[q.qtype],
            }
            for q in dns_record.questions
        ],
        'Answers': [
            {
                'Name': str(a.rname),
                'Type': a.rtype,
                'TTL': a.ttl,
                'Data': str(a.rdata),
            }
            for a in dns_record.rr
        ],
        'TC': dns_record.header.flags.TC,
        'RD': dns_record.header.flags.RD,
        'RA': dns_record.header.flags.RA,
        'AD': dns_record.header.flags.AD,
        'CD': dns_record.header.flags.CD,
        'Status': dns_record.header.flags.RCODE,
    }


def json_to_wireformat(json: dict, transaction_id=0) -> bytes:
    # Convert DOH json response into wireformat

    dns_record = DNSRecord()
    dns_record.header.qr = 1
    dns_record.header.tc = json['TC']
    dns_record.header.rd = json['RD']
    dns_record.header.ra = json['RA']
    dns_record.header.ad = json['AD']
    dns_record.header.cd = json['CD']
    dns_record.header.rcode = json['Status']
    dns_record.header.id = transaction_id

    for question in json['Question']:
        dns_record.add_question(
            DNSQuestion(question['name'], question['type'])
        )

    for answer in json['Answer']:
        dns_record.add_answer(
            RR(
                answer['name'],
                answer['type'],
                rdata=RD(answer['data'].encode('latin-1')),
                ttl=answer['TTL'],
            )
        )

    return bytes(dns_record.pack())


async def patch_response(json: dict, type_: str):
    domain = json['Question'][0]['name']
    that_response = await fetch_dns('namu.wiki', type_)
    answer = [
        answer
        for answer in json['Answer']
        if answer['type'] not in (QTYPE.A, QTYPE.AAAA)
    ] + [
        {**answer, 'name': domain}
        for answer in that_response['Answer']
        if answer['type'] in (QTYPE.A, QTYPE.AAAA)
    ]
    json['Answer'] = answer


async def fetch_dns(domain: str, type_: str) -> dict:
    if answer := get_cache(domain, type_):
        return answer

    async with httpx.AsyncClient() as client:
        res = await client.get(
            'https://1.1.1.1/dns-query',
            params={
                'name': domain,
                'type': type_,
            },
            headers={
                'accept': 'application/dns-json',
            },
        )

        answer = res.json()
        store_cache(domain, type_, answer)
        return answer


async def is_cloudflare(ip: str) -> bool:
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(
                'https://ifconfig.co/json',
                params={
                    'ip': ip,
                })

            data = res.json()
            return data['asn_org'] == 'CLOUDFLARENET'
    except httpx.HTTPError as e:
        print(f"Error while checking {ip}: {e}")
        return False
