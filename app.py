from datetime import datetime, timedelta

import httpx

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

app = FastAPI()

TYPE_A = 1
TYPE_AAAA = 28


CACHED_QUERY = {}  # (Domain, Type): (expire_timestamp, answer)


def store_cache(domain: str, type_: str, answer):
    key = (domain, type_)
    expire_timestamp = datetime.now() + timedelta(seconds=answer['Answer'][0]['TTL'])

    CACHED_QUERY[key] = (expire_timestamp, answer)


def get_cache(domain: str, type_: str):
    key = (domain, type_)
    now = datetime.now()
    if key not in CACHED_QUERY:
        return None
    expire_timestamp, answer = CACHED_QUERY.get(key)

    if now > expire_timestamp:
        # TODO: Delete other expired keys
        del CACHED_QUERY[key]
        return None

    return answer


async def fetch_dns(domain: str, type_: str):
    if answer := get_cache(domain, type_):
        return answer

    async with httpx.AsyncClient() as client:
        res = await client.get(
            'https://1.1.1.1/dns-query',
            headers={
                'Accept': 'application/dns-json',
            },
            params={
                'name': domain,
                'type': type_,
            }
        )

        answer = res.json()
        store_cache(domain, type_, answer)
        return answer


async def is_cloudflare(ip: str) -> bool:
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get('https://ifconfig.co/json', params={
                'ip': ip,
            })

        data = res.json()
        return data['asn_org'] == 'CLOUDFLARENET'
    except Exception as e:
        print(f'Error while fetching {ip}: {e}')
        return False


async def patch_response(json, type_: str):
    domain = json['Question'][0]['name']
    that_response = await fetch_dns('namu.wiki', type_)
    answer = [
        answer
        for answer in json['Answer']
        if answer['type'] not in (TYPE_A, TYPE_AAAA)
    ] + [
        {**answer, 'name': domain}
        for answer in that_response['Answer']
        if answer['type'] in (TYPE_A, TYPE_AAAA)
    ]

    json['Answer'] = answer
    return json


@app.get("/dns-query")
async def dns_query(request: Request):
    domain = request.query_params.get('name')
    type_ = request.query_params.get('type', 'A')

    if answer := get_cache(domain, type_):
        return JSONResponse(answer)

    async with httpx.AsyncClient() as client:
        res = await client.get(
            f'https://1.1.1.1/dns-query?{request.query_params}',
            headers={
                key: val
                for key, val in request.headers.items()
                if key not in ['host']
            }
        )

    try:
        json = res.json()
        try:
            ip1 = next(
                answer['data']
                for answer in json['Answer']
                if answer['type'] in (TYPE_A, TYPE_AAAA)  # A, AAAA
            )
        except StopIteration:
            pass
        else:
            if await is_cloudflare(ip1):
                json = await patch_response(json, type_)

        store_cache(domain, type_, json)

        return JSONResponse(
            json,
            headers={
                key: val
                for key, val in res.headers.items()
                if key not in ['Content-Length', 'Content-Encoding']
            },
            status_code=res.status_code)

    except Exception as e:
        print(f'Error while fetching {domain}: {e}')
        return Response(
            res.text,
            headers=res.headers,
            status_code=res.status_code)
