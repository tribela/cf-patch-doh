import dns_utils
import httpx

from dnslib import DNSRecord, QTYPE
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


app = FastAPI()


@app.post("/dns-query")
@app.get("/dns-query")
async def dns_query(request: Request):
    if request.method == 'GET' and request.headers.get('accept') == 'application/dns-json':
        response_type = 'dns-json'
        domain = request.query_params.get('name')
        type_ = request.query_params.get('type', 'A')
    else:
        response_type = 'dns-wireformat'
        # Parse dns wireformat
        body = await request.body()
        dns_record = DNSRecord.parse(body)
        domain = dns_record.q.get_qname().idna()
        type_ = QTYPE[dns_record.q.qtype]
        tid = dns_record.header.id

    if answer := dns_utils.get_cache(domain, type_):
        if response_type == 'dns-json':
            return JSONResponse(answer)
        else:
            return Response(
                dns_utils.json_to_wireformat(dns_record, answer),
                headers={
                    'Content-Type': 'dns-message',
                }
            )

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

    try:
        answer = res.json()
        try:
            ip1 = next(
                answer['data']
                for answer in answer['Answer']
                if answer['type'] in (QTYPE.A, QTYPE.AAAA)
            )
        except StopIteration:
            pass
        else:
            if await dns_utils.is_cloudflare(ip1):
                answer = await dns_utils.patch_response(answer, type_)

        print(answer)
        dns_utils.store_cache(domain, type_, answer)

        if response_type == 'dns-json':
            return JSONResponse(
                answer,
                headers={
                    'Content-Type': 'application/dns-json',
                },
                status_code=res.status_code)
        else:
            return Response(
                content=dns_utils.json_to_wireformat(dns_record, answer),
                headers={
                    'Content-Type': 'dns-message',
                }
            )

    except ZeroDivisionError as e:
        print(f'Error while fetching {domain}: {e}')
        return Response(
            res.text,
            headers=res.headers,
            status_code=res.status_code)
