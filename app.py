import base64

import dns_utils

from dnslib import DNSRecord, QTYPE
from fastapi import FastAPI, Request, Response


app = FastAPI()


@app.get('/health')
async def health():
    return 'OK'


@app.get('/dns-query')
@app.post("/dns-query")
@app.get('/dns-query/{upstream:path}')
@app.post('/dns-query/{upstream:path}')
async def dns_query(request: Request, upstream: str | None = None):
    if request.method == 'GET':
        try:
            query_b64 = request.query_params.get('dns')
            query_b64 += '=='  # Deal with padding
            query = base64.b64decode(query_b64)
        except Exception as e:
            return Response(status_code=400)
    elif request.method == 'POST':
        if request.headers.get('accept') != 'application/dns-message' and \
                request.headers.get('content-type') != 'application/dns-message':
            return Response(status_code=406)
        query = await request.body()

    answer = await get_record(query, upstream)
    return Response(bytes(answer.pack()), media_type='application/dns-message')


async def get_record(query, upstream: str):
    record = DNSRecord.parse(query)
    domain = record.q.qname.idna().rstrip('.')
    upstream = upstream or dns_utils.DEFAULT_UPSTREAM
    type_ = QTYPE[record.q.qtype]

    if rrs := dns_utils.get_cache(domain, type_, upstream):
        answer = dns_utils.make_answer(record, rrs)
        return answer

    answer = await dns_utils.fetch_dns(domain, type_, upstream)
    answer = dns_utils.make_answer(record, answer)
    await dns_utils.patch_response(answer)

    dns_utils.store_cache(domain, type_, upstream, answer.rr)
    return answer
