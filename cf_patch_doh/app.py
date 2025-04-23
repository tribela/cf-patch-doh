import base64

from dnslib import DNSRecord, QTYPE
from fastapi import FastAPI, Request, Response
from starlette.responses import RedirectResponse

from . import dns_utils

app = FastAPI(
    docs_url=None,
    redoc_url=None,
)


@app.get('/')
async def root_page():
    return RedirectResponse('https://github.com/tribela/cf-patch-doh', status_code=303)


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
            # Deal with padding
            padding_needed = 4 - (len(query_b64) % 4)
            query_b64 += '=' * padding_needed
            query = base64.b64decode(query_b64)
        except Exception:
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
