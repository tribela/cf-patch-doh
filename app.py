import dns_utils

from dnslib import DNSRecord, QTYPE
from fastapi import FastAPI, Request, Response


app = FastAPI()


@app.get("/health")
async def health():
    return 'OK'


@app.post("/dns-query/{upstream:path}")
@app.post("/dns-query")
async def dns_query(request: Request, upstream: str | None = None):
    if request.headers.get('accept') != 'application/dns-message' and \
            request.headers.get('content-type') != 'application/dns-message':
        return Response(status_code=406)

    record = DNSRecord.parse(await request.body())
    domain = record.q.qname.idna().rstrip('.')
    type_ = QTYPE[record.q.qtype]

    upstream = upstream or request.query_params.get('upstream') or dns_utils.DEFAULT_UPSTREAM

    if rrs := dns_utils.get_cache(domain, type_, upstream):
        answer = dns_utils.make_answer(record, rrs)
        return Response(bytes(answer.pack()), media_type='application/dns-message')

    answer = await dns_utils.fetch_dns(domain, type_, upstream)
    answer = dns_utils.make_answer(record, answer)
    await dns_utils.patch_response(answer)

    dns_utils.store_cache(domain, type_, upstream, answer.rr)
    return Response(bytes(answer.pack()), media_type='application/dns-message')
