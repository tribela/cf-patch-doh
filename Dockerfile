FROM python:alpine

WORKDIR /app
ENV PATH="/app/.venv/bin:$PATH"

COPY . ./
COPY --from=ghcr.io/astral-sh/uv /uv /uvx /bin/
RUN uv sync --frozen

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=2 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["uvicorn", "cf_patch_doh.app:app", "--proxy-headers", "--host=0", "--port=5000"]
