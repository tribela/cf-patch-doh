FROM python:3.10

WORKDIR /app
ENV PATH="/root/.local/bin:${PATH}"

RUN curl -sSL https://install.python-poetry.org | POETRY_VERSION=1.4.0 python3
COPY pyproject.toml poetry.lock ./
RUN \
    poetry config virtualenvs.create false && \
    poetry install --only main --no-root
COPY . ./

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=2 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["uvicorn", "app:app", "--proxy-headers", "--host=0", "--port=5000"]
