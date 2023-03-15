FROM python:3.10

WORKDIR /app
ENV PATH="/root/.local/bin:${PATH}"

RUN curl -sSL https://install.python-poetry.org | POETRY_VERSION=1.4.0 python3
COPY pyproject.toml poetry.lock ./
RUN \
    poetry config virtualenvs.create false && \
    poetry install --only main --no-root
COPY . ./

CMD ["uvicorn", "app:app", "--proxy-headers", "--host=0", "--port=5000"]
