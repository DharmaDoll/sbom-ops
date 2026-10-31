FROM ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 AS uv
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
ENV UV_PYTHON_DOWNLOADS=never UV_NO_CACHE=1
RUN uv sync --locked --no-dev --no-install-project --no-build \
    && uv pip freeze --python /app/.venv/bin/python > /app/application-packages.txt
USER 65532:65532
CMD ["/app/.venv/bin/python", "-c", "import idna; print(idna.encode('checkout.example').decode())"]
