FROM ghcr.io/astral-sh/uv:trixie-slim AS runner

RUN mkdir /website

WORKDIR /app
COPY . /app

RUN uv sync --no-dev

RUN uv pip install gunicorn
ENV PYTHONUNBUFFERED=TRUE
CMD ["uv", "run", "gunicorn", "--control-socket", "/website/portal_gunicorn.sock", "--enable-stdio-inheritance", "-w", "2", "-b", "unix:/website/portal.sock", "portal:create_app()"]
