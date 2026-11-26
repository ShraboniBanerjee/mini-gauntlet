# syntax=docker/dockerfile:1

# ---- Build: install dependencies into a virtualenv ---------------------------------
FROM python:3.12.16-slim-trixie AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# ---- Runtime: the virtualenv and the app, nothing else -----------------------------
FROM python:3.12.16-slim-trixie AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    INVENTORY_PATH=/inventory/inventory.json \
    DATABASE_PATH=/data/mini_gauntlet.db

# A fixed, unprivileged user. /data is created here, owned by that user, so a named
# volume mounted on it starts with the right ownership.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data \
 && chown app:app /data

WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY app ./app

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"]

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
