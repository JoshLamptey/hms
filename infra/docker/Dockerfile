# syntax=docker/dockerfile:1.7

ARG PYTHON_BASE_IMAGE=python:3.12-slim-bookworm

FROM ${PYTHON_BASE_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:${PATH}" \
    APP_HOME=/app \
    TMPDIR=/app/tmp
WORKDIR ${APP_HOME}
RUN python -m venv /opt/venv

FROM base AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc g++ libpq-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements/ ./requirements/
RUN pip install --upgrade pip setuptools wheel \
    && pip wheel --wheel-dir=/wheels/base -r requirements/base.txt \
    && pip wheel --wheel-dir=/wheels/production -r requirements/production.txt \
    && pip wheel --wheel-dir=/wheels/development -r requirements/development.txt

FROM base AS runtime-base
ARG APP_UID=10001
ARG APP_GID=10001
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpq5 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid "${APP_GID}" appgroup \
    && useradd --system --uid "${APP_UID}" --gid appgroup --home-dir "${APP_HOME}" --shell /usr/sbin/nologin appuser \
    && mkdir -p "${APP_HOME}/staticfiles" "${APP_HOME}/media" "${APP_HOME}/tmp" "${APP_HOME}/runtime" \
    && chown -R appuser:appgroup "${APP_HOME}"
COPY --chmod=0755 infra/docker/*.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
STOPSIGNAL SIGTERM

FROM runtime-base AS production
COPY requirements/ ./requirements/
COPY --from=builder /wheels/base /wheels/base
COPY --from=builder /wheels/production /wheels/production
RUN pip install --no-index --find-links=/wheels/base -r requirements/base.txt \
    && pip install --no-index --find-links=/wheels/base --find-links=/wheels/production -r requirements/production.txt \
    && rm -rf /wheels requirements
COPY --chown=${APP_UID}:${APP_GID} . .
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 CMD curl -f -H "X-Forwarded-Proto: https" http://localhost:8000/health/live/ || exit 1
CMD ["/usr/local/bin/start-prod.sh"]

FROM runtime-base AS development
COPY requirements/ ./requirements/
COPY --from=builder /wheels/base /wheels/base
COPY --from=builder /wheels/development /wheels/development
RUN pip install --no-index --find-links=/wheels/base -r requirements/base.txt \
    && pip install --no-index --find-links=/wheels/base --find-links=/wheels/production --find-links=/wheels/development -r requirements/development.txt \
    && rm -rf /wheels
COPY --chown=${APP_UID}:${APP_GID} . .
USER appuser
EXPOSE 8000
CMD ["/usr/local/bin/start-dev.sh"]
