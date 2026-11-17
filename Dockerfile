# syntax=docker/dockerfile:1

# ---- build stage: install the app into a self-contained virtualenv ----
FROM python:3.15-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /venv
ENV PATH=/venv/bin:$PATH
WORKDIR /src
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install .

# ---- runtime stage: just Python + the venv, running as non-root ----
FROM python:3.15-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin scanboard \
 && mkdir /data && chown scanboard /data
COPY --from=build /venv /venv
ENV PATH=/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////data/scanboard.db
USER 10001
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
