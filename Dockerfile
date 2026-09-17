# agent-trace central collector.
#
# Prerequisite: the standalone trace shell assets must exist in the
# build context — run `python ui/build-ui.py` first (copies the
# plugin's dist/index.js as ui/app.js + vendored React/antd UMDs).
# .dockerignore keeps ui/vendor + ui/app.js IN the context on purpose.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TRACE_DB=/data/traces.db

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py storage.py auth.py ./
COPY portal/ ./portal/
COPY ui/index.html ./ui/index.html
COPY ui/vendor/ ./ui/vendor/
COPY ui/app.js ./ui/app.js

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:8790'+os.environ.get('TRACE_BASE_PATH','').rstrip('/')+'/healthz', timeout=4)"

# TRACE_TOKEN is intentionally unset by default (open collector on a
# private network); set it via `-e TRACE_TOKEN=...` in production.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8790"]
