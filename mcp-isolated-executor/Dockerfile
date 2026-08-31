FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ISOLATED_EXECUTOR_RUNTIME=hardened-container \
    ISOLATED_EXECUTOR_ALLOW_NETWORK=false

WORKDIR /app

RUN groupadd --gid 1000 executor && \
    useradd --uid 1000 --gid executor --create-home --home-dir /home/executor executor && \
    mkdir -p /tmp && chown executor:executor /tmp

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY isolated_executor ./isolated_executor

USER 1000:1000

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

CMD ["uvicorn", "isolated_executor.app:app", "--host", "0.0.0.0", "--port", "8080"]
