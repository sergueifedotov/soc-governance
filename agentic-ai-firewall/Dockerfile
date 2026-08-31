FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTGUARD_HOST=0.0.0.0 \
    AGENTGUARD_PORT=8088

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY agentguard ./agentguard
COPY policy.example.yaml ./policy.yaml

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8088/healthz', timeout=2).raise_for_status()" || exit 1

CMD ["python", "-m", "agentguard"]
