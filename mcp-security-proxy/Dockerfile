FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_security_proxy ./mcp_security_proxy
COPY config ./config

EXPOSE 8090

CMD ["uvicorn", "mcp_security_proxy.app:app", "--host", "0.0.0.0", "--port", "8090"]