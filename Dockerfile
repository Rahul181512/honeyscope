# HoneyScope - Honeypot with Attack Visualization Dashboard
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY core/ ./core/
COPY honeypot/ ./honeypot/
COPY dashboard/ ./dashboard/
COPY reports/ ./reports/
COPY scripts/ ./scripts/
COPY run.py .

# Runtime artefacts (SQLite db, raw logs, generated reports) live here.
VOLUME ["/app/data", "/app/logs", "/app/reports/out"]

EXPOSE 5555 2121 2222 2323 8081 \
       1433 2375 3000 3306 3389 5000 5432 5900 6379 \
       8000 8009 8443 9000 9042 9200 11211 27017

ENV PYTHONUNBUFFERED=1 \
    HONEYPOT_BIND_HOST=0.0.0.0

# Consent flag: container decoys bind 0.0.0.0 -> operator asserts authority
CMD ["python", "run.py", "--mode", "all", "--host", "0.0.0.0", \
     "--i-own-this-network"]
