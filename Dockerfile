FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 riskeye && \
    chown -R riskeye:riskeye /app && \
    mkdir -p /app/scan_results && \
    chown -R riskeye:riskeye /app/scan_results

USER riskeye

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

CMD ["python", "riskeye.py"]
