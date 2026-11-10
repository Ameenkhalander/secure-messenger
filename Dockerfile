FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_ENV=production
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --system --create-home app && mkdir -p /srv/instance && chown -R app /srv/instance
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1
# One process, many threads: presence/WebSockets live in memory. Scale out with a Socket.IO message queue.
CMD ["gunicorn", "--worker-class", "gthread", "--workers", "1", "--threads", "100", "--bind", "0.0.0.0:8000", "run:app"]
