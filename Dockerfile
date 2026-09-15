FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

RUN groupadd --gid 10001 memo \
    && useradd --uid 10001 --gid memo --no-create-home --shell /usr/sbin/nologin memo \
    && mkdir /data \
    && chown memo:memo /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

USER 10001:10001
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "2", "--worker-tmp-dir", "/tmp", "--umask", "0077", "--forwarded-allow-ips", "", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
