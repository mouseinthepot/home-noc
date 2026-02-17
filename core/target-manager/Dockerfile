FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY app.py /app/app.py
COPY seed.json /app/seed.json
COPY static /app/static

EXPOSE 8080

CMD ["python", "/app/app.py"]
