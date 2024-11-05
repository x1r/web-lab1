FROM python:3.10-slim

WORKDIR /app

# Скопируем requirements и установим зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# Добавляем PYTHONPATH, чтобы видеть папку website
ENV PYTHONPATH=/app:/website

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--reload"]
