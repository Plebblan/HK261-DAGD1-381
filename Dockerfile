FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY docs/app1/openapi.json ./openapi.json
COPY cyber-range ./cyber-range
EXPOSE 8000
CMD ["uvicorn", "app.standard.main:app", "--host", "0.0.0.0", "--port", "8000"]
