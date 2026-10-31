FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY __init__.py common.py tenantdesk.py shopflow.py ./custom_1/
COPY docs ./custom_1/docs
COPY cyber-range ./custom_1/cyber-range

EXPOSE 8001 8002

CMD ["uvicorn", "custom_1.tenantdesk:app", "--host", "0.0.0.0", "--port", "8001"]
