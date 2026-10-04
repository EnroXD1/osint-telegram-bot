FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY osint_bot ./osint_bot
RUN useradd --create-home botuser
USER botuser
CMD ["python", "-m", "osint_bot"]
