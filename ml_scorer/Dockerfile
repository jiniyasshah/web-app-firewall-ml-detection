FROM python:3.14-slim
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Run the server directly
CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "8000"]