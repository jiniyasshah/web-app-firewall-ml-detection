FROM python:3.14-slim

WORKDIR /app

# Install libs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY . .

# Train the model immediately during build
RUN python train.py

# Start API
EXPOSE 8000
CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "8000"]