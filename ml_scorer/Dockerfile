# Use official Python image
FROM python:3.12-slim

# Set work directory inside the container
WORKDIR /app

# Copy requirement file if you have it
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install -r requirements.txt

# Copy the entire Django project
COPY . /app/

# Expose port 8000 for Django
EXPOSE 8000

# Default command when the container starts
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
