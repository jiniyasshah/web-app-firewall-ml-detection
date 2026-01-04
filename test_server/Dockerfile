# Use the official Python image from the Docker Hub, latest stable version
FROM python:3.14-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the Python code into the container
COPY . .

# Upgrade pip to the latest version
RUN pip install --upgrade pip

# Install Flask (or any other requirements)
RUN pip install flask

# Expose the port for the Python HTTP server
EXPOSE 3000

# Run the Python HTTP server
CMD ["python", "app.py"]
