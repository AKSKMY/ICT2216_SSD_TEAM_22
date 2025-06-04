# Use official lightweight Python image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire backend folder contents (app.py, config.py, html/, static/, etc.)
COPY . .

# Expose the port Flask listens on
EXPOSE 5000

# Use gunicorn for production WSGI server
CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5000", "--workers", "4"]
