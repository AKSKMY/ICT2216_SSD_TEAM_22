# ───────────────────────────────────────────────────────────────────────
# 1. Start from a minimal Python image
FROM python:3.11-slim

# 2. Set /app as the working directory inside the container
WORKDIR /app

# 3. Copy only requirements first (so Docker can cache pip install)
COPY backend/requirements.txt /app/requirements.txt

# 4. Install system dependencies if needed & then install Python packages
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libpq-dev \
 && pip install --no-cache-dir -r /app/requirements.txt \
 && apt-get purge -y --auto-remove gcc \
 && rm -rf /var/lib/apt/lists/*

# 5. Copy your Flask app code & templates into the image
COPY backend/ /app/
COPY html/    /app/templates/

# 6. Expose port 5000 for Flask
EXPOSE 5000

# 7. Default command: run Flask’s development server (you can swap for gunicorn later)
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
