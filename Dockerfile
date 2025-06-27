# -------------------------------------------------------------------------------
# Dockerfile  (place this at the *root* of ICT2216_SSD_TEAM_22/)
# -------------------------------------------------------------------------------

FROM python:3.10-slim

# 1) Create /app directory and switch working directory
WORKDIR /app

# 2) Copy only requirements.txt (caching layer)
COPY ./backend/requirements.txt /app/requirements.txt

# 3) Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 4) Copy the entire "backend" folder into /app
#    This includes app.py, config.py, html/, static/, etc.
COPY ./backend /app

# 5) Expose port 5000 (Gunicorn will listen here)
EXPOSE 5000

# 6) Default environment = production (can be overridden)
ENV FLASK_ENV=production

# 7) Launch Gunicorn, binding to 0.0.0.0:5000, serving "app:app"
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "main:app"]