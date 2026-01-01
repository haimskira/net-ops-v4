# Base Image - Slim version for smaller footprint
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Set environment variables
# PYTHONDONTWRITEBYTECODE: Prevents Python from writing pyc files to disc
# PYTHONUNBUFFERED: Prevents Python from buffering stdout and stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies (if needed later, e.g. for LDAP or DB drivers)
# RUN apt-get update && apt-get install -y --no-install-recommends gcc libldap2-dev libsasl2-dev && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose the application port
EXPOSE 5100
EXPOSE 514/udp

# Run the application
# Note: For production, consider using gunicorn (e.g., CMD ["gunicorn", "--bind", "0.0.0.0:5100", "app:app"])
# For now, using direct python execution as per existing setup
CMD ["python", "app.py"]
