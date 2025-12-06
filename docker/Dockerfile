FROM python:3.11-slim

# Install system dependencies (ssh-keygen, gpg, cron)
RUN apt-get update && apt-get install -y openssh-client gnupg cron && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first to leverage cache
COPY server/requirements.txt ./server/requirements.txt
RUN pip install --no-cache-dir -r server/requirements.txt

# Copy application code
COPY server ./server
COPY public ./public

# Create necessary directories
RUN mkdir -p /app/keys /app/data /app/temp /app/ca_store

# Expose port
EXPOSE 3000

# Run the application as a module
CMD ["python", "-u", "-m", "server.server"]
