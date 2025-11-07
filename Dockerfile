# Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    sqlmap \
    git \
    wget \
    curl \
    dnsutils \
    whois \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install OWASP ZAP
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz \
    && tar -xvf ZAP_2.14.0_Linux.tar.gz -C /opt/ \
    && rm ZAP_2.14.0_Linux.tar.gz

ENV PATH="/opt/ZAP_2.14.0:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./src/
COPY data/ ./data/

# Create non-root user for security
RUN useradd -m -u 1000 mcpuser && \
    chown -R mcpuser:mcpuser /app

USER mcpuser

# Expose port for HTTP transport
EXPOSE 8080

# Start MCP server
CMD ["python", "-m", "src.server"]