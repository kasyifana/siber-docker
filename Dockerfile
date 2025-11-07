# Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    sqlmap \
    git \
    wget \
    curl \
    dnsutils \
    whois \
    netcat-openbsd \
    perl \
    libnet-ssleay-perl \
    openssl \
    libauthen-pam-perl \
    libio-pty-perl \
    libmd-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto from GitHub
RUN git clone https://github.com/sullo/nikto /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# Note: OWASP ZAP is optional and heavy (300MB+)
# Uncomment below if you need ZAP functionality
# RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz \
#     && tar -xvf ZAP_2.15.0_Linux.tar.gz -C /opt/ \
#     && rm ZAP_2.15.0_Linux.tar.gz
# ENV PATH="/opt/ZAP_2.15.0:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./src/
COPY data/ ./data/

# Copy startup script first (before creating user)
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create non-root user for security
RUN useradd -m -u 1000 mcpuser && \
    chown -R mcpuser:mcpuser /app

USER mcpuser

# Expose HTTP port for MCP over SSE
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Run both HTTP server (background) and stdio bridge (foreground)
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]