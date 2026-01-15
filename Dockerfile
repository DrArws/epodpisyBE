# E-Signing Service Dockerfile for Google Cloud Run
# Multi-stage build for smaller image size

# ============================================================================
# Stage 1: Java Builder (PAdES KMS Signer)
# ============================================================================
FROM maven:3.9-eclipse-temurin-17 as java-builder

WORKDIR /build

# 1️⃣ Copy pom.xml first and download dependencies (cached layer)
COPY pades-kms-signer/pom.xml ./pom.xml
RUN mvn dependency:go-offline -q

# 2️⃣ Then copy source and build (only rebuilds when code changes)
COPY pades-kms-signer/src ./src
RUN mvn -q -DskipTests package -o

# ============================================================================
# Stage 2: Python Builder
# ============================================================================
FROM python:3.11-slim-bookworm as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Stage 3: Runtime
# ============================================================================
FROM python:3.11-slim-bookworm as runtime

# Metadata
LABEL maintainer="E-Signing Service"
LABEL version="1.0.0"

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Cloud Run will set PORT
    PORT=8080 \
    # PAdES signer JAR location
    PADES_JAR_PATH="/app/lib/pades-kms-signer.jar" \
    # Java options for Cloud Run - headless mode and UTC timezone for consistent audit timestamps
    JAVA_TOOL_OPTIONS="-Djava.awt.headless=true -Duser.timezone=UTC -Xmx256m -XX:+UseG1GC"

# Install runtime dependencies
# LibreOffice for document conversion + fonts + Java 17 JRE for PAdES signing
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Java 17 JRE for PAdES signing
    openjdk-17-jre-headless \
    # LibreOffice core (minimal) - needed for PDF conversion
    libreoffice-core \
    libreoffice-writer \
    libreoffice-calc \
    libreoffice-impress \
    # Fonts for proper rendering (including MS-compatible fonts)
    fonts-liberation \
    fonts-liberation2 \
    fonts-dejavu-core \
    fonts-dejavu-extra \
    fonts-freefont-ttf \
    fonts-noto-core \
    fonts-noto-cjk \
    fonts-crosextra-carlito \
    fonts-crosextra-caladea \
    fontconfig \
    # Required libraries
    libmagic1 \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives/* \
    # Rebuild font cache
    && fc-cache -f -v \
    # Verify installations
    && soffice --version \
    && java -version

# Create non-root user for security
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Create lib directory for JAR
RUN mkdir -p /app/lib

# Copy PAdES signer JAR from java-builder
COPY --from=java-builder /build/target/pades-kms-signer.jar /app/lib/pades-kms-signer.jar

# Copy application code
COPY --chown=appuser:appgroup app/ ./app/

# Create temp directory with proper permissions
RUN mkdir -p /tmp/e-signing && \
    chown -R appuser:appgroup /tmp/e-signing && \
    chmod 755 /tmp/e-signing && \
    # Set permissions for PAdES JAR
    chown -R appuser:appgroup /app/lib && \
    chmod 755 /app/lib/pades-kms-signer.jar

# LibreOffice needs a home directory for profile
RUN mkdir -p /home/appuser/.config/libreoffice && \
    chown -R appuser:appgroup /home/appuser

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/health')" || exit 1

# Expose port
EXPOSE ${PORT}

# Run the application
# Cloud Run sets $PORT environment variable
CMD exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port ${PORT} \
    --workers 1 \
    --timeout-keep-alive 30 \
    --proxy-headers \
    --forwarded-allow-ips="*" \
    --access-log
