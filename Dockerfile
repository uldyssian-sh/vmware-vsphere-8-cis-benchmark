# VMware vSphere 8 CIS Benchmark - Docker Container
# Enterprise-ready containerized CIS compliance assessment tool

FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

# Metadata
LABEL maintainer="VMware Security Team" \
      description="VMware vSphere 8 CIS Benchmark Compliance Assessment Tool" \
      version="3.0.0" \
      vendor="Open Source" \
      license="MIT"

# Set working directory
WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY scripts/ ./scripts/
COPY docs/ ./docs/
COPY README.md SECURITY.md LICENSE ./

# Install PowerShell modules
RUN pwsh -Command "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted" && \
    pwsh -Command "Install-Module -Name VMware.PowerCLI -Force -AllowClobber -Scope AllUsers" && \
    pwsh -Command "Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:\$false -Scope AllUsers"

# Create reports directory
RUN mkdir -p /app/reports

# Set permissions
RUN chmod +x /app/scripts/Invoke-vSphere8CISAudit.ps1

# Create non-root user for security
RUN useradd -m -s /bin/bash cisaudit && \
    chown -R cisaudit:cisaudit /app

USER cisaudit

# Environment variables
ENV POWERSHELL_TELEMETRY_OPTOUT=1
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pwsh -Command "Get-Module -ListAvailable VMware.PowerCLI | Select-Object -First 1"

# Default command
CMD ["pwsh", "-File", "/app/scripts/Invoke-vSphere8CISAudit.ps1"]

# Usage examples:
# Build: docker build -t vsphere-cis-benchmark .
# Run: docker run -it --rm -v $(pwd)/reports:/app/reports vsphere-cis-benchmark
# Interactive: docker run -it --rm vsphere-cis-benchmark pwsh# Updated 20251109_123841
