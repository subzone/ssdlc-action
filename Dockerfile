# ─────────────────────────────────────────────────────────────────
# AI SSDLC Action — Docker Image
# Pre-bakes all security tooling so client runners need nothing.
# ─────────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="subzone"
LABEL description="AI-powered SSDLC GitHub Action — all security tools included"
LABEL org.opencontainers.image.source="https://github.com/subzone/ssdlc-action"

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.local/bin:/usr/local/go/bin:$PATH"

# ── System dependencies ───────────────────────────────────────────
# nodejs/npm excluded — not used by any scanner or script (Semgrep 1.x
# is pure Python; Gitleaks and Trivy are standalone binaries).
# wget/unzip excluded — curl covers all download needs.
# apt-get upgrade applies all available Debian security backports.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        git \
        curl \
        jq \
        ca-certificates \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

# ── Python tooling ────────────────────────────────────────────────
# Upgrade pip + setuptools first — fixes CVE-2024-6345 (setuptools HIGH)
# and ensures subsequent installs use the latest pip/setuptools features and security fixes.
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

RUN pip install --no-cache-dir \
    semgrep \
    checkov \
    safety \
    pip-audit \
    anthropic \
    openai \
    requests \
    jinja2 \
    pyyaml \
    packaging \
    cryptography

# ── Gitleaks (secret scanning) ────────────────────────────────────
RUN GITLEAKS_VERSION="8.30.0" && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz

# ── Trivy (container + IaC + SCA scanning) ────────────────────────
# Use the official Trivy apt repo — avoids hardcoding release URLs that
# can 404 when GitHub asset naming changes between versions.
RUN curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor \
    | tee /usr/share/keyrings/trivy.gpg > /dev/null && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
    | tee /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends trivy && \
    rm -rf /var/lib/apt/lists/*

# ── GitHub CLI (for PR comments and SARIF upload) ─────────────────
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | tee /etc/apt/sources.list.d/github-cli.list > /dev/null && \
    apt-get update && apt-get install -y gh && \
    rm -rf /var/lib/apt/lists/*

# ── Copy action source ────────────────────────────────────────────
WORKDIR /action
COPY src/ /action/src/
COPY entrypoint.sh /action/entrypoint.sh
RUN chmod +x /action/entrypoint.sh
RUN find /action/src -name "*.sh" -exec chmod +x {} \;

# ── Warm Semgrep rule cache (speeds up first run) ─────────────────
RUN semgrep --version

ENTRYPOINT ["/action/entrypoint.sh"]
