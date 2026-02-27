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
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    jq \
    unzip \
    nodejs \
    npm \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Python security tooling ───────────────────────────────────────
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
RUN GITLEAKS_VERSION="8.18.3" && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz

# ── Trivy (container + IaC + SCA scanning) ────────────────────────
RUN TRIVY_VERSION="0.50.1" && \
    curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz

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
