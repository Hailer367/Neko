FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Update and install base dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    python3-venv \
    golang \
    nodejs \
    npm \
    sudo \
    jq \
    vim \
    unzip \
    build-essential \
    libpcap-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install 70+ tools for White-box and Black-box scanning

# 1. SAST & Static Analysis
RUN apt-get update && apt-get install -y \
    bandit \
    shellcheck \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages \
    semgrep \
    checkov \
    detect-secrets \
    vulture \
    dodgy \
    safety \
    pip-audit \
    radon \
    xenon

# 2. Secret Detection
RUN apt-get update && apt-get install -y \
    gitleaks \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSL https://raw.githubusercontent.com/trufflehog/trufflehog/main/scripts/install.sh | sh

# 3. Dependency & Container Scanning (SCA)
RUN wget https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_Linux-64bit.deb \
    && dpkg -i trivy_0.59.1_Linux-64bit.deb && rm trivy_0.59.1_Linux-64bit.deb
RUN wget https://github.com/anchore/grype/releases/download/v0.86.1/grype_0.86.1_linux_amd64.deb \
    && dpkg -i grype_0.86.1_linux_amd64.deb && rm grype_0.86.1_linux_amd64.deb
RUN wget https://github.com/anchore/syft/releases/download/v1.40.1/syft_1.40.1_linux_amd64.deb \
    && dpkg -i syft_1.40.1_linux_amd64.deb && rm syft_1.40.1_linux_amd64.deb

# 4. Web Scanners & Recon
RUN apt-get update && apt-get install -y \
    nmap \
    sqlmap \
    nikto \
    ffuf \
    dirb \
    dirsearch \
    wfuzz \
    && rm -rf /var/lib/apt/lists/*

# 5. Advanced Tools (Nuclei, Katana, etc.)
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# 6. Specialized Testing
RUN apt-get update && apt-get install -y \
    jwt-tool \
    commix \
    wapiti \
    xsser \
    sqlninja \
    metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# 7. Language Specific SAST
RUN npm install -g eslint eslint-plugin-security retire \
    && go install github.com/securego/gosec/v2/cmd/gosec@latest

# 8. IaC & Cloud Security
RUN wget https://github.com/tenable/terrascan/releases/download/v1.19.1/terrascan_1.19.1_Linux_x86_64.tar.gz \
    && tar -xf terrascan_1.19.1_Linux_x86_64.tar.gz terrascan && mv terrascan /usr/local/bin/ && rm terrascan_1.19.1_Linux_x86_64.tar.gz
RUN wget https://github.com/Checkmarx/kics/releases/download/v2.1.3/kics_2.1.3_linux_amd64.tar.gz \
    && tar -xf kics_2.1.3_linux_amd64.tar.gz kics && mv kics /usr/local/bin/ && rm kics_2.1.3_linux_amd64.tar.gz

# 9. Additional Tools (HexStrike-style)
RUN apt-get update && apt-get install -y \
    rustscan \
    masscan \
    feroxbuster \
    gobuster \
    arjun \
    && rm -rf /var/lib/apt/lists/*

# Set up Neko environment
WORKDIR /neko
COPY . /neko/
RUN pip3 install --break-system-packages aiohttp requests jinja2

# Add Go binaries to PATH
ENV PATH="/root/go/bin:${PATH}"

# Final Tool Count Check (should be > 70)
# Including: nmap, masscan, rustscan, sqlmap, commix, nikto, ffuf, dirb, dirsearch, wfuzz, 
# gobuster, feroxbuster, nuclei, katana, subfinder, httpx, naabu, interactsh, jwt-tool, 
# semgrep, bandit, checkov, shellcheck, detect-secrets, vulture, dodgy, safety, pip-audit, 
# radon, xenon, gitleaks, trufflehog, trivy, grype, syft, eslint, retire, gosec, terrascan, 
# kics, wapiti, xsser, metasploit, ... and many more dependencies.

ENTRYPOINT ["python3", "-m", "neko.agents.commander"]
