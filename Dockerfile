# BlueGuardian AI Sandbox Image
# Isolated environment for safe malware analysis

FROM ubuntu:22.04

LABEL maintainer="BlueGuardian AI Team"
LABEL description="Isolated sandbox for malware analysis"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install basic analysis tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    file \
    binutils \
    strings \
    hexdump \
    strace \
    ltrace \
    radare2 \
    yara \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python analysis libraries
RUN pip3 install --no-cache-dir \
    pefile \
    pyelftools \
    yara-python \
    python-magic

# Create non-root sandbox user
RUN useradd -m -s /bin/bash -u 1000 sandbox

# Create workspace directory
RUN mkdir -p /workspace && chown sandbox:sandbox /workspace

# Switch to sandbox user
USER sandbox
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
