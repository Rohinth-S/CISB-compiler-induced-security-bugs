# syntax=docker/dockerfile:1
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Install LLVM 18, Clang 18, build toolchain, binutils, and Python environment
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    binutils \
    git \
    curl \
    ca-certificates \
    clang-18 \
    clang-tools-18 \
    llvm-18 \
    llvm-18-dev \
    libclang-18-dev \
    libclang-cpp18-dev \
    python3 \
    python3-pip \
    python3-matplotlib \
    && rm -rf /var/lib/apt/lists/*

# Set up standard symlinks for clang, opt, and llvm-config
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 && \
    update-alternatives --install /usr/bin/opt opt /usr/bin/opt-18 100 && \
    update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-18 100

WORKDIR /workspace

# Copy repository files
COPY . /workspace

# Configure and compile libCISBGuard.so and ub-check-guard
RUN cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm \
    -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang \
    && cmake --build build

# Make cisb-guard-cc executable
RUN chmod +x bin/cisb-guard-cc

EXPOSE 8080

CMD ["python3", "backend/app.py"]
