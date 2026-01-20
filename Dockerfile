# Build Stage: Compile rtl_entropy tool
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libusb-1.0-0-dev \
    librtlsdr-dev \
    pkg-config

# Clone and build rtl_entropy
WORKDIR /tmp
RUN git clone https://github.com/n1474335/rtl-entropy.git \
    && cd rtl-entropy \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && make install

# Final Stage: Runtime
FROM python:3.11-slim

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    librtlsdr0 \
    libusb-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binary from builder
COPY --from=builder /usr/local/bin/rtl_entropy /usr/local/bin/

# Set working directory
WORKDIR /app

# Copy requirements and install Python libs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose ports: HTTP (8000), OSC (9000/udp), WebSocket (9001)
EXPOSE 8000 9000/udp 9001

# Run the application
CMD ["python", "main.py"]
