# EntropyOrchestrator

A production-ready asyncio service that harvests entropy from hardware and serves it via OSC, WebSockets, and HTTP for generative art.

## Overview

EntropyOrchestrator is a Python-based service designed to collect high-quality entropy from hardware sources (TrueRNG v3 or RTL-SDR) and make it available to generative art systems via multiple protocols:

- **HTTP API**: RESTful endpoints for accessing random data
- **OSC Server**: UDP-based Open Sound Control for SuperCollider/TidalCycles
- **WebSocket Server**: Real-time streaming for Hydra, P5.js, and other web-based generative art tools

## Features

- **Multiple Hardware Sources**: Supports TrueRNG v3 serial devices and RTL-SDR receivers
- **Async Implementation**: Built with asyncio for high-performance concurrent operations
- **Buffered Streaming**: Decouples hardware read speeds from API access speeds
- **Musical Quantization**: Converts raw entropy to musical scales and notes
- **Production Ready**: Includes Docker support, proper logging, and error handling

## Architecture

The system consists of three main components:

1. **Entropy Sources**: 
   - Hardware-based (TrueRNG v3 via serial, RTL-SDR via rtl_entropy)
   - Fallback mock source for development/testing

2. **Entropy Buffer**: 
   - Maintains a queue of normalized floating-point values (0.0-1.0)
   - Handles buffering and rate limiting between hardware and API access

3. **Protocol Servers**: 
   - HTTP (Quart): REST endpoints for batch data access
   - OSC (UDP): Query-based protocol for SuperCollider/Tidal integration
   - WebSocket: Real-time stream for generative art tools

## Hardware Requirements

### TrueRNG v3
- USB serial device (typically `/dev/ttyACM0`)
- Requires `pyserial` Python library

### RTL-SDR
- USB SDR receiver (e.g., RTL2832U-based devices)
- Requires `rtl_entropy` binary to be installed (built in Dockerfile)
- Requires USB device access privileges

## Configuration

Environment variables:

- `SOURCE_TYPE`: 'mock', 'serial', or 'sdr' (default: 'mock')
- `SERIAL_PORT`: Serial port path (default: '/dev/ttyACM0')
- `BUFFER_SIZE`: Size of entropy buffer (default: 1024)
- `BROADCAST_INTERVAL_MS`: WebSocket broadcast interval in milliseconds (default: 100)

## API Endpoints

### HTTP
- `GET /batch?count=N`: Get N random floats (max 1000)
- `GET /status`: Get service status

### OSC
- `GET /rnd/float`: Logs generated float values (for debugging)

### WebSocket
- Connect to `ws://localhost:9001` for real-time streaming of entropy values

## Docker Deployment

The application includes a complete Docker setup:

```bash
# Build and run with hardware access
docker-compose up

# Or build manually
docker build -t entropy-orchestrator .
docker run --privileged \
  --device=/dev/ttyACM0:/dev/ttyACM0 \
  --device=/dev/bus/usb:/dev/bus/usb \
  -p 8000:8000 -p 9000:9000/udp -p 9001:9001 \
  entropy-orchestrator
```

## Usage Examples

### For Generative Art with Hydra:
```javascript
// Connect to WebSocket stream
const ws = new WebSocket('ws://localhost:9001');
ws.onmessage = (event) => {
  const value = parseFloat(event.data);
  // Use value for generative art
};
```

### For TidalCycles:
```haskell
-- Use OSC to query random values
d1 $ sound "bd" # pan (lch $ s "osc" 9000 "/rnd/float")
```

### For HTTP API:
```bash
# Get 10 random floats
curl "http://localhost:8000/batch?count=10"

# Check status
curl "http://localhost:8000/status"
```

## Development

### Running Locally
```bash
# Install dependencies
pip install -r requirements.txt

# Run with mock source (no hardware required)
SOURCE_TYPE=mock python main.py
```

### Testing Hardware Sources
```bash
# With TrueRNG v3
SOURCE_TYPE=serial python main.py

# With RTL-SDR (requires rtl_entropy to be built and installed)
SOURCE_TYPE=sdr python main.py
```

## License

MIT