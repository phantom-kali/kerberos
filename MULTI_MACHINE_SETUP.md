# Kerberos Authentication System - Multi-Machine Setup Guide

## Overview
This Kerberos implementation supports both single-machine and multi-machine deployments.

## Architecture
- **KDC (Key Distribution Center)**: Issues TGTs and Service Tickets
- **Service Server**: The protected service that requires authentication
- **Client**: Requests tickets and connects to the service

---

## Single Machine Setup (All on localhost)

### 1. Start the KDC Server
```bash
python kdc.py
```

### 2. Start the Service Server
```bash
python service.py
```

### 3. Run the Client
```bash
# Kerberos mode (secure)
python client.py kerberos

# Insecure mode (no authentication)
python client.py insecure
```

---

## Multi-Machine Setup

### Scenario: KDC and Client on Machine A, Service on Machine B

#### Machine B (Service Server)
1. Get the IP address:
   ```bash
   hostname -I
   # Example output: 192.168.1.100
   ```

2. Start the service server:
   ```bash
   python service.py
   ```
   The server will listen on `0.0.0.0:9999` (all network interfaces)

#### Machine A (KDC and Client)
1. Start the KDC server:
   ```bash
   python kdc.py
   ```
   The KDC will listen on `0.0.0.0:8888`

2. Run the client with the service server's IP:
   ```bash
   # Set the SERVICE_HOST environment variable
   export SERVICE_HOST=192.168.1.100
   
   # Run the client
   python client.py kerberos
   ```

---

## Environment Variables

The client supports the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KDC_HOST` | `localhost` | IP address of the KDC server |
| `KDC_PORT` | `8888` | Port of the KDC server |
| `SERVICE_HOST` | `localhost` | IP address of the service server |
| `SERVICE_PORT` | `9999` | Port of the service server |

### Example: All servers on different machines
```bash
export KDC_HOST=192.168.1.50
export KDC_PORT=8888
export SERVICE_HOST=192.168.1.100
export SERVICE_PORT=9999

python client.py kerberos
```

---

## Firewall Configuration

If you're running servers on different machines, ensure the firewall allows connections:

### On the KDC machine:
```bash
sudo firewall-cmd --add-port=8888/tcp --permanent
sudo firewall-cmd --reload
```

### On the Service machine:
```bash
sudo firewall-cmd --add-port=9999/tcp --permanent
sudo firewall-cmd --reload
```

Or for Ubuntu/Debian with ufw:
```bash
# On KDC machine
sudo ufw allow 8888/tcp

# On Service machine
sudo ufw allow 9999/tcp
```

---

## Troubleshooting

### Connection Refused Error
**Problem**: `ConnectionRefusedError: [Errno 111] Connection refused`

**Causes**:
1. The server is not running on the target machine
2. The server is bound to `localhost` instead of `0.0.0.0` (fixed in this version)
3. Firewall is blocking the connection
4. Wrong IP address or port

**Solutions**:
1. Verify the server is running: `ps aux | grep python`
2. Check if the port is listening: `netstat -tuln | grep <PORT>`
3. Test connectivity: `telnet <IP> <PORT>` or `nc -zv <IP> <PORT>`
4. Check firewall rules
5. Verify the IP address is correct

### Testing Network Connectivity
```bash
# From the client machine, test if you can reach the service
nc -zv 192.168.1.100 9999

# If successful, you should see:
# Connection to 192.168.1.100 9999 port [tcp/*] succeeded!
```

---

## Security Notes

⚠️ **WARNING**: This is a simplified Kerberos implementation for educational purposes.

**Current limitations**:
- Hardcoded encryption keys (should use secure key distribution)
- No certificate validation
- No replay attack protection beyond timestamp checking
- Keys are stored in plaintext in the code

**For production use**, you should:
1. Use proper key management (e.g., key files with restricted permissions)
2. Implement certificate-based authentication
3. Add replay attack protection
4. Use TLS/SSL for transport security
5. Implement proper logging and monitoring
6. Use a real Kerberos implementation (MIT Kerberos, Heimdal, etc.)

---

## Network Diagram

```
┌─────────────────┐         ┌─────────────────┐
│   Machine A     │         │   Machine B     │
│                 │         │                 │
│  ┌───────────┐  │         │  ┌───────────┐  │
│  │    KDC    │  │         │  │  Service  │  │
│  │ :8888     │  │         │  │  :9999    │  │
│  └───────────┘  │         │  └───────────┘  │
│        ▲        │         │        ▲        │
│        │        │         │        │        │
│  ┌─────┴─────┐  │         │        │        │
│  │  Client   │  │─────────┼────────┘        │
│  └───────────┘  │ SERVICE_HOST=192.168.1.100│
│                 │         │                 │
└─────────────────┘         └─────────────────┘
```

---

## Quick Reference

### Start all servers locally:
```bash
# Terminal 1
python kdc.py

# Terminal 2
python service.py

# Terminal 3
python client.py kerberos
```

### Connect to remote service:
```bash
export SERVICE_HOST=<service-ip>
python client.py kerberos
```

### Connect to remote KDC and service:
```bash
export KDC_HOST=<kdc-ip>
export SERVICE_HOST=<service-ip>
python client.py kerberos
```
