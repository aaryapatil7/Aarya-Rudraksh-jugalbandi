# Active Connections Auditor Agent

## Overview
The Active Connections Auditor Agent is a Python-based Linux security utility that audits active network connections and UDP sockets. It collects connection information, identifies remote IP addresses and ports, retrieves approximate geographic information for eligible public IP addresses, and flags connections using configured ports for review.

## Features
- Detects established TCP connections.
- Audits UDP sockets and identifies visible remote peers.
- Retrieves approximate geolocation information for eligible public IP addresses.
- Flags configured ports for further review.
- Reports findings and execution time.
- Provides a callable `audit_connections()` function for programmatic use.

## Technologies Used
- Python 3
- Linux networking utilities (`ss`)
- IP geolocation API

## Requirements
- Linux environment or Ubuntu on WSL
- Python 3
- Internet access for geolocation lookups
- The `ss` utility from the `iproute2` package

## How to Run

```bash
cd active_connections_auditor
python3 active_connections_auditor.py
```

## Programmatic Usage

```python
from active_connections_auditor import audit_connections

result = audit_connections()
print(result)
```

## Limitations
- Geolocation is approximate and depends on an external service.
- UDP remote-peer information depends on what the operating system exposes.
- Configured review ports are indicators for further investigation, not proof of malicious activity.

## Project Status
Standalone agent implemented and tested. Integration with the main Agentic Shell is pending verification.
