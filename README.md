# UAF - Unified Automation Framework

## 🎯 Project Overview

The **Unified Automation Framework (UAF)** is a vendor-agnostic network automation platform that bridges legacy CLI-based network devices with modern API-first SDN controllers. It provides a unified control plane for managing hybrid network ecosystems.

### Key Features

✅ **Vendor-Agnostic Abstraction Layer**
- Cisco IOS/IOS-XE (via Netmiko/SSH)
- MikroTik RouterOS (via SSH/API)
- Ubiquiti UniFi (via REST API)

✅ **Automated Security (Kill-Switch)**
- Real-time rogue device detection
- Automated port isolation
- Incident logging and audit trails

✅ **Intelligent Power Management**
- Time-based port scheduling
- Wake-on-LAN support
- Cost optimization for SMEs

✅ **Network Monitoring**
- Real-time device health metrics
- Interface status tracking
- Network-wide availability monitoring

✅ **Source of Truth Integration**
- NetBox integration for inventory management
- Dynamic device discovery
- Configuration version control

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        UAF Backend                          │
│                     (FastAPI + Python)                      │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────┐ │
│  │   API    │  │  Kill     │  │ Monitor  │  │ Scheduler │ │
│  │Endpoints │  │  Switch   │  │ Service  │  │  Service  │ │
│  └──────────┘  └───────────┘  └──────────┘  └───────────┘ │
├─────────────────────────────────────────────────────────────┤
│              Vendor-Agnostic Abstraction Layer              │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐                │
│  │  Cisco   │  │ MikroTik  │  │  UniFi   │                │
│  │  Driver  │  │  Driver   │  │  Driver  │                │
│  └──────────┘  └───────────┘  └──────────┘                │
├─────────────────────────────────────────────────────────────┤
│                   NetBox (Source of Truth)                  │
└─────────────────────────────────────────────────────────────┘
                              ↓
         ┌────────────────────────────────────────┐
         │  Physical/Virtual Network Devices      │
         │  - Cisco Switches                      │
         │  - MikroTik Routers                    │
         │  - UniFi Access Points                 │
         └────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git

### Quick Start

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/uaf.git
   cd uaf
   ```

2. **Configure Environment**
   ```bash
   cd backend
   cp .env.example .env
   # Edit .env with your device credentials
   ```

3. **Start the Stack with Docker Compose**
   ```bash
   docker-compose up -d
   ```

4. **Verify Services**
   ```bash
   # Check if all containers are running
   docker-compose ps
   
   # UAF Backend: http://localhost:8000
   # NetBox: http://localhost:8080 (admin/admin)
   ```

### Manual Installation (Without Docker)

1. **Install Dependencies**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Start NetBox (Separate Terminal)**
   ```bash
   docker run -d \
     --name netbox \
     -p 8080:8080 \
     -e SUPERUSER_NAME=admin \
     -e SUPERUSER_PASSWORD=admin \
     netboxcommunity/netbox:latest
   ```

3. **Start UAF Backend**
   ```bash
   python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

---

## 🔑 Authentication

### Default Credentials

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| `admin` | `admin123` | Admin | Full Access |
| `operator` | `operator123` | Operator | Read + Execute |
| `viewer` | `viewer123` | Viewer | Read Only |

### Getting an Access Token

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 28800,
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```

### Using the Token

```bash
curl -X GET http://localhost:8000/api/devices \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 📚 API Documentation

### Interactive API Docs

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Core Endpoints

#### Device Management

```bash
# Get all devices
GET /api/devices

# Get specific device
GET /api/devices/{device_name}

# Get device interfaces
GET /api/devices/{device_name}/interfaces
```

#### Port Control (Kill-Switch)

```bash
# Shutdown a port
POST /api/devices/port-control
{
  "device_name": "cisco-sw01",
  "port_id": "GigabitEthernet0/5",
  "action": "shutdown"
}

# Enable a port
POST /api/devices/port-control
{
  "device_name": "cisco-sw01",
  "port_id": "GigabitEthernet0/5",
  "action": "enable"
}
```

#### Security Operations

```bash
# Trigger security alert
POST /api/security/alert
{
  "device_name": "cisco-sw01",
  "port_id": "GigabitEthernet0/10",
  "threat_type": "rogue_device"
}

# Get active threats
GET /api/security/threats

# Manual security scan
POST /api/security/scan
```

#### Network Monitoring

```bash
# Get network health
GET /api/monitor/network-health

# Get device metrics
GET /api/monitor/device/{device_name}/metrics
```

#### Scheduler Control

```bash
# Trigger time-based policy
POST /api/scheduler/control
{
  "action": "trigger_time_policy"
}

# Trigger security scan
POST /api/scheduler/control
{
  "action": "trigger_security"
}

# Get scheduler status
GET /api/scheduler/status
```

#### Wake-on-LAN

```bash
# Wake a device
POST /api/power/wake
{
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "broadcast_ip": "192.168.1.255"
}
```

---

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# System Settings
PROJECT_NAME="UAF - Unified Automation Framework"
VERSION="1.0.0"
MOCK_MODE=True  # Set to False for real devices

# Cisco Switch (SSH)
CISCO_IP=192.168.1.10
CISCO_PORT=22
CISCO_USER=admin
CISCO_PASS=cisco123
CISCO_SECRET=cisco123

# MikroTik Router (SSH/API)
MIKROTIK_IP=192.168.1.20
MIKROTIK_PORT=22
MIKROTIK_USER=admin
MIKROTIK_PASS=mikrotik123

# UniFi Controller (API)
UNIFI_IP=192.168.1.30
UNIFI_PORT=8443
UNIFI_USER=ubnt
UNIFI_PASS=ubnt123
UNIFI_SITE=default

# NetBox Integration
NETBOX_URL=http://localhost:8000
NETBOX_TOKEN=0123456789abcdef0123456789abcdef01234567
```

### NetBox Setup

1. Access NetBox: http://localhost:8080
2. Login with: `admin` / `admin`
3. Generate API Token:
   - Profile → API Tokens → Add Token
4. Add Devices:
   - Organization → Devices → Add Device
   - Required fields:
     - Name
     - Device Role (e.g., "switch", "router")
     - Platform (must contain "cisco", "mikrotik", or "unifi")
     - Primary IP

---

## 🧪 Testing

### Running the Test Suite

```bash
cd backend
pytest tests/ -v
```

### Manual Testing

1. **Test Device Connection**
   ```bash
   python -c "
   from app.services.device_manager import DeviceFactory
   from app.inventory.netbox_client import NetboxInventory
   
   nb = NetboxInventory()
   devices = nb.get_all_devices()
   
   for device in devices:
       print(f'Testing {device[\"name\"]}...')
       driver = DeviceFactory.get_driver(device)
       driver.connect()
       print(f'Connected successfully!')
       driver.disconnect()
   "
   ```

2. **Test Kill-Switch**
   ```bash
   curl -X POST http://localhost:8000/api/security/alert \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "device_name": "test-switch",
       "port_id": "Gi0/1",
       "threat_type": "rogue_device"
     }'
   ```

---

## 🚀 Deployment

### Development
```bash
docker-compose up -d
```

### Production

1. **Disable Mock Mode**
   ```bash
   # In .env
   MOCK_MODE=False
   ```

2. **Configure Real Device Credentials**
   ```bash
   # Update .env with actual IPs and credentials
   CISCO_IP=YOUR_CISCO_IP
   CISCO_USER=YOUR_USERNAME
   # etc...
   ```

3. **Use Production Dockerfile**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

4. **Enable HTTPS** (Recommended)
   - Add Nginx reverse proxy
   - Configure SSL certificates (Let's Encrypt)

---

## 📊 Project Structure

```
uaf/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── endpoints.py      # Main API routes
│   │   │   └── auth.py           # Authentication endpoints
│   │   ├── core/
│   │   │   ├── config.py         # Configuration management
│   │   │   └── security.py       # Security & auth utilities
│   │   ├── drivers/
│   │   │   ├── base_driver.py    # Abstraction layer
│   │   │   ├── cisco_driver.py   # Cisco implementation
│   │   │   ├── mikrotik_driver.py
│   │   │   └── unifi_driver.py
│   │   ├── inventory/
│   │   │   └── netbox_client.py  # NetBox integration
│   │   ├── services/
│   │   │   ├── device_manager.py # Device orchestration
│   │   │   ├── kill_switch.py    # Security automation
│   │   │   ├── monitor.py        # Network monitoring
│   │   │   ├── scheduler.py      # Background tasks
│   │   │   └── wol.py            # Wake-on-LAN
│   │   └── main.py               # FastAPI app entry
│   ├── logs/                     # Application logs
│   ├── tests/                    # Test suite
│   ├── .env                      # Environment config
│   ├── requirements.txt
│   └── Dockerfile
├── infra/
│   └── docker-compose.yml
└── README.md
```

---

## 🔐 Security Considerations

1. **Change Default Passwords**
   - Update default user passwords immediately
   - Use strong, unique passwords for each service

2. **API Token Security**
   - Rotate tokens regularly
   - Store tokens securely (never in code)
   - Use environment variables

3. **Network Segmentation**
   - Deploy UAF in a management VLAN
   - Restrict access to management interfaces
   - Use firewall rules

4. **Audit Logging**
   - All security events are logged
   - Review logs regularly
   - Set up log forwarding (Syslog, ELK, etc.)

---

## 🐛 Troubleshooting

### Common Issues

**1. "Connection refused" when accessing devices**
- Solution: Ensure devices are reachable and SSH/API is enabled
- Check: `MOCK_MODE=True` in .env if testing without real devices

**2. "NetBox connection failed"**
- Solution: Verify NetBox container is running: `docker ps | grep netbox`
- Check: NetBox URL and API token in .env

**3. "Port already in use" error**
- Solution: Stop conflicting services or change ports in docker-compose.yml

**4. Scheduler not running**
- Solution: Check logs: `docker-compose logs uaf-backend`
- Verify: Background scheduler started message in logs

---

## 📖 Documentation

- **API Reference**: http://localhost:8000/docs
- **NetBox Docs**: https://docs.netbox.dev/
- **Project Proposal**: See `/docs/project_proposal.pdf`

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📝 License

This project is licensed under the MIT License. See LICENSE file for details.

---

## 👨‍💻 Author

**Your Name**
- GitHub: [@yourusername](https://github.com/yourusername)
- Project Advisor: [Advisor Name]
- Institution: [University Name]

---

## 🙏 Acknowledgments

- NetBox Community
- FastAPI Framework
- Netmiko Library
- GitHub Student Developer Pack

---

**Built with ❤️ for Network Automation**
