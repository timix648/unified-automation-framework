# UAF — Unified Automation Framework

A vendor-agnostic network automation framework that unifies Cisco IOS, MikroTik
RouterOS, and Ubiquiti UniFi under a single control plane. UAF translates one
high-level administrative intent into the vendor-specific commands each device
requires, and adds an automated security kill-switch, time-based access
scheduling, and continuous monitoring on top of a NetBox source of truth.

The framework has been validated against live hardware: a Cisco Catalyst 2960
switch, a MikroTik router, and a self-hosted UniFi controller with a real access
point, all managed concurrently from one interface.

## What problem it solves

A network built from multiple vendors forces an administrator to operate three
separate, incompatible management tools — the Cisco CLI, MikroTik's Winbox/API,
and the UniFi controller — none of which talk to each other. Routine cross-vendor
operations (provision a network segment, enforce an access window, isolate an
intruder) become three manual jobs in three different syntaxes, repeated daily.

UAF is the unified Day-1 operations layer above those silos. After each device is
made reachable once (Day-0 bootstrap), UAF orchestrates ongoing operations across
all vendors from one console, automatically and at scale.

## Core capabilities

Vendor-agnostic abstraction layer. A single intent ("create network segment X")
is translated into a VLAN and port assignment on Cisco (via Netmiko/SSH), a DHCP
pool and network on MikroTik (via the RouterOS API), and a Wi-Fi SSID on UniFi
(via its REST API). Provisioning and de-provisioning both run as one action
across all three vendors.

Automated kill-switch security module. A scheduled scan reads each switch's MAC
address table and compares it against the authorized registry. The framework
operates in two phases: a learning phase that detects and reports unrecognized
devices without disruption, and an armed phase the administrator explicitly
activates, after which unauthorized devices have their switch port shut down
automatically. Every action is recorded to an audit trail.

Time-based access control scheduler. One administrator-defined access window is
enforced across all vendors simultaneously — time-based ACLs on Cisco, firewall
filter rules on MikroTik, and SSID schedules on UniFi — with Wake-on-LAN support
for waking managed hosts.

Single source of truth. NetBox holds the network inventory (devices, addresses,
per-device credentials). UAF reads inventory dynamically from NetBox, with a JSON
file as an offline development fallback.

REST API, RBAC, and operations console. A FastAPI backend exposes the framework
through a documented REST API with JWT authentication and three roles (admin,
operator, viewer). Accounts are administrator-provisioned — there is no
self-service registration, appropriate for a privileged network tool. A Reflex
operations console provides the dashboard, device inspection, provisioning,
security, scheduling, and audit views.

Uplink discovery instead of hardcoded ports. The trunk uplinks to the router and
the access point are resolved at run time from the switch itself rather than read
from configuration: neighbouring devices are located through CDP where they
advertise it, and through the switch's MAC address table where they do not
(Ubiquiti access points, for instance, do not speak CDP). A hardcoded port fails
silently when equipment is re-cabled — the framework configures an empty port and
still reports success — so configuration is treated as a hint and the switch is
believed over it. This has been verified by moving all three devices to different
ports without updating any configuration; provisioning located each of them and
completed with every step successful.

Concurrent network segments. Because the uplink to the access point is trunked
rather than placed in a segment's VLAN, one access point serves several isolated
networks simultaneously, each SSID tagged into its own VLAN while the access
point keeps its own management address on the untagged VLAN. Two segments have
been run concurrently on one access point, with clients on each receiving
addresses from separate DHCP pools.

## Architecture

```
                         Reflex Operations Console
                                    |
                          FastAPI Backend (REST)
        ____________________________|____________________________
       |            |            |            |                   |
   API/Auth    Kill-Switch    Monitor     Scheduler        User/RBAC
       |____________|____________|____________|___________________|
                    Vendor-Agnostic Abstraction Layer
              ___________________|___________________
             |                   |                   |
        Cisco Driver      MikroTik Driver       UniFi Driver
        (Netmiko/SSH)     (RouterOS API)        (REST API)
             |                   |                   |
        Catalyst 2960      MikroTik Router     UniFi Controller + AP
                    |
            NetBox (Source of Truth) + PostgreSQL + Redis
```

## Technology

Backend: Python, FastAPI, Uvicorn. Drivers: Netmiko (Cisco), RouterOS API
(MikroTik), Requests (UniFi REST). Frontend: Reflex. Inventory: NetBox. Supporting
services: PostgreSQL, Redis. Containerization: Docker Compose.

## Repository layout

```
backend/
  app/
    api/endpoints.py          REST API routes
    core/                     config, security/JWT, SNMP, Nornir manager
    drivers/                  base_driver + cisco/mikrotik/unifi drivers
    inventory/                netbox_client, authorized_registry
    services/                 device_manager, kill_switch, monitor,
                              scheduler, enforcement_state, wol
    main.py                   FastAPI entry point
  scripts/seed_netbox.py      seeds NetBox with the device inventory
  tests/                      test suite
frontend/
  frontend/frontend.py        Reflex operations console
infra/
  docker-compose.yml          full stack (backend, frontend, NetBox, DB, cache)
docker-compose.prod.yml       production stack
```

## Running it

The recommended development setup runs NetBox, PostgreSQL, and Redis in Docker,
while the backend and frontend run locally so the backend can reach physical
devices on the LAN directly.

Prerequisites: Python 3.11+ (the project has been run on 3.14), Docker Desktop,
and Git.

1. Configure environment.

   ```
   cd backend
   cp .env.example .env
   ```

   Edit `.env` with the device addresses, credentials, and the NetBox URL/token.
   Set `MOCK_MODE=False` to talk to real hardware.

2. Start the inventory and data services in Docker.

   ```
   docker compose -f infra/docker-compose.yml up -d netbox postgres redis
   ```

   Wait for NetBox to finish initializing, then confirm it answers at
   `http://localhost:8080`.

3. Seed the inventory.

   ```
   cd backend
   python scripts/seed_netbox.py
   ```

4. Start the backend (locally, for LAN access to devices).

   ```
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

5. Start the frontend (locally), pointing it at the local backend.

   ```
   cd frontend
   python -m reflex run --backend-port 8001
   ```

   Open the console at `http://localhost:3000`. The frontend defaults to a
   backend on `http://localhost:8000/api`; set `API_BASE` only if yours differs
   (`$env:API_BASE = "..."` in PowerShell, `export API_BASE=...` on a shell).
   Reflex needs its own port for the state channel, which is what
   `--backend-port` supplies; it is unrelated to the UAF API on port 8000.

For a fully containerized deployment (for example on a VPS), build and start the
whole stack from the repository root:

```
docker compose -f infra/docker-compose.yml up -d --build
```

The `--build` flag is important — it rebuilds the backend image from the current
source so the running container never serves stale code.

## Authentication

The framework ships with three default roles. Passwords should be changed for any
real deployment, and additional accounts are created by an administrator under
Settings, not through self-service registration.

| Username  | Role     | Access                  |
|-----------|----------|-------------------------|
| admin     | Admin    | Full access             |
| operator  | Operator | Read and execute        |
| viewer    | Viewer   | Read only               |

Obtain a token by posting credentials to `/api/auth/login`, then send it as a
bearer token on subsequent requests. Interactive API documentation is available
at `/docs` (Swagger UI) and `/redoc` while the backend is running.

## Selected API endpoints

Device management: `GET /api/devices`, `GET /api/devices/{name}/interfaces`,
port enable/disable.

Security: `POST /api/security/scan`, `GET /api/security/threats`,
`GET/POST /api/security/enforcement` (learning/armed).

Provisioning: `POST /api/provision/network`, `POST /api/provision/deprovision`,
`GET /api/provision/segments`.

Scheduling and power: scheduler status and policy, time-based enforcement,
Wake-on-LAN.

Monitoring: `GET /api/monitor/network-health`.

User management (admin only): list, create, and remove accounts.

## Configuration

Configuration is supplied through `backend/.env`. A template is provided as
`.env.example`. The key groups are system settings (including `MOCK_MODE`),
per-vendor device addresses and credentials, the UniFi controller port and site,
and the NetBox URL and API token. Secrets are never committed to the repository.

Uplink ports may be supplied as `AP_UPLINK_PORT` and `ROUTER_UPLINK_PORT`, but
they are a last-resort fallback rather than the mechanism: the ports are
discovered from the switch, and a stale value is detected and overridden rather
than obeyed.

## Known constraints

These are properties of the equipment rather than defects in the framework, but
they shape what to expect when running it against hardware of this vintage.

The Catalyst 2960 grants approximately one usable SSH session at a time, so
provisioning holds a single session across all its phases, and an administrative
operation issued while a scheduled scan is still running will spend time
recovering the session before it can proceed. Pausing background jobs prevents
new ones from starting but cannot recall a scan already in progress.

Timings vary with the switch rather than with the work. A full provisioning run
across all three vendors has been measured between 73 and 140 seconds, and
de-provisioning between 45 and 68 seconds, for identical operations. Every read
and connect timeout is configurable through the environment so the same code can
run on a local network or across a high-latency link.

The switch's SSH implementation predates the algorithms modern client libraries
negotiate by default, and the RouterOS installation uses the login exchange
superseded at version 6.43. Both are handled in the drivers at run time, so
neither device needs a firmware upgrade in order to be managed.

## Security notes

Default passwords must be changed before any real use. API tokens are read from
the environment and never stored in code. The framework is intended to run inside
a management network with restricted access to device management interfaces. All
security-relevant actions — provisioning, port shutdowns, enforcement changes,
and account changes — are written to the audit log.

## License

Released under the MIT License. See the LICENSE file for details.