UAF — Cloud Deployment & Tailscale Mesh (Report 4.3)
====================================================

GOAL
----
Run the UAF engine (backend + frontend, optionally NetBox) on a cloud VM, and
let it reach the physical lab devices (Cisco / MikroTik / UniFi) that sit
behind a home or campus NAT — without port-forwarding anything. A Tailscale
mesh provides that bridge.

    [ Cloud VM ]                                 [ Lab 192.168.1.0/24 ]
      backend ──┐                                  ┌── Cisco    .10
      frontend  ├── tailscale sidecar ◀── tailnet ─┤── MikroTik .20
      (netbox)──┘     (uaf-cloud)                   └── UniFi    .30
                                                    ▲
                                          lab subnet router
                                       (advertises 192.168.1.0/24)


PREREQUISITES
-------------
- A cloud VM (Ubuntu) with Docker + the Docker Compose plugin.
- A Tailscale account (free tier is fine).
- One always-on machine ON the lab network (a Pi, the lab PC, or the MikroTik
  itself) to act as the Tailscale "subnet router".


STEP 1 — Lab side: advertise the device subnet
-----------------------------------------------
On the always-on lab machine:

    curl -fsSL https://tailscale.com/install.sh | sh
    sudo tailscale up --advertise-routes=192.168.1.0/24

Then in the Tailscale admin console (Machines -> that node -> Edit route
settings) APPROVE the 192.168.1.0/24 route. This is what makes the lab subnet
reachable from the rest of the tailnet.


STEP 2 — Cloud side: configure and bring up
-------------------------------------------
On the cloud VM, in the repo root:

    cp .env.prod.example .env.prod
    # then edit .env.prod:
    #  - set JWT_SECRET_KEY  (python -c "import secrets; print(secrets.token_urlsafe(48))")
    #  - set TS_AUTHKEY      (Tailscale admin -> Settings -> Keys -> generate; reusable or ephemeral)
    #  - set PUBLIC_API_BASE (e.g. http://uaf-cloud:8000/api)
    #  - fill in the device IPs/credentials as reachable over the tailnet
    #  - MOCK_MODE=False

    docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build

The `tailscale` sidecar joins the tailnet as `uaf-cloud` and (via
`--accept-routes`) accepts the lab subnet. The `backend` container shares that
sidecar's network namespace, so when it SSHes to 192.168.1.10 or hits the UniFi
controller on 192.168.1.30, the traffic routes over the mesh to the lab subnet
router and on to the device.


STEP 3 — Verify the mesh
------------------------
    # Is the cloud node on the tailnet and does it see the lab route?
    docker compose -f docker-compose.prod.yml exec tailscale tailscale status

    # Can the backend reach a device over the mesh?
    docker compose -f docker-compose.prod.yml exec tailscale ping -c2 192.168.1.10

    # API + live alert channel up?
    curl http://<vm-ip-or-tailnet-name>:8000/api/health


STEP 4 — Use it
---------------
- Console:  http://<vm>:3000   (sign in: admin / admin123 — change in prod)
- API docs: http://<vm>:8000/docs
- The Dashboard's REAL-TIME ALERTS card streams over the WebSocket channel
  (/api/ws/events) — threats, port actions, and device-status changes appear
  the instant they happen (Report 4.7).


NOTES
-----
- NetBox is optional here. To use an existing NetBox, set NETBOX_URL/NETBOX_TOKEN
  in .env.prod. To run it in-stack, uncomment the netbox services in the compose
  file. With neither, the backend uses its built-in inventory.
- Security: change the default admin password, keep .env.prod out of git, and
  scope the Tailscale auth key (ephemeral keys auto-expire). Consider Tailscale
  ACLs so only the cloud node can reach the lab subnet.
- This file documents the deployment; the actual cloud VM + tailnet must be
  provisioned by hand (that part is ops, not code).
