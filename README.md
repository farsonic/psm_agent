# PSM eBPF Agent

`agent.py` is a lightweight eBPF-based telemetry agent for Linux to send updated into PSM as a workload object. It observes live network activity on the host directly in the Kernel, enriches it with userland metadata (user, process, IP, direction, etc.), and reports the summarized activity to PSM via labeled payloads. The update interval can be set in the configuration file as well as additional timers and tiering labels. 

This is a proof of concept to see how eBPF integrates with the Linux Kernel and userland tools. 

---

## 🚀 Features

- 🧠 Real-time connection tracking using eBPF
- 📤 Inbound/outbound user+process+port labeling
- ⚠️ Suspicious binary detection (outside `/usr/bin`, `/usr/sbin`) - Work in Progress 
- 🧠 System metadata: hostname, kernel, uptime, heartbeat, role, status, version, checksum
- 🗂 Label grouping by user + direction
- 🧊 Redis-backed TTL cache to reduce noise
- 🔄 Periodic push to `/configs/workload/...` endpoint on PSM
- 🔧 Configurable behavior via `config.json`

---

## 📦 Requirements

| Requirement | Notes |
|-------------|-------|
| **Ubuntu Server 20.04+** | 22.04 or greater recommended |
| **Linux Kernel 5.15+**   | Needed for BPF features |
| **Python 3.8+**          | Runtime |
| **Redis**                | In-memory event tracking |
| **BCC**                  | eBPF/BPF tracing support |

---

## 🛠 Installation Guide

Clone this repo into /opt on your Linux server. 

### ✅ 1. Check/Upgrade Kernel

```bash
uname -r
```

If the version is below `5.15.x`, run the following to upgrade the kernel to the latest generic kernel. I suggest running latest kernel if you are 
testing eBPF as there is ongoing updates to this capability. 

```bash
# For Ubuntu 20.04 LTS
sudo apt update
sudo apt install linux-image-generic-hwe-20.04
sudo reboot
```

Then confirm:

```bash
uname -r
```

---

### 📦 2. Install Required Packages

```bash
sudo apt update
sudo apt install -y \
  redis-server \
  python3 python3-pip \
  gcc make \
  libelf-dev libbpf-dev \
  bpfcc-tools linux-headers-$(uname -r) \
  python3-bcc
```

---

### 🐍 3. Install Python Libraries

I had to install these using sudo as eBPF via BCC requires root access for kernel socket hooks. 

```bash
sudo pip3 install --upgrade pip
sudo pip3 install redis requests
```

---

### 🚦 4. Enable and Start Redis

```bash
sudo systemctl enable redis
sudo systemctl start redis
```

---

### ⚙️ 5. Create `config.json`

This config should sit in the **same directory** as `agent.py`, which will most likely be /opt/psm-agent. Ensure that you have
correctly entered the psm IP Address, username and password. 

Change the hostip to be that of the host you are administering and the spec-hostname should be a dummy host that already exists within
PSM. 

```json
{
  "psmipaddress": "10.0.0.5",
  "psmusername": "admin",
  "psmpassword": "changeme",
  "hostip": "10.0.0.25",
  "hostname": "my-host-001",
  "spec_hostname": "dummy",
  "enable_suspicious_binary_labels": true,
  "ttl_seconds": 3600,
  "summary_interval": 25,
  "role": "backend",
  "status": "prod"
}
```

---

### ▶️ 6. Run the Agent

```bash
chmod +x agent.py
./agent.py --debug
```

You should start seeing:

```text
[DEBUG] New connection: out:root:curl:443 from 10.0.0.25
[DEBUG] PUT https://<psm>/configs/workload/v1/... 200 OK
```

---

## ⚙️ Optional: Run on Boot (systemd)

Create a service file:

```bash
sudo vi /etc/systemd/system/psm-agent.service
```

Paste:

```ini
[Unit]
Description=PSM Agent
After=network.target redis.service

[Service]
Type=simple
WorkingDirectory=/opt/psm-agent
ExecStart=/usr/bin/python3 agent.py
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

Enable the service:

```bash
sudo systemctl daemon-reexec
sudo systemctl enable psm-agent
sudo systemctl start psm-agent
```

---

## 🧪 What It Tracks

The agent observes TCP connections via eBPF and pushes summarized labels such as:

- `user:root --> Outbound Traffic` → outbound connections
- `user:root <-- Inbound Traffic` → incoming sessions
- `user:suspicious:root` → binary not in trusted locations

Also includes system metadata for host visibility.

---

## 🧾 Example Label Payload (sent to PSM)

```json
{
  "user:root --> Outbound Traffic": "curl:443 wget:80",
  "user:root <-- Inbound Traffic": "sshd:22",
  "user:suspicious:root": "tmp_binary:8080",
  "agent_version": "1.0.0",
  "agent_checksum": "cdaf7a0a4c1f2f...<sha256>",
  "uptime": "2d 6h 30m",
  "heartbeat": "0y 0d 0h 21m 42s",
  "hostname": "my-host-001",
  "kernel_version": "5.15.0-91-generic",
  "ip_address": "10.0.0.25",
  "role": "backend",
  "status": "prod"
}
```

---

## 🐞 Debugging

Run the agent in debug mode:

```bash
./agent.py --debug
```

You’ll see live connections, Redis key entries, and PSM HTTP interactions.
```
redis-cli keys "*"
redis-cli ttl <Key> 
```

---

## 🔐 Security Tips

- Create a dedicated user in PSM that has a role assignment that only allows workload creation and updates. 

---

## 🧠 Why This Agent?

This tool gives you deep visibility into:

- Which users are making network connections
- What binaries are involved
- How hosts behave in different environments (via `role` / `status`)
- Agent uptime and system health reporting

---

## 📄 License

MIT — feel free to fork, improve, and submit PRs.

---

## 💬 Questions?

Open an issue 

Not currently tested for production use 

Feedback appreciated 
