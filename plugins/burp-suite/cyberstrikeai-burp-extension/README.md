## CyberStrikeAI Burp Suite Extension

中文说明见：`README.zh-CN.md`

### What it does

- Configure **Host / Port / HTTPS / Password** and choose an agent mode
- Click **Validate** to login (`POST /api/auth/login`) and verify token (`GET /api/auth/validate`)
- Right-click any HTTP message in Burp and send it to CyberStrikeAI for **streaming web pentest** (agent modes: **Eino Single**, Deep, Plan-Execute, Supervisor — maps to `/api/eino-agent/stream` or `/api/multi-agent/stream`)
- Keep a **test history sidebar** (searchable) so you can revisit previous runs
- Output is split into **collapsible Progress** + **Final Response** (Markdown rendering supported)
- View captured **Request / Response** for each run
- **Stop** a running task (calls `/api/agent-loop/cancel` once `conversationId` is available)

### Build

Requirements:

- JDK 11+
- Maven (recommended) OR Burp Extender API jar (offline mode)

#### Option A (recommended): Maven build (no need to locate Burp)

```bash
cd plugins/burp-suite/cyberstrikeai-burp-extension
./build-mvn.sh
```

Output:

- `dist/cyberstrikeai-burp-extension.jar`

#### Option B: Offline build with `build.sh` (needs Burp API jar)

1) Create `lib/` and copy Burp's API jar into it:

```bash
mkdir -p lib
# copy from your Burp installation, for example:
# cp "/path/to/burp-extender-api.jar" lib/
```

2) Build:

```bash
cd plugins/burp-suite/cyberstrikeai-burp-extension
./build.sh
```

Output:

- `dist/cyberstrikeai-burp-extension.jar`

#### Option C: Gradle (optional)

If you already have Gradle available, you can still use `build.gradle` to build.

### Load in Burp Suite

- Burp Suite → **Extensions** → **Installed** → **Add**
- Extension type: **Java**
- Select the jar above

### Notes

- Default connection is `https://127.0.0.1:8080` (**HTTPS** checked). Self-signed / local certs are trusted automatically (no import).
- Uncheck **HTTPS** only if your server runs plain HTTP.
- It uses **Bearer Token** authentication obtained from the configured password.

