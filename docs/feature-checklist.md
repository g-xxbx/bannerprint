# Banner 指纹识别系统 · 结构化功能清单与 MVP 边界

> v1.0 · 2026-10-22 · 依据：任务说明、示例响应、20 条自测输入
> 定位：开发排期与验收对齐的唯一事实源。**P0 = 交付门槛（MVP）**，P1 = 核心闭环通过后的增量，P2 = 明确不做。

---

## 0. 结论

MVP 是一条能自证的端到端链路：

```
JSON 文件 → client 容器 →(服务名 DNS)→ server 容器
              ↓                          ↓
        表格/JSON 输出         规则引擎(YAML) → 7 字段结果
```

**P0 必须包含 4 件事**：
1. 两个接口 + 独立 client（题目硬性要求）；
2. SSH / HTTP(nginx·Apache·Jetty) / MySQL / Redis / FTP 六族识别 + `unknown` 兜底永不崩（题目硬性要求）；
3. 规则即数据（YAML + 通用引擎，零协议专属代码）+ 双镜像 + Compose 编排（**评估者点名检查**）；
4. 容器间访问收敛、真实健康依赖、多阶段构建、权限收紧、README 自证（**评估者点名检查**）。

**明确排除在 MVP 之外**：扩展协议族、TLS 识别、指标/追踪、CI、多架构、Web UI、持久化。这些不改变架构，随时可加。

---

## 1. 判定原则

| # | 原则 | 推论 |
|---|---|---|
| P1 | 题目显式要求 + 评估显式考察 → P0，不计成本 | 接口、字段、unknown、Compose、健康检查、权限、解耦 |
| P2 | 隐含的"崩掉"风险 → P0（成本低、伤害大） | 畸形 JSON、`\xNN` 非法转义、二进制 banner、缺字段、超长 |
| P3 | 只影响"更准/更多"，不影响"能跑通、能验收" → P1 | 拓展协议、证据字段、指标 |
| P4 | 需要新外部依赖或改变架构形态 → P2 | DB、队列、k8s、Web UI |
| P5 | P1 必须能被 P0 的架构容纳 | 规则即数据 ⇒ 加协议只改 YAML，不改代码 |

---

## 2. 需求解构（来源 → 落地）

| 编号 | 来源 | 要求 | 落地 |
|---|---|---|---|
| R1 | 要求 1 | `POST /fingerprint` 批量、`GET /health` | F01 / F02 |
| R2 | 要求 1 | client 独立程序，读本地 JSON、发请求、展示 | F18 |
| R3 | 要求 2 | 7 字段 + confidence 0~1 | F03 |
| R4 | 要求 2 | 认不出 → `protocol:"unknown"`，不报错不崩 | F03 / F04 |
| R5 | 要求 3 | SSH、HTTP(nginx/Apache/Jetty)、MySQL、Redis、FTP | F06–F11 |
| R6 | 要求 4 | Compose 一键；访问收敛；真实健康依赖；编译打包；权限收紧；规则解耦 | F15–F19 |

---

## 3. 关键设计决策（决定清单切分）

| # | 决策 | 理由 | 影响 |
|---|---|---|---|
| D1 | **规则即数据**：单个通用正则引擎按原始字节匹配，YAML 声明 `match / fields / confidence` | 加协议=加 YAML；文本与二进制同引擎（Go RE2 支持 `\x00`、字节类） | F06 是最大工作量，也是解耦证据 |
| D2 | **输入宽容优先**：严格解析失败 → 修复 `\xNN` 转义 → 再解析 → 仍失败才 400 | 样例里 `"J\x00\x00\x00\n8.0.32\x00"` 不是合法 JSON 转义 | F04 |
| D3 | **健康检查用二进制自探针**：`server healthcheck` 子命令 | scratch/distroless 无 shell、无 curl/wget | F14 / F16 |
| D4 | **端口只作弱先验**：不建端口→协议硬映射，443 也给 `HTTP` | 示例 443→HTTP、8443→nginx；端口会骗人 | F12 |
| D5 | **置信度 = 证据分级 + 规则覆盖**：协议 0.5 / +产品 0.7 / +版本 0.9 / +OS 佐证 0.95 / unknown 0.1 | 精确复现示例（Redis 0.7、Jetty 0.85、SSH 0.95） | F13 |
| D6 | **规则双源**：`go:embed` 内置 + `RULES_DIR` 只读挂载覆盖 | 镜像自包含，又能"改规则不重建镜像" | F06 / F16 |

---

## 4. P0 · MVP 必须（22 项）

### A. 接口与契约

| ID | 能力 | 验收口径 | 复杂度 |
|---|---|---|---|
| F01 | `POST /fingerprint` 批量识别 | 收裸数组（兼容 `{"items":[...]}`）；返回**等长、保序**数组；200 + `application/json`；body ≤ 8MB、≤ 10000 条；超限 413 | M |
| F02 | `GET /health` | 200 + `{"status":"ok","version":…,"rules":N,"uptime_s":…}`；规则未加载返回 503 | S |
| F03 | 结果契约 | 7 字段齐全、`port` 为数字、`confidence∈[0,1]`；未知项 `protocol:"unknown"`、product/version/os_hint 为空、confidence 0.1 | S |
| F04 | 容错 / 不崩 | 空 banner、二进制、非法 UTF-8、缺字段、超长、`\xNN` 转义 → 一律 unknown 且 200；单条 panic 隔离；非法 JSON → 400 结构化错误（不 500、不泄栈） | M |
| F05 | 确定性 | 同输入同输出；规则按 priority 稳定排序；无跨请求可变状态 | S |

### B. 识别能力

| ID | 能力 | 验收口径 | 复杂度 |
|---|---|---|---|
| F06 | 通用规则引擎（数据驱动） | YAML 字段：id/protocol/priority/match(原始字节正则)/fields(product,version,os_hint)/confidence 覆盖；启动校验，坏规则 fail-fast；`-list-rules` 可查；**代码中无任何协议分支** | L |
| F07 | SSH | `OpenSSH_8.9p1 Ubuntu-3`→8.9p1+Ubuntu；`9.3 Debian-1`→9.3+Debian；`SSH-1.99-OpenSSH_4.3`→4.3、os 空 | S |
| F08 | HTTP | 状态行可缺省；header 名大小写不敏感；`Server:` 解析 nginx/Apache/Jetty（含 IIS）；版本；`(Ubuntu)`→os_hint；无 Server 头 → protocol=HTTP、product 空、0.5 | M |
| F09 | MySQL | 二进制握手（3B 长度 + seq + `0x0A` + 版本）与纯文本形态；8.0.32 / 5.7.42 | M |
| F10 | Redis | `-ERR` / `+PONG` / `-NOAUTH` / `*` / `$` 内联应答；product=Redis、version 空、0.7 | S |
| F11 | FTP | `220` 应答；ProFTPD / vsFTPd / Pure-FTPd；版本可缺省（缺省降置信度） | S |
| F12 | 冲突消解 | 二进制探测优先于文本；端口仅弱先验；避免 HTTP 规则吞掉 SSH 文本 | S |
| F13 | 置信度模型 | 证据分级 + 规则覆盖（Jetty 0.85）；README 给出对照表 | S |

### C. 交付与部署

| ID | 能力 | 验收口径 | 复杂度 |
|---|---|---|---|
| F14 | 双程序 | `cmd/server`、`cmd/client` 独立二进制；`-version`、`server healthcheck` 子命令 | S |
| F15 | 镜像工程 | 多阶段 build；`CGO_ENABLED=0`；`-trimpath`；`-ldflags "-s -w -X main.version=…"`；go.mod/go.sum 先行以复用缓存；`.dockerignore`；scratch/distroless；`USER 65532`；单镜像 < 30MB | M |
| F16 | Compose 编排 | server `healthcheck` 探 `/health`；client `depends_on: condition: service_healthy`；client 用 `http://server:8080`；**仅 server 发布端口**；单一自定义网络；`restart: unless-stopped` | M |
| F17 | 权限收紧 | `read_only` + `tmpfs:/tmp` + `cap_drop: ALL` + `no-new-privileges` + 非 root + `pids_limit` + 内存/CPU 限制 + `init` + `stop_grace_period` | S |
| F18 | client | `-file/-server/-json/-timeout`；读本地 JSON；表格与 JSON 双输出；连接失败退避重试 3 次；退出码 0/1/2 | M |
| F19 | 一键启动 | `docker compose up` 即：server 起 → 健康 → client 识别 → 打印结果；内置 `data/sample.json` | S |

### D. 文档与质量

| ID | 能力 | 验收口径 | 复杂度 |
|---|---|---|---|
| F20 | README + 决策记录 | 架构图、API 示例、规则编写指南、安全基线、验证步骤、置信度表、取舍与已知边界 | M |
| F21 | 测试 | 表驱动覆盖 20 条样例 + 边界（空/二进制/超长/乱码/缺字段）；`httptest` 覆盖 handler；`go vet` 通过 | M |
| F22 | 运维性 | slog JSON 日志 + 请求 ID + 访问日志；读写超时；优雅退出；`/health` 带版本与规则数 | S |

---

## 5. P1 · 核心闭环后集成（按性价比排序）

| 组 | 内容 | 增量成本 | 价值 |
|---|---|---|---|
| 协议扩展 | SMTP / IMAP / POP3 / Telnet / PostgreSQL / MongoDB / Memcached / Elasticsearch / SMB / RDP | 纯 YAML | 高（隐藏数据很可能含） |
| 产品扩展 | IIS / Caddy / Tomcat / lighttpd / MariaDB / Percona / Dropbear / libssh / FileZilla / Serv-U / MinIO / RabbitMQ | 纯 YAML | 高 |
| TLS | ClientHello/ServerHello 识别、TLS 版本、SNI/ALPN、证书 CN（自测第 16 条） | 1 条规则 + 小解析 | 中高（自测已出现） |
| HTTP 增强 | 全量 header 提取、`X-Powered-By`、title/favicon 指纹、HTTP/2 preface | 中 | 中 |
| 可解释性 | 结果附 `evidence`（命中 rule_id + 片段）、banner 摘要；开关控制不破坏 7 字段契约 | 中 | 中高（演示加分） |
| 输入增强 | base64 banner、port 字符串、CRLF/LF 混用、超长截断策略 | 小 | 中 |
| client 增强 | 目录批量、CSV/NDJSON 输出、分块上传、并发、`--fail-fast` | 中 | 中 |
| 规则工程 | SIGHUP 热加载、`-validate-rules`、规则覆盖率报告 | 中 | 中（"解耦"叙事更强） |
| 可观测性 | `/metrics`、pprof（debug tag）、trace id 透传 | 中 | 低中 |
| CI/供应链 | GitHub Actions（vet/test/build）、golangci-lint、trivy/SBOM、多架构 buildx、镜像签名 | 中 | 中（"生产级"加分） |
| 安全增强 | API Key / mTLS、限流、CORS、请求压缩、自定义 seccomp | 中 | 低中（默认网络已收敛） |
| 性能 | benchmark、worker pool、buffer 复用 | 小 | 低 |

> 时间允许时，**TLS + 3~5 个协议族**优先并入（都只是 YAML）。

---

## 6. P2 · 明确不做

Web UI、数据库持久化、任务队列、资产 diff、分布式 worker、Kubernetes/Helm、WASM/Lua 规则插件、多租户与鉴权体系、i18n。

---

## 7. 自测数据期望矩阵（P0 自检基线）

| # | ip:port | protocol | product | version | os_hint | conf |
|---|---|---|---|---|---|---|
| 1 | 1.2.3.4:22 | SSH | OpenSSH | 8.9p1 | Ubuntu | 0.95 |
| 2 | 1.2.3.5:80 | HTTP | nginx | 1.24.0 | | 0.90 |
| 3 | 1.2.3.6:443 | HTTP | Apache | 2.4.57 | | 0.90 |
| 4 | 1.2.3.7:3306 | MySQL | MySQL | 8.0.32 | | 0.90 |
| 5 | 1.2.3.8:6379 | Redis | Redis | | | 0.70 |
| 6 | 1.2.3.9:21 | FTP | ProFTPD | 1.3.7 | | 0.90 |
| 7 | 1.2.3.10:8080 | HTTP | Jetty | 9.4.51 | | 0.85 |
| 8 | 1.2.3.11:22 | SSH | OpenSSH | 9.3 | Debian | 0.95 |
| 9 | 1.2.3.12:80 | HTTP | nginx | 1.18.0 | Ubuntu | 0.90 |
| 10 | 1.2.3.13:443 | HTTP | Apache | 2.4.41 | Ubuntu | 0.90 |
| 11 | 1.2.3.14:3306 | MySQL | MySQL | 5.7.42 | | 0.90 |
| 12 | 1.2.3.15:6379 | Redis | Redis | | | 0.70 |
| 13 | 1.2.3.16:21 | FTP | vsFTPd | 3.0.5 | | 0.90 |
| 14 | 1.2.3.17:8443 | HTTP | nginx | 1.25.3 | | 0.90 |
| 15 | 1.2.3.18:22 | SSH | OpenSSH | 4.3 | | 0.90 |
| 16 | 1.2.3.19:9999 | TLS | | | | 0.60 |
| 17 | 1.2.3.20:8888 | HTTP | Microsoft-IIS | 10.0 | | 0.90 |
| 18 | 1.2.3.21:6379 | Redis | Redis | | | 0.70 |
| 19 | 1.2.3.22:21 | FTP | Pure-FTPd | | | 0.70 |
| 20 | 1.2.3.23:12345 | unknown | | | | 0.10 |

**注意**：
- 443/8443 也输出 `HTTP`（与示例一致，不因端口改成 HTTPS）。
- Jetty 0.85 与 nginx 0.90 的差异只能由"规则级置信度覆盖"表达，不能用全局公式。
- 第 19 条无版本 → 产品级 0.70；与 Redis 同级，保持一致。
- 第 16 条为 TLS ClientHello（`16 03 01` + `0x01`）；默认实现为 P1，若时间不足则落 unknown（题目允许）。

---

## 8. 评估者检查点 ↔ 交付证据

| 考察点 | 做法 | 证据位置 |
|---|---|---|
| 容器间访问收敛 | client 只用服务名 `http://server:8080`（可被 `FP_SERVER_URL` 覆盖）；单一自定义网络；不支持 `host.docker.internal`/`links`/静态 IP；仅 server 对外发布端口 | `compose.yaml` + README"网络模型" |
| 启动依赖真实健康 | Dockerfile/compose `healthcheck` 调 `/health`（二进制自探针）；`depends_on: service_healthy`；client 侧退避重试兜底 | `compose.yaml`、`cmd/server` |
| 镜像编译打包 | 多阶段、静态二进制、ldflags 注入版本、依赖层缓存、`.dockerignore`、distroless/scratch、非 root、体积数据 | `Dockerfile.*` + README"构建" |
| 运行权限收紧 | read_only、tmpfs、cap_drop ALL、no-new-privileges、非 root、pids/mem/cpu 限制、init | `compose.yaml` |
| 规则/代码解耦 | `rules/*.yaml` + 通用引擎；embed 内置 + RO 挂载覆盖；`-list-rules`；README 教"如何加一个协议" | `internal/rules`、`rules/` |

---

## 9. 30 分钟时间盒

| 时段 | 内容 | 退出条件 |
|---|---|---|
| 0–3 | 脚手架、契约类型、`/health` | `go build` 通过 |
| 3–12 | 规则引擎 + 6 个 YAML + 引擎单测 | 20 条样例单测全绿 |
| 12–17 | handler（容错/错误契约/日志/超时/优雅退出）+ client | 本地 `go run` 打通 |
| 17–21 | Dockerfile×2 + compose + `.dockerignore` + 内置数据 | 镜像可构建 |
| 21–25 | `docker compose up` 实测 + 修偏差 + README | 一键输出符合矩阵 |
| 25–30 | git init/commit + 建仓 + push | GitHub 可克隆 |

**熔断**：T+25 若实测未过，先推可用版本再迭代；文档与容器细节优先级高于协议扩展。

---

## 10. 风险与对策

| 风险 | 概率 | 对策 |
|---|---|---|
| 样例 JSON 含 `\xNN` 非法转义导致整批 400 | 高 | 严格解析失败 → 转义修复重试 → 单条降级（F04） |
| scratch 无 shell 导致健康检查不可用 | 高 | 二进制自探针子命令（D3） |
| 首次拉取 golang 基础镜像慢 | 中 | 提前 `docker pull`；构建与写文档并行 |
| 无 GitHub 凭据无法推送 | 高 | 需 PAT；否则交付本地 git bundle |
| 产品名大小写/别名与验收不一致（vsftpd/vsFTPd、IIS/Microsoft-IIS） | 中 | 规则内建别名表 + 统一词表 |
| 隐藏数据含未覆盖协议 | 高 | unknown 兜底；YAML 可增量扩展 |
| confidence 期望有容差或与示例不同 | 中 | 严格对齐示例反推分级 |

---

## 11. 开工前需要的输入

1. GitHub 仓库：`owner/name`（或授权我用 API 创建）；
2. 仓库可见性：建议 public（评估者离线克隆）；
3. 凭据：`GITHUB_TOKEN`（repo 权限），通过环境变量注入，不写入代码/日志。

> 当前环境：Go 1.23.11、Docker 28.3.0、Compose v2.38.1 可用；`gh` 未安装，将改用 GitHub REST + `git push`。
