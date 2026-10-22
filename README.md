# Banner 指纹识别系统

接收网络扫描原始数据（`ip` / `port` / `banner`），识别协议、软件与版本，输出
`ip, port, protocol, product, version, os_hint, confidence`。

采用 **client + server** 架构，`docker compose up` 一键启动。

> 当前阶段：**架构与骨架已锁定**，识别规则与测试正在填充（见文末「实施状态」）。

---

## 1. 架构

```
               本地 JSON 文件
                     │
                     ▼
        ┌───────────────────────┐
        │  client 容器          │  一次性任务，无端口暴露，非 root
        │  cmd/client           │
        └───────────┬───────────┘
                    │  POST /fingerprint
                    │  http://server:8080   ← 只走服务名，不碰宿主机端口
                    ▼
        ┌───────────────────────┐
        │  server 容器          │  :8080 是唯一对外端口
        │  cmd/server           │
        │  ┌─────────────────┐  │
        │  │ 规则引擎 (通用) │◀─┼── rules/*.yaml（内置 embed + 只读挂载覆盖）
        │  └─────────────────┘  │
        └───────────────────────┘
```

**关键约束**

- 只有 `server` 发布端口；`client` 通过 compose 内网服务名访问。
- 服务启动顺序由**真实健康检查**保证（`condition: service_healthy`），而不是 `sleep`。
- 识别规则是数据，不是代码：新增协议只改 YAML。

## 2. 目录结构

```
cmd/server            # HTTP 服务：/fingerprint、/health、healthcheck 子命令
cmd/client            # 读文件 → 调服务 → 表格/JSON 输出
internal/fingerprint  # 规则模型 + 引擎（通用匹配、置信度、panic 收敛）
internal/ingest       # 输入解析（裸数组 / 包装对象 / \xNN 非法转义修复）
internal/httpapi      # 路由、中间件（请求 ID、访问日志、panic 兜底）、错误契约
rules/                # YAML 规则（go:embed，也可被只读挂载覆盖）
docker/               # 两个多阶段 Dockerfile（运行期 scratch）
data/sample.json      # 自测数据
compose.yaml          # 一键启动 + 安全基线
```

## 3. 快速开始

```bash
docker compose up --build
```

预期：`server` 通过健康检查 → `client` 读取 `/data/sample.json` → 打印识别表格。

只起服务端并手工验证：

```bash
docker compose up -d server
curl -s localhost:8080/health
curl -s -X POST localhost:8080/fingerprint \
  -H 'Content-Type: application/json' \
  -d '[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]'
```

## 4. API 契约

### `POST /fingerprint`

请求（裸数组；同时兼容 `{"items":[...]}`、`{"data":[...]}`、`{"batch":[...]}`）：

```json
[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]
```

响应：**等长、保序**的数组。

```json
[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH",
  "version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}]
```

- 未知项：`protocol:"unknown"`，其余字段为空字符串，`confidence` 为 `0.1`。
- 单条解析/匹配异常被隔离，不影响整批，服务不崩溃。
- 输入宽容：`port` 支持数字/字符串/浮点，`banner` 允许缺失或 `null`，
  `\xNN` 非标准转义与 UTF-8 BOM 会被自动修复，单个对象也会被当作单条批次。
- 上限：body 64 MiB、单批 200000 条，超限返回 `413`。
- 非法请求体返回 `400`，响应体为 `{"error":..., "detail":...}`。

### `GET /health`

```json
{"status":"ok","version":"0.1.0","rules":11,"uptime_s":42}
```

规则未加载时返回 `503`。

## 5. 规则即数据

一条规则 = 一个协议（可选产品）+ 一个正则，直接在**原始字节**上匹配，
因此文本协议与二进制协议（MySQL 握手包）共用同一引擎。

```yaml
- id: ssh.openssh
  protocol: SSH
  product: OpenSSH
  priority: 200          # 越大越先匹配
  kind: text
  match: '(?i)SSH-[0-9]\.[0-9]+-OpenSSH[_-]'
  version: '(?i)OpenSSH[_-]([0-9][0-9A-Za-z._-]*)'   # 第一个捕获组 = version
  os_hint:
    - match: '(?i)\bubuntu\b'
      value: Ubuntu
```

新增一个协议：在 `rules/` 下加一个 `.yaml` 即可，**不需要改 Go 代码**。
运行期也可以挂载外部目录覆盖内置规则（`FP_RULES_DIR` → `./rules:/etc/bannerprint/rules:ro`），
改规则只需重启容器，无需重建镜像。

规则错误（正则写错、ID 重复）会让进程**启动失败**，避免带病上线。

## 6. 置信度模型

| 证据 | 置信度 |
|---|---|
| 产品 + 版本 + OS 佐证 | 0.95 |
| 产品 + 版本 | 0.90 |
| 仅产品 | 0.70 |
| 仅协议 | 0.50 |
| 未识别 | 0.10 |

规则可用 `confidence` 显式覆盖（如 Jetty 的 `Server` 头容易伪造，取 0.85）。

## 7. 部署与安全基线

| 项 | 做法 |
|---|---|
| 构建 | 多阶段：`golang:1.23-alpine` 编译 → `scratch` 运行；`CGO_ENABLED=0`、`-trimpath`、`-s -w`、版本注入 |
| 离线构建 | 依赖已 `vendor/` 提交，构建期不访问 module proxy；只拷贝构建所需目录以复用缓存 |
| 依赖缓存 | `go.mod/go.sum/vendor` 单独一层 + BuildKit cache mount |
| 运行身份 | `USER 65532:65532`，镜像内无 shell、无包管理器 |
| 文件系统 | `read_only: true` + `/tmp` tmpfs |
| 能力 | `cap_drop: ALL` + `no-new-privileges` |
| 资源 | `pids_limit`、`mem_limit`、`cpus` |
| 网络 | 单一自定义网络；只有 server 发布端口；client 使用服务名 |
| 健康 | 二进制自带的 `healthcheck` 子命令探测 `/health`，client 以 `service_healthy` 为前置条件 |

## 8. 设计取舍

1. **规则外置而非硬编码**：识别逻辑易变，代码应稳定；因此引擎通用、规则可热替换。
2. **端口只作弱先验**：443 也输出 `HTTP`，不对端口做硬映射，避免被端口欺骗。
3. **输入宽容**：真实扫描数据常含 `\x00` 等非标准转义，宁可修复后识别，也不整批 400。
4. **panic 收敛**：单条数据绝不拖垮服务，未识别一律 `unknown`。
5. **scratch + 自探针健康检查**：最小攻击面，同时保留 compose 健康语义。

## 9. 实施状态

| 能力 | 状态 |
|---|---|
| 工程骨架、契约、引擎、输入解析、HTTP 层、client、镜像、compose | 已完成并容器实测 |
| SSH / HTTP(nginx·Apache·Jetty·IIS) / MySQL(MariaDB) / Redis / FTP / TLS 规则 | 已完成 |
| 扩展规则：SMTP / POP3 / IMAP / Memcached / Caddy / openresty / Tomcat / FileZilla 等 | 已完成 |
| 20 条自测数据表驱动测试 + 边界与 handler 测试 | 已完成（`go test ./...` 全绿） |
| 剩余协议（PostgreSQL、MongoDB、SMB 等） | 待补（P1，仅需加 YAML） |
| CI、`/metrics`、多架构镜像 | 待补（P1） |

```bash
go test ./...        # 单元测试
go run ./cmd/server  # 本地起服务
go run ./cmd/client -file data/sample.json -server http://localhost:8080
```
