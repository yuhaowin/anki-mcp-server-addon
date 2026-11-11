# anki-mcp-relay — 自托管 AnkiMCP 隧道中继（Go）

`wss://tunnel.ankimcp.ai` 的替代品。**不改插件代码**，只需改插件配置里的
`tunnel_server_url`，Anki 就会连到你自己的服务器，并得到一个可以公网访问的 MCP URL。

```
MCP 客户端 ──HTTPS POST──► relay /t/<tunnel-id> ──WebSocket──► Anki 插件 ──► Anki 集合
```

## 实现的协议（与 `anki_mcp_server/tunnel/` 对齐）

| 端点 | 用途 |
|---|---|
| `POST /auth/device` | OAuth 设备码（RFC 8628）：返回 `device_code / user_code / verification_uri(_complete) / expires_in / interval` |
| `POST /auth/token` | `grant_type=...device_code`（`authorization_pending` / `expired_token`）和 `refresh_token`（`invalid_grant`）；响应带插件要求的 `user{id,email,tier}` |
| `GET/POST /device` | 浏览器授权页：输入 Anki 显示的代码 + 中继密码即可批准 |
| `GET /` 或 `/ws`（WebSocket） | 插件隧道：校验 `Authorization: Bearer`，发 `tunnel_established{url}`，每 30s `ping`，转发 `request` / 接收 `response` |
| `POST /t/<id>[/...]` | 公网 MCP 端点（Streamable HTTP，无状态 JSON 响应）；`GET`/`DELETE` 返回 405，`OPTIONS` 处理 CORS |
| `GET /healthz` | 健康检查 |

使用的关闭码：`4005` 同一账号新连接顶掉旧连接，`4009` 中继关闭（插件会自动重连），
`4002` 账号被撤销（插件不再重连），`1001` 心跳超时。

每个账号有一个持久化的 128 位随机 tunnel ID，所以公网 URL 在重连、中继重启后都不变。

## 运行

```bash
go build -o anki-mcp-relay .
RELAY_PASSWORD='一个强密码' ./anki-mcp-relay \
  -listen :8080 \
  -public-url https://relay.example.com \
  -trust-proxy
```

或 Docker：

```bash
docker build -t anki-mcp-relay .
docker run -d --name anki-relay -p 8080:8080 -v anki-relay:/data \
  -e RELAY_PASSWORD='一个强密码' -e RELAY_PUBLIC_URL=https://relay.example.com \
  -e RELAY_TRUST_PROXY=1 anki-mcp-relay
```

TLS 建议交给反向代理，例如 Caddy（自动证书，WebSocket 无需额外配置）：

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

也可以直接用 `-tls-cert / -tls-key` 让中继自己监听 HTTPS。

### 参数（均可用环境变量）

| 参数 | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-password` | `RELAY_PASSWORD` | 必填 | 批准设备登录的密码 |
| `-public-url` | `RELAY_PUBLIC_URL` | 按请求 Host 推导 | 对外的 `https://` 地址，用于生成 MCP URL 和授权页链接 |
| `-listen` | `RELAY_LISTEN` | `:8080` | |
| `-data` | `RELAY_DATA` | `relay-data.json` | 账号、refresh token 哈希、签名密钥 |
| `-trust-proxy` | `RELAY_TRUST_PROXY=1` | 关 | 信任 `X-Forwarded-*`（在反代后面时打开） |
| `-public-api-key` | `RELAY_PUBLIC_API_KEY` | 空 | 设置后 MCP 客户端必须带 `Authorization: Bearer <key>` |
| `-cors-origins` | `RELAY_CORS_ORIGINS` | `*` | 公网端点的 CORS 来源，空=不发 CORS 头 |
| `-request-timeout` | `RELAY_REQUEST_TIMEOUT` | `30s` | 单个 MCP 请求等待 Anki 的上限（插件自身 25s 超时） |
| `-access-token-ttl` | `RELAY_ACCESS_TOKEN_TTL` | `24h` | |
| `-client-ids` | `RELAY_CLIENT_IDS` | `ankimcp-cli` | 接受的 OAuth client_id，空=任意 |
| `-tier` | `RELAY_TIER` | `self-hosted` | Anki 里显示的套餐名（非 `free` 时显示 "Permanent URL"） |

## 插件这边

Anki → *工具 → 插件 → AnkiMCP Server → 配置*：

```json
"tunnel_server_url": "wss://relay.example.com"
```

（本地测试可用 `ws://127.0.0.1:8080`。）重启 Anki，打开 *Tools → AnkiMCP Server Settings…* →
**Connect Tunnel**，浏览器会打开 `/device` 页面，填中继密码批准即可。连上后复制显示的 URL，
填进 Claude / ChatGPT 等 MCP 客户端。

如果之前登录过官方中继，先点 **Logout**，否则插件会拿官方的 token 来连，会被拒绝。

## 安全说明

- 公网 MCP URL 本身就是访问凭证（128 位随机）。需要更强保护时设置 `-public-api-key`。
- 授权页每个 IP 15 分钟内最多失败 5 次。
- 撤销某个账号：停掉中继，在数据文件里删掉它的 `refresh_tokens` 条目，再启动（在线时
  下一次心跳会以 4002 断开）。删掉整个数据文件会轮换签名密钥，所有客户端都要重新登录，
  公网 URL 也会变。
- 帧大小：插件的 websockets 客户端只接收 ≤1 MiB 的帧，所以中继会对超过约 1 MiB 的请求直接返回 413，
  防止整条隧道被断开（大媒体请用 URL 方式传入 `store_media_file`）。
