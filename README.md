# agent-trace 中央采集服务（Central Collector）

企业部署形态：每台 QwenPaw（边端）照常本地记录轨迹，同时把事件
批量推送到一台中央服务，统一展示全组织的会话轨迹 —— 按用户、按
机器实例筛选。

> 本仓库是 [qwenpaw-trace](https://github.com/flyrae/qwenpaw-trace)
> 插件的**服务端配套**（2026-09 自插件仓库拆出，首个提交对应插件
> `d52baf5`）。边端采集（shipper、`remote_*` 配置）在插件仓库；
> 两侧通过 `schema_version` 信封契约解耦。

```
QwenPaw 实例 A/B/C ──shipper(gzip+token+落盘重试)──▶ /ingest
                                                      │ SQLite
                       门户 /（登录门 + 总览仪表盘）
                       轨迹 /trace（与 Console 同一 bundle）
                       ◀── /api/agent-trace/*（与插件本地读 API 同契约）
```

## 1. 启动服务

```bash
pip install fastapi uvicorn            # 无其它依赖（SQLite 内置）
python ui/build-ui.py                  # 首次：准备 UI 静态资源（见下）
TRACE_DB=./traces.db TRACE_TOKEN=一个长随机串 \
    uvicorn app:app --host 0.0.0.0 --port 8790
```

环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `TRACE_DB` | `./traces.db` | SQLite 路径 |
| `TRACE_TOKEN` | 空 | **管理员令牌**：设置后 `/ingest` 与 `/api` 需 `Authorization: Bearer <token>`；静态页（门户/轨迹壳）不拦截 |
| `TRACE_TOKENS_FILE` | 空 | 多用户令牌**种子文件**（JSON，见 §2）：仅首次导入 DB，之后以管理台为准 |
| `TRACE_UI_DIR` | `./ui` | 轨迹壳目录；删除则 `/trace` 关闭 |
| `TRACE_PORTAL_DIR` | `./portal` | 门户目录 |

## 2. 多用户令牌与作用域隔离

单一共享 `TRACE_TOKEN` 时人人都是管理员 —— 单人运维没问题，多人
共享就会互相看见全部对话。多用户部署改用**管理台发放令牌**：

1. 用管理员令牌（`TRACE_TOKEN`）登录门户 `/`，出现"令牌管理"区；
2. 填显示名 + 作用域 → 发放 → 明文令牌**仅显示一次**，复制发给本人；
3. 吊销即时生效（持有者下一次请求即 401），发放同样即时生效。

等价的管理 API（管理员令牌专用，受限令牌访问返回 404）：

```bash
curl -s -H "Authorization: Bearer $ADMIN" \
     localhost:8790/api/agent-trace/admin/tokens          # 列表（令牌打码）
curl -s -H "Authorization: Bearer $ADMIN" \
     -H 'Content-Type: application/json' \
     -d '{"name":"alice","users":["alice@wecom"]}' \
     localhost:8790/api/agent-trace/admin/tokens          # 发放
curl -s -X DELETE -H "Authorization: Bearer $ADMIN" \
     localhost:8790/api/agent-trace/admin/tokens/7        # 吊销
```

作用域语义（管理台表单与 API 一致）：

- `users` / `instances` 是允许列表，匹配会话的 `user_id`（渠道用户
  身份）与 `instance_id`（边端机器身份）；**两个维度同时给出时需
  同时满足**（AND）。
- 都留空 = 管理员级令牌（全量可见，谨慎发放）。
- 隔离语义：受限令牌的会话列表、会话详情、stats、export、overview、
  instances 全部按作用域过滤；**跨作用域访问返回 404 而非 403**，
  不泄露"该会话存在"。无 `user_id` 的会话（如 Console 直连）对
  纯用户作用域令牌不可见，对实例作用域令牌按实例匹配。
- `/ingest` 对所有有效令牌开放（采集不设限，只限读）；边端
  `remote_token` 可直接复用受限令牌。
- `GET /api/agent-trace/whoami` 返回当前令牌身份与作用域（门户
  登录后头部展示用）。

令牌持久化在 SQLite 的 `tokens` 表（`TRACE_DB` 同库）。批量初始化
可用 `TRACE_TOKENS_FILE`（JSON）作**种子**：启动时导入 DB 中不存在的
令牌，**不覆盖**管理台已改动/已吊销的记录 —— 运行期以 DB 为准：

```json
{
  "tok_alice_9f2c":  {"name": "alice",  "users": ["alice@wecom"]},
  "tok_shanghai_7d1": {"name": "上海机房", "instances": ["edge-shanghai-01"]}
}
```

注意：一旦存在任何令牌（环境管理员令牌或 DB 中有效令牌），服务即
要求认证 —— 开放模式（无令牌）下发放的第一个令牌会立即让匿名访问
变成 401。`TRACE_TOKEN`（管理员）与令牌文件可并存；文件不可读时仅
管理员令牌生效（启动日志有 warning）。

生成令牌串（手工造种子文件时）：`python -c "import secrets;print('tok_'+secrets.token_urlsafe(24))"`。

### 2.1 设备自助注册（enrollment，适合批量边端）

几百台边端逐台发令牌不现实。管理员改为生成一个**注册凭据**
（enroll key，可限次数/设有效期/可吊销），边端首次加载时自动注册
并领取"仅本实例"作用域的最小权限令牌：

```bash
# 管理台"设备注册"区生成，或等价 API：
curl -s -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
     -d '{"name":"华东机房 9 月批","max_uses":200,"expires_days":14}' \
     localhost:8790/api/agent-trace/admin/enroll-keys   # 明文仅此一次
```

- 边端在 `traces/config.json` 配 `remote_enroll_key`（插件 ≥ v0.8.0），
  首次加载调用 `POST /enroll` 上报自身 `instance_id`，服务端吊销该
  实例旧令牌（轮换）并发新令牌，边端持久化到
  `<WORKING_DIR>/traces/.instance-token`，之后一直用它；
- 令牌被吊销/失效时边端收到 401 自动重新注册（凭据仍有效时）；
- 注册凭据**只**能用于 `/enroll`，不能当 Bearer 令牌访问任何其它
  端点；吊销凭据不影响已发放的实例令牌；
- 实例令牌在令牌管理列表中标记来源为"自动注册"。

`POST /enroll` 请求体：`{"instance_id": "...", "hostname": "..."}`
+ `Authorization: Bearer <注册凭据>`；响应 `{"token", "name",
"instances"}`（token 明文仅此一次）。

## 3. 边端开启推送（每台 QwenPaw）

在插件仓库侧配置 `<WORKING_DIR>/traces/config.json`：

```json
{
  "remote_enabled": true,
  "remote_url": "http://collector.internal:8790",
  "remote_token": "手工发放的令牌",
  "remote_enroll_key": "或：注册凭据，首次加载自动领取实例令牌"
}
```

令牌来源优先级（插件 ≥ v0.8.0）：持久化的实例令牌
（`traces/.instance-token`，enroll 自动写入）> `remote_enroll_key`
（首次自动注册）> `remote_token`（手工配置）。

行为契约：**本地优先**（断网不影响本机轨迹）、批量推送（2s/200 条/1MB）、
失败退避 + 落盘排队自动补传、队列上限丢旧、绝不阻塞智能体循环、
按 `(instance, session, seq)` 幂等去重。

实例身份优先级：config `remote_instance_id` > 环境变量
`QWENPAW_INSTANCE_ID`（容器/服务部署推荐）> 首次生成 UUID 持久化在
边端 `<WORKING_DIR>/traces/.instance-id`。

## 4. 入口与 UI

- `/` **门户**（`portal/`，自包含单文件）：令牌登录门 → KPI 卡
  （接入实例/会话/活跃用户/LLM 调用/Token/错误）→ 实例表 → 最近
  会话（点击进轨迹）；10 秒自动刷新。令牌与 `/trace` 共享
  `localStorage.trace_token`。
- `/trace` **轨迹查看器**（`ui/`）：vendored React/dayjs/antd/icons
  UMD 提供 `window.QwenPaw.host` 壳，**与 Console 共用同一个前端
  bundle**（`build-ui.py` 从插件仓库取 `dist/index.js`，默认兄弟目录
  `../qwenpaw-trace`，可用 `--bundle` 指定）。
- 跨源部署：任意 nginx/CDN 托管 `ui/`（CORS 已开），页面上
  `localStorage.setItem('trace_api_base', 'http://collector:8790')`。

深链：`/trace/?session=<instance>~<session_id>`，可分享/刷新。

## 5. 运维

```bash
curl -s localhost:8790/healthz            # 实例数 / 会话数
curl -s -H "Authorization: Bearer $T" \
     'localhost:8790/api/agent-trace/sessions?user=alice'
curl -s -H "Authorization: Bearer $T" localhost:8790/api/agent-trace/whoami
```

保留策略（v1）：按需清理 SQLite 或归档后重建。多用户隔离已按
`TRACE_TOKENS_FILE` 落地（§2）；OIDC / 对接企业身份源在后续版本。

## 测试

```bash
python -m pytest tests -q        # ingest/幂等/过滤/分页/鉴权/overview
python smoke_e2e.py              # 真实 shipper→server→API→UI 全链路
                                # （需本地有插件仓库 checkout，
                                #  或设 TRACE_PLUGIN_ROOT 指向它）
```

## 6. 容器部署（推荐生产形态）

```bash
# 前置：准备 UI 资源（vendored UMD + 插件 bundle）
python ui/build-ui.py                  # 默认取兄弟目录 ../qwenpaw-trace/dist/index.js

# 构建 + 运行（compose）
TRACE_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(24))") \
    docker compose up -d --build       # 数据持久化在 named volume trace-data

# 或直接 docker
docker build -t agent-trace-server:0.3 .
docker run -d --name trace-server -p 8790:8790 \
    -e TRACE_TOKEN=... -v trace-data:/data --restart unless-stopped \
    agent-trace-server:0.1
```

镜像要点：`python:3.12-slim` + fastapi/uvicorn（仅两个依赖）；数据库
固定在 `/data/traces.db`（volume 持久化）；内置 `HEALTHCHECK`（30s 探
`/healthz`）；`TRACE_TOKEN` 默认留空（私网开放），生产必须设置。多用户
部署：把 `tokens.json` 放进 volume（如 `/data/tokens.json`），再设
`TRACE_TOKENS_FILE=/data/tokens.json`（compose 已透传该变量）。

`smoke_e2e.py` 同样适用容器目标：起容器后把边端 `remote_url` 指过去
即可（本仓库的 e2e 验证即用此方式跑通过：ingest → 聚合 → 门户 →
轨迹壳 → 健康检查全部通过）。

K8s 要点：`Deployment`（镜像 + `TRACE_TOKEN` from Secret）+
`PersistentVolumeClaim` 挂 `/data` + `readinessProbe`/`livenessProbe`
GET `/healthz`，无需其它特殊配置。
