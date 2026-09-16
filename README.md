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
| `TRACE_TOKENS_FILE` | 空 | 多用户令牌文件（JSON，见 §2）；按用户/实例隔离读权限 |
| `TRACE_UI_DIR` | `./ui` | 轨迹壳目录；删除则 `/trace` 关闭 |
| `TRACE_PORTAL_DIR` | `./portal` | 门户目录 |

## 2. 多用户令牌与作用域隔离

单一共享 `TRACE_TOKEN` 时人人都是管理员 —— 单人运维没问题，多人
共享就会互相看见全部对话。多用户部署改用令牌文件（`TRACE_TOKENS_FILE`）：

```json
{
  "tok_alice_9f2c":  {"name": "alice",  "users": ["alice@wecom"]},
  "tok_shanghai_7d1": {"name": "上海机房", "instances": ["edge-shanghai-01"]},
  "tok_auditor_3e":  {"name": "审计",   "users": null, "instances": null}
}
```

- `users` / `instances` 是允许列表，匹配会话的 `user_id`（渠道用户
  身份）与 `instance_id`（边端机器身份）；**两个维度同时给出时需
  同时满足**（AND）。
- `null` 或缺省 = 该维度不受限；两个都为 `null` 等同管理员。
- 隔离语义：受限令牌的会话列表、会话详情、stats、export、overview、
  instances 全部按作用域过滤；**跨作用域访问返回 404 而非 403**，
  不泄露"该会话存在"。无 `user_id` 的会话（如 Console 直连）对
  纯用户作用域令牌不可见，对实例作用域令牌按实例匹配。
- `/ingest` 对所有有效令牌开放（采集不设限，只限读）；边端
  `remote_token` 可直接复用受限令牌。
- `GET /api/agent-trace/whoami` 返回当前令牌身份与作用域（门户
  登录后头部展示用）。
- `TRACE_TOKEN`（管理员）与令牌文件可并存；令牌文件不可读时仅
  管理员令牌生效（启动日志有 warning）。

生成令牌建议 `python -c "import secrets;print('tok_'+secrets.token_urlsafe(18))"`。

## 3. 边端开启推送（每台 QwenPaw）

在插件仓库侧配置 `<WORKING_DIR>/traces/config.json`：

```json
{
  "remote_enabled": true,
  "remote_url": "http://collector.internal:8790",
  "remote_token": "同一个长随机串"
}
```

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
