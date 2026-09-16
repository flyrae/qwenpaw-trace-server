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
| `TRACE_TOKEN` | 空 | 设置后 `/ingest` 与 `/api` 需 `Authorization: Bearer <token>`；静态页（门户/轨迹壳）不拦截 |
| `TRACE_UI_DIR` | `./ui` | 轨迹壳目录；删除则 `/trace` 关闭 |
| `TRACE_PORTAL_DIR` | `./portal` | 门户目录 |

## 2. 边端开启推送（每台 QwenPaw）

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

## 3. 入口与 UI

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

## 4. 运维

```bash
curl -s localhost:8790/healthz            # 实例数 / 会话数
curl -s -H "Authorization: Bearer $T" \
     'localhost:8790/api/agent-trace/sessions?user=alice'
```

保留策略（v1）：按需清理 SQLite 或归档后重建。RBAC / OIDC /
按用户隔离在二期（身份字段已就位，权限只是查询 WHERE 条件）。

## 测试

```bash
python -m pytest tests -q        # ingest/幂等/过滤/分页/鉴权/overview
python smoke_e2e.py              # 真实 shipper→server→API→UI 全链路
                                # （需本地有插件仓库 checkout，
                                #  或设 TRACE_PLUGIN_ROOT 指向它）
```
