---
name: api-design-spec
description: 现代软件与接口契约设计规范技能包。指导 RESTful API、RPC 契约设计、URI 资源命名、HTTP/业务状态码分流、接口幂等性、游标分页、OpenAPI (Swagger) 规范及版本演进策略。
---

# 软件与接口设计规范 (API Design & Contract Specification)

本技能为 AI Agent 在设计系统对外接口、前后端交互契约与微服务通信协议时提供**工业级标准化规范**。

---

## 一、 资源命名与 RESTful 动词规范

### 1. 资源 URI 路径规则
- **使用小写复数名词**：URI 代表资源集合，严禁在路径中出现动词。
  - ✅ 正确：`GET /api/v1/devices`、`POST /api/v1/devices`、`GET /api/v1/devices/{id}`
  - ❌ 错误：`GET /api/v1/getDevices`、`POST /api/v1/createDevice`、`POST /api/v1/device/delete`
- **层级嵌套不超过 2 层**：过深的嵌套（如 `/users/1/orders/2/items/3/reviews`）应展平：
  - ✅ 推荐：`GET /api/v1/orders/{order_id}/items`；详情直接查 `GET /api/v1/items/{item_id}`。
- **连字符命名**：多词复合 URI 使用连字符（`kebab-case`），禁止驼峰或下划线：
  - ✅ 正确：`/api/v1/network-interfaces`
  - ❌ 错误：`/api/v1/network_interfaces` 或 `/api/v1/networkInterfaces`。

### 2. HTTP 动词语义映射
| HTTP 动词 | 动作语义 | 幂等性 | 安全性(只读) | 推荐返回 HTTP 状态码 |
| :--- | :--- | :--- | :--- | :--- |
| **`GET`** | 获取单条或列表资源 | 是 (Idempotent) | 是 (Safe) | `200 OK` |
| **`POST`** | 新建资源或执行复杂计算动作 | 否 | 否 | `201 Created` / `200 OK` |
| **`PUT`** | 全量替换更新资源 | 是 | 否 | `200 OK` |
| **`PATCH`** | 增量字段更新资源 | 否/是 | 否 | `200 OK` |
| **`DELETE`**| 删除指定资源 | 是 | 否 | `200 OK` / `204 No Content` |

*特例处理（非 CRUD 动作）*：若动作无法映射为资源（如触发重启、发送邮件），采用子资源动词后缀：
`POST /api/v1/devices/{id}/reboot` 或 `POST /api/v1/notifications/dispatch`。

---

## 二、 统一响应契约与状态码标准

### 1. 响应体规范 (Unified JSON Response)
所有业务请求（无论是成功还是业务失败）统一包装为如下顶层结构：

```json
{
  "success": true,               // 布尔值：业务层面的成功与否
  "code": 200,                   // 业务状态码 (非仅 HTTP 状态码)
  "message": "设备配置下发完成",  // 人类友好的提示文案（支持国际化）
  "data": {                      // 成功时挂载的有效载荷 Payload (对象或数组)
    "task_id": "task-98213",
    "executed_lines": 42
  },
  "error": null,                 // 失败时挂载的错误详情 (成功时固定为 null)
  "timestamp": "2026-10-11T17:21:00Z"
}
```

### 2. 失败响应契约 (Standard Error Payload)
当业务校验失败或出现异常时：
```json
{
  "success": false,
  "code": 40001,
  "message": "参数校验失败",
  "data": null,
  "error": {
    "type": "ValidationError",
    "field_errors": [
      { "field": "ip_address", "rejected_value": "999.1.1.1", "reason": "非法的 IPv4 地址格式" }
    ]
  },
  "timestamp": "2026-10-11T17:21:00Z"
}
```

---

## 三、 高可靠性接口设计原则

### 1. 接口幂等性设计 (Idempotency)
对于非天然幂等的 `POST` 请求（如支付扣款、批量配置下发、工单创建），必须支持**幂等令牌（Idempotency-Key）**机制：
- 客户端在 HTTP Header 中传递唯一生成的 UUID：`Idempotency-Key: 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d`。
- 服务端利用 Redis `SET key value NX EX 120` 原子指令：
  - 若 Key 不存在，记录正在处理，执行业务并把最终返回体缓存 120 秒；
  - 若 Key 已存在且正在处理，返回 `409 Conflict: Request is already processing`；
  - 若 Key 已存在且已处理完，直接返回已缓存的历史成功结果。

### 2. 分页标准 (Pagination)
- **常规小数据量管理后台**：使用 Offset 分页：
  - 入参：`page=1&page_size=20`
  - 返回体包含 meta：`{ "page": 1, "page_size": 20, "total": 128, "total_pages": 7 }`。
- **高并发海量数据 / 移动端瀑布流**：必须使用**基于游标的分页 (Cursor-based Pagination)**，防止 `OFFSET 100000` 慢查询与数据漂移：
  - 入参：`limit=20&cursor=eyJpZCI6MTA0Mn0=` (上一页最后一条记录的 ID 或时间戳)。
  - 返回体：`{ "items": [...], "has_more": true, "next_cursor": "..." }`。

### 3. 版本演进策略 (API Versioning)
- 强制使用 **URI 路径主版本号**：`/api/v1/...`、`/api/v2/...`。
- **向前兼容原则**：
  - 允许：增加新的返回字段、增加可选入参。
  - 禁止：删除现有字段、修改现有字段数据类型、增加必填入参（破坏性变更破坏老客户端，必须升级大版本号）。

---

## 四、 接口规范自检清单 (API Checklist)
- [ ] 路径是否全为名词复数与小写，使用中划线连接？
- [ ] HTTP 动词（GET/POST/PUT/PATCH/DELETE）语义是否准确？
- [ ] 返回体是否严格契合 `{success, code, message, data, error}`？
- [ ] 关键写入操作是否设计了防重提交与幂等保障？
- [ ] 分页列表是否对 `page_size` 限制了上限（如最大 100 条）以防 OOM 拖垮 DB？
