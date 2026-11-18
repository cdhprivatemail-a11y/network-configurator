---
name: fullstack-developer
description: 工业级全栈开发规范技能包。指导全栈项目的前后端架构分层、RESTful/API契约设计、输入防御与校验、数据库建模与索引优化、前端组件化与性能提升，以及单元/集成自动化测试规范。
---

# 工业级全栈开发规范 (Full-Stack Engineering Standard)

本技能为 AI Agent 在全栈项目（前端、后端、数据库、API 契约、测试与部署）开发、重构或代码审查时提供**工业级工程标准与实施准则**。

---

## 一、 总体架构设计原则 (Architecture Principles)

1. **前后端职责分离 (Clear Separation of Concerns)**：
   - **前端**：负责视图渲染、用户交互、表单初筛校验、本地状态管理。坚决不承载核心商业逻辑与安全凭证。
   - **后端**：负责业务规则校验、权限鉴权、数据持久化、事务完整性控制与审计日志。
2. **分层架构规范 (Layered Architecture)**：
   - `Controller / Route Layer`：仅负责入参解析、鉴权、调用 Service、组装统一返回体。不写具体 SQL 或繁杂计算。
   - `Service / Business Layer`：承载所有核心业务逻辑、跨表事务、第三方服务调用。
   - `Data Access / Repository Layer`：封装 ORM、SQL 操作及缓存读写。
   - `Schema / DTO Layer`：严格定义前端传入请求与后端返回响应的结构与类型。

---

## 二、 API 契约与接口设计规范 (API Contract Standards)

1. **统一返回体封装 (Unified Response Structure)**：
   所有业务接口必须遵循统一的 JSON 结构规范：
   ```json
   {
     "success": true,       // 布尔值：明确标识业务是否成功
     "code": 200,           // 业务状态码 (200, 400, 401, 403, 404, 500)
     "message": "操作成功",  // 人类可读的提示信息
     "data": {},            // 成功时承载的实际数据对象或列表 (失败时为 null)
     "error": null          // 失败时记录的具体错误详情或错误码
   }
   ```

2. **HTTP 动词规范 (RESTful Conventions)**：
   - `GET`：幂等且只读，不得产生业务副作用。
   - `POST`：创建新资源或提交复杂计算。
   - `PUT`：全量覆盖更新现有资源。
   - `PATCH`：部分增量更新资源指定字段。
   - `DELETE`：删除指定资源。

3. **防御式输入校验 (Defensive Input Validation)**：
   - 所有的 API 入参（Body、Query、Path）必须有显式的类型声明与校验器（如 Pydantic、Zod、Joi、TypeScript Interface）。
   - 严禁信任客户端传入的任何数据：严格校验字符串长度、数值范围、枚举合法性、邮箱/手机格式及非法字符注入（防 SQL 注入与 XSS）。

---

## 三、 前端工程化与交互规范 (Frontend Standards)

1. **组件化高内聚设计**：
   - 单个组件文件代码行数尽量控制在 300 行以内；超过即刻拆分子组件（如提取出独立的 TableRow、Modal、FilterToolbar）。
   - 状态提升（State Lifting）：通用状态通过父组件或全局 Store（Pinia/Redux）下发，私有 UI 状态（如下拉展开、Tooltip）留在组件内部。
2. **交互体验与弹性 UI (Resilient UI)**：
   - **加载中状态 (Loading State)**：所有异步操作（保存、查询、删除、上传）按钮必须有 Loading 禁用态与骨架屏，防止重复提交。
   - **空状态与异常处理 (Empty & Error State)**：列表为空时必须展示友好的空状态（Empty Placeholder），请求报错时必须通过全局 Toast/Message 提示用户。
   - **防抖与节流 (Debounce & Throttle)**：搜索输入框必须添加 300ms~500ms 防抖，滚动/拖拽监听必须添加节流。

---

## 四、 数据库与持久化规范 (Database & Data Modeling)

1. **表设计基础要求**：
   - 每张业务表必须包含三大基础字段：
     - `id`：主键（自增整型或 UUID/Snowflake）。
     - `created_at`：创建时间（默认当前时间戳）。
     - `updated_at`：更新时间（随修改自动更新时间戳）。
   - 字段名统一采用下划线命名法（`snake_case`），布尔类型统一使用 `is_` 或 `has_` 前缀（如 `is_active`）。
2. **索引优化原则 (Indexing Best Practices)**：
   - 高频查询条件、排序字段、唯一外键必须建立索引。
   - 联合索引遵循**最左匹配原则**（区分度最高且高频作为过滤条件的列放在最前面）。
   - 避免冗余索引，不在低基数列（如性别、仅有0/1状态且分布均匀的列）单独建普通索引。
3. **事务完整性 (Transaction Integrity)**：
   - 涉及多张表的增删改操作（如扣减余额+创建订单）必须显式包裹在事务中，出现异常时自动全量回滚。

---

## 五、 测试驱动与质量保证 (Testing & Quality Assurance)

1. **测试分层策略 (Testing Pyramid)**：
   - **单元测试 (Unit Tests)**：对核心业务逻辑函数、复杂算法、金额/数据推导引擎进行 100% 覆盖。
   - **集成测试 (API Integration Tests)**：验证 Controller -> Service -> Repository 的端到端请求闭环。
2. **边界与异常覆盖**：
   - 测试用例必须覆盖：
     - 正常主流程（Happy Path）
     - 临界边界值（空字符串、0、极值、大数组）
     - 非法参数导致的预期报错拦截（如不存在的 ID、未授权访问）

---

## 六、 技能使用自检清单 (Full-Stack Agent Checklist)

在为用户编写或重构全栈功能代码时，执行以下自检：
- [ ] 后端路由是否包裹了统一的错误捕获与日志记录？
- [ ] 接口入参是否有严格的类型校验层？
- [ ] 前端按钮在发起网络请求时是否有 Loading 防重复点击处理？
- [ ] 错误返回给前端时是否有友好的中文提示文案？
- [ ] 新建的数据库表/数据结构是否规划了主键、索引与基础时间戳？
- [ ] 敏感配置（密钥、端口、连接串）是否通过环境变量（`.env`）隔离而非硬编码？
