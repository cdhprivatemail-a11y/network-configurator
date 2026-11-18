---
name: code-review-guardian
description: 资深代码审查守卫技能包。在代码合并、PR评估或审查代码质量时，从安全性漏洞（OWASP）、并发与竞态、资源泄露、异味复杂度、防御性容错与性能瓶颈五个维度执行大厂级严格代码评审。
---

# 资深代码审查守卫规范 (Code Review Guardian)

本技能为 AI Agent 在执行 **Code Review (代码评审)**、Pull Request (PR) 审查或重构评估时提供**一线工业级质量防线**。

---

## 一、 审查问题等级与处置标准

所有审查反馈必须附带明确的严重度级别标记：

| 级别标识 | 严重度 | 处置动作 | 典型问题场景 |
| :--- | :--- | :--- | :--- |
| **`[BLOCKER]`** | 阻断级 | **禁止合并** | SQL 注入、密钥明文硬编码、并发死锁、内存无限泄漏、破坏事务原子性 |
| **`[CRITICAL]`** | 严重缺陷 | **必须修复** | 未捕获可能引发崩溃的异常、未释放连接/文件句柄、N+1 查询、绕过权限校验 |
| **`[MAJOR]`** | 架构/重构 | **强烈建议修改** | 圈复杂度过高 (>15)、违反单一职责原则、全局状态隐蔽共享、缺少关键单测 |
| **`[MINOR]`** | 规范改进 | **建议改进** | 命名语义模糊、无用的注释与死代码、日志等级滥用、缺少超时配置 |
| **`[NIT]`** | 微小细节 | **可选** | 代码排版格式、微小的文档错别字、非关键语法糖 |

---

## 二、 五大核心审查防线 (The 5 Review Pillars)

### 1. 安全性防线 (Security & OWASP)
- **输入注入防范**：严禁拼接 SQL 语句（必须使用参数化查询/预编译语句）；严禁拼接 Shell 命令（必须使用安全传参数组）。
- **敏感信息暴露**：代码中严禁硬编码 API 密钥、数据库账密、私钥；日志中对手机号、密码、身份证脱敏。
- **越权漏洞 (BOLA / IDOR)**：检查所有涉及数据查询或修改的 API，是否仅凭前端传入的 `id` 查询，而**没有校验当前登录用户的属主权限**。

### 2. 资源管理与生命周期 (Resource Leaks)
- **句柄与连接回收**：所有的文件句柄、网络 Socket、数据库 Session、互斥锁必须使用上下文管理器（如 Python `with` 语法、Java `try-with-resources`、Go `defer resp.Body.Close()`）。
- **长连接与超时兜底**：所有的 HTTP 请求、RPC 调用、Socket 连接必须显式配置 `connect_timeout` 与 `read_timeout`，严禁无限挂起等待。

### 3. 并发安全与竞态条件 (Concurrency & Race Conditions)
- **共享可变状态**：检查多线程/协程中操作共享全局字典/切片时是否加锁（Mutex/RWLock）。
- **先检查后执行 (Check-Then-Act)**：
  - *错误示范*：`if not exists(user_id): insert(user_id)`（并发下产生重复数据或唯一键冲突）。
  - *正确模式*：依靠数据库唯一索引约束（Unique Constraint）或分布式锁确保原子性。

### 4. 异常处理与防御容错 (Exception Defense)
- **严禁吞异常**：严禁写 `except: pass` 或 `catch (Exception e) {}` 空代码块。
- **精准捕获**：禁止捕获顶层 `BaseException`/`Exception`；只捕获明确预期的异常类型，并在捕获处记录堆栈日志（`logger.exception()`）。
- **兜底恢复**：异步任务队列（Celery/Worker）中必须有重试退避机制（Exponential Backoff）与死信队列（Dead Letter Queue）。

### 5. 性能与数据库交互 (Performance & N+1)
- **ORM N+1 查询**：检查循环遍历体内是否存在单条 SQL 查询；必须改用 `selectinload` / `joinedload` / `IN (...)` 批量查询。
- **大内存加载**：批量读取大数据量（如上万条记录、大文件）严禁一次性 `.all()` 或 `.read()`，必须使用分页游标（Cursor）或流式生成器（Streaming/Generator）。

---

## 三、 Review 反馈格式规范

审查意见必须包含：**定位、问题归类、风险解释、修改建议代码对（Before vs After）**：

> **`[BLOCKER] [Security]`** `services/user_service.py` L42: 存在 SQL 拼接注入风险
> 
> - **风险描述**：直接使用 f-string 拼接 `username` 入参，恶意攻击者可通过 `' OR '1'='1` 绕过认证或执行恶意指令。
> - **修改方案**：
> ```python
> # ❌ 修改前 (易受攻击):
> cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
> 
> # ✅ 修改后 (参数化安全查询):
> cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
> ```

---

## 四、 审查守卫交付清单 (Review Checklist)
- [ ] 代码是否通过了敏感信息扫描（无 Token/Password 硬编码）？
- [ ] 外部输入是否在最外层（DTO/Schema）完成了防御式类型校验？
- [ ] 所有的 I/O 资源是否均在退出作用域时安全关闭？
- [ ] 是否存在循环内反复查询数据库的 N+1 性能陷阱？
- [ ] 边界条件（0、空值、None/null、极长字符、并发重入）是否安全覆盖？
