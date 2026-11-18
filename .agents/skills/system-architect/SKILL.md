---
name: system-architect
description: 资深系统架构师技能包。指导复杂软件系统的技术选型、分层架构设计（C4模型）、领域驱动设计（DDD）、高可用高并发架构、数据流与状态机设计，以及架构演进决策（ADR）。
---

# 资深系统架构师设计规范 (System Architecture Standards)

本技能为 AI Agent 在承接系统方案设计、技术选型评估、架构重构与领域建模时提供**工业级架构方法论与设计规范**。

---

## 一、 架构设计核心方法论

### 1. C4 架构可视化模型 (C4 Model)
任何系统设计文档必须遵循从宏观到微观的 4 级抽象：
- **Context (语境图)**：系统与外部用户、第三方系统（如网关、短信、支付、监控）的交互边界。
- **Container (容器图)**：运行时的可独立部署单元（如 Web 前端、API 后端服务、Worker 队列、Redis、PostgreSQL）。
- **Component (组件图)**：容器内部的职责模块（如 AuthComponent、PaymentService、NotificationWorker）。
- **Code (代码类图/流程图)**：核心算法、状态机或复杂时序图。

### 2. 领域驱动设计 (DDD - Domain-Driven Design)
在业务中台或复杂应用开发中，坚决避免贫血模型与逻辑泄漏：
- **战略设计 (Strategic Design)**：
  - 划分**通用语言 (Ubiquitous Language)**，杜绝中英文混用或歧义词。
  - 界定**限界上下文 (Bounded Context)**，明确上下文映射关系（防腐层 ACL、开放主机服务 OHS）。
- **战术设计 (Tactical Design)**：
  - **实体 (Entity)**：拥有唯一身份标识（ID）且具有生命周期状态变化的对象。
  - **值对象 (Value Object)**：无身份标识、不可变（Immutable），仅用于描述度量或属性（如 Money, Address）。
  - **聚合根 (Aggregate Root)**：事务与业务一致性边界，外部对象严禁直接引用聚合内部实体，必须通过聚合根操作。
  - **领域服务 (Domain Service)**：承载不属于单一实体或聚合的多聚合协调逻辑。

---

## 二、 技术选型与权衡原则 (Architecture Trade-offs)

架构设计的本质是权衡（Trade-off）。在做选型决策时必须评估：

1. **CAP 定理权衡**：
   - 网络分区不可避免（P 必须满足）。
   - 在高并发读写下明确选择 **AP**（最终一致性，如 Dynamo/Cassandra、消息队列异步解耦）或 **CP**（强一致性，如 Raft/ZooKeeper、分布式事务 2PC/Saga）。
2. **单体优先 vs 微服务边界**：
   - **单体优先原则 (Modular Monolith First)**：在业务规模尚未达到组织壁垒或性能瓶颈前，优先采用模块化单体，避免过早引入分布式调用的网络延迟与运维开销。
   - **微服务拆分触发条件**：明确的团队边界（康威定律）、独立扩缩容需求（如高频计算节点 vs 基础 CRUD）、异构技术栈刚需。
3. **架构决策记录 (ADR - Architecture Decision Records)**：
   每次重大选型必须输出 ADR 文档：
   ```markdown
   # ADR 001: 采用 PostgreSQL 替代 MySQL 作为核心存储
   - 状态：已批准 (Approved)
   - 上下文：系统需要存储高维向量与原生 JSONB 拓扑属性。
   - 决策：选用 PostgreSQL 16 + pgvector。
   - 影响：支持强事务同时原生支持向量检索；需要团队熟悉 Postgres 索引机制。
   ```

---

## 三、 高可用与高并发设计标准 (HA & High-Concurrency)

1. **弹性与容灾模式**：
   - **熔断与降级 (Circuit Breaker & Fallback)**：对依赖的第三方接口设置熔断器（如 Resilience4j），超时即降级返回兜底数据。
   - **限流 (Rate Limiting)**：在网关层使用令牌桶（Token Bucket）或漏桶算法对 IP/Token 实施限流（如 100 req/s）。
   - **异步削峰 (Message Queue Buffering)**：写入峰值高于 DB 承载力时，必须经由 Kafka/RabbitMQ 异步排队，削峰平谷。
2. **缓存架构规范 (Cache Aside Pattern)**：
   - **读模式**：先读缓存；命中则返回；未命中则查 DB，写入缓存并设置 TTL。
   - **写模式**：先更新 DB，再**淘汰（Delete）缓存**，切忌先写缓存后写 DB。
   - **三大防御机制**：
     - **穿透 (Cache Penetration)**：对不存在的空 key 缓存短 TTL 或使用布隆过滤器（Bloom Filter）。
     - **击穿 (Cache Breakdown)**：热点 key 失效时，加互斥锁（Mutex）回源 DB。
     - **雪崩 (Cache Avalanche)**：缓存过期时间必须添加随机偏移量（Jitter，如 TTL + Random(1~5min)）。

---

## 四、 架构师交付物自检清单 (Architecture Checklist)

在输出系统设计方案或技术评审时，逐项核对：
- [ ] 是否具备系统上下文图（边界划分与外部依赖）？
- [ ] 核心业务是否定义了清晰的领域实体与聚合根一致性边界？
- [ ] 核心流程是否有清晰的时序图（Sequence Diagram）或状态流转图？
- [ ] 高并发/高频读写路径是否评估了 DB 负载与缓存策略？
- [ ] 是否规划了优雅降级方案与故障恢复机制（Failover）？
- [ ] 是否给出了部署拓扑、横向扩展策略与监控度量（Observability: Metrics/Logs/Traces）？
