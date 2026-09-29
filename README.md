# auth-session-gateway-go

一套可本地运行的身份认证与访问控制组件（纯 Go 标准库、内存态存储），演示在
**密钥轮换、并发请求、异常链路**下仍能给出可验证且一致的结论。

## 目录结构

| 包 | 职责 |
|---|---|
| `internal/keyring` | 签名密钥的轮换、退役与历史查询；维护“同时只有一个 active key”不变量 |
| `internal/token` | HS256 紧凑令牌的签发与校验；退役密钥只可校验、不可签发 |
| `internal/ratelimit` | 失败尝试计数、限速与锁定；原因可区分，事件幂等，计数无漏计/重复计 |
| `internal/session` | 服务端会话、刷新令牌族；原子轮换、复用检测、族级撤销 |
| `internal/authz` | RBAC + ABAC 判定；显式拒绝优先、资源层级、最小权限作用域收窄 |
| `internal/csrf` | Double-submit CSRF 防护、安全响应头、注入消毒与敏感字段脱敏 |
| `internal/audit` | 安全事件审计；EventID 幂等去重，关键事件显式标记 |
| `internal/auth` | 组合以上组件的认证外观（登录 / 刷新 / 登出 / 鉴权） |
| `cmd/gateway` | 本地 HTTP 网关，把全部组件串成可运行服务 |

## 运行

```bash
go run ./cmd/gateway                 # 默认 127.0.0.1:8080
ADDR=127.0.0.1:18080 go run ./cmd/gateway
```

预置账号（演示用）：

| 用户名 | 密码 | 角色 | 作用域 |
|---|---|---|---|
| `admin` | `admin-pass` | admin | `*` |
| `alice` | `alice-pass` | viewer | `docs:read` |
| `bob`   | `bob-pass`   | editor | `docs:read`,`docs:write` |

HTTP 端点：

- `POST /login` — 凭据校验；成功后通过 HttpOnly Cookie 下发 `access_token` 与
  `refresh_token`（仅作用于 `/refresh` 路径），另下发非 HttpOnly 的 `csrf_token`；
  响应体只含 `session_id` / `key_id` / `expires_at` / `idle_deadline` /
  `absolute_deadline` / `csrf_token`，**不含任何刷新凭据明文**。请求体可选
  `label`（设备/来源标记，用于多端会话辨认）
- `POST /refresh` — 续期轮换：携带 `refresh_token` Cookie + `X-CSRF-Token`；
  成功后访问凭据与刷新凭据在同一个响应里一起换新（Cookie 覆盖），响应体只回
  会话标识与有效期
- `POST /logout` — 撤销当前会话族（需 CSRF）
- `GET  /sessions` — 查询当前账号的活跃会话清单（建立时间、最近活动时间、
  设备标记、空闲/绝对截止时间、`current` 标记当前端）
- `POST /sessions/revoke` — 定向撤销单台设备（body: `{"session_id":"..."}`，
  需 CSRF；只能撤销自己的会话）
- `POST /rotate-keys` — 轮换签名密钥（旧密钥保留用于历史校验）
- `GET  /audit` — 查看审计事件
- `/**` — 受保护资源，先认证后授权；Cookie 会话的非安全方法需带 `X-CSRF-Token`

快速体验：

```bash
curl -c cj -X POST localhost:8080/login -d '{"username":"alice","password":"alice-pass"}'
curl -b cj "localhost:8080/docs/r1?echo=<script>x</script>"   # 200，注入被转义
curl -b cj -X POST localhost:8080/docs/r1                     # 403 CSRF 缺失
CSRF=$(awk '/csrf_token/{print $7}' cj)
curl -b cj -c cj -H "X-CSRF-Token: $CSRF" -X POST localhost:8080/refresh  # 200，双 Cookie 换新
curl -b cj localhost:8080/sessions                            # 多端会话清单
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " \
  -X POST localhost:8080/login -d '{"username":"bob","password":"x"}'; done
# 401 401 429 429 423 —— 凭据错误 / 限速 / 锁定 三种原因可区分
```

## 认证流程

1. **准入判定**：登录先查限速器。`locked`（阈值已达）与 `throttled`（窗口内失败过多）
   是两种独立结论，分别映射 HTTP `423` 与 `429`，普通凭据错误为 `401`。
2. **凭据校验**：密码为加盐 SHA-256（盐随机 16 字节，`base64(salt‖sha256(salt‖pw))`），
   常量时间比较；用户不存在时执行等量散列以减轻用户名枚举时序差异。
3. **失败累计**：每次失败带唯一 `eventID`，在限速器单把互斥锁内完成“计数+阈值跃迁”。
   并发 N 次失败恰好计 N 次（无丢失更新），且阈值只被一个请求跨越（只产生一次锁定）；
   同一事件重放不重复计数。
4. **签发**：成功后原子执行“容量淘汰 + 会话创建 + 首个刷新令牌”，并用当前 active
   密钥签发访问令牌；每次登录是一个独立会话（一台设备）。
5. **鉴权**：先验签（含过期），再校验服务端会话仍存活——**签名有效不等于可通过**，
   已撤销/已过期会话一律拒绝；成功访问会刷新 `LastActiveAt`。

## 续期链路（Cookie 交付 + 轮换）

- **凭据交付**：访问凭据与刷新凭据都只通过 HttpOnly、`SameSite=Strict` 的 Cookie
  下发；刷新 Cookie 的 `Path` 收窄为 `/refresh`。响应体与日志中绝不出现刷新凭据
  明文（日志/审计里只见 `***REDACTED***`；脱敏只作用于输出，不影响发给客户端的值）。
- **续期**：客户端带 `refresh_token` Cookie 与双提交 CSRF 令牌调用 `POST /refresh`。
  成功后**新访问凭据与新刷新凭据在同一响应中同时生效**（两个 Cookie 一起覆盖），
  新访问凭据立即可访问受保护资源，响应体只回会话标识与有效期。
- **跨站前置校验**：`/refresh`、`/logout`、`/sessions/revoke` 三个会改状态的入口，
  一律先做 CSRF 校验，再触碰任何凭据或会话。缺令牌（`403 csrf: unsafe…`）与
  令牌不匹配（`403 csrf: token mismatch`）分别可辨；被 CSRF 拦下的请求**既不算
  凭据复用，也不会撤销/作废任何正常会话**（有专门 HTTP 用例断言会话与凭据在被拦
  后仍可正常使用）。

## 刷新令牌轮换与复用检测

- 每个会话拥有一个 **family（会话族）**，刷新令牌链挂在该族上。
- 刷新 = 单一临界区内“旧令牌置为 rotated + 新令牌落库”，不存在半更新状态。
- 并发使用同一刷新令牌时：恰好 1 个成功，其余立即被识别（测试覆盖 20 并发 → 1 成功 /
  19 复用拒绝）。
- **复用即失窃信号**：已轮换令牌被再次提交时返回 `ErrRefreshReused`，并连带撤销
  整个会话族——攻击者与原持有人的后续令牌同时失效，绝不静默放行。
- 对外结果严格区分：复用 → HTTP `409`（`session: refresh token reuse detected`）；
  空闲过期 / 绝对过期 → `410`（消息分别为 idle / absolute）；登出、定向撤销、
  容量淘汰导致的撤销 → `401`（session revoked）；未知凭据 → `401` invalid。
- 正常轮换（`Rotated`）与撤销作废（`Invalidated`）分开标记，因此“族已撤销”与
  “令牌复用”两种失败原因始终可区分。
- 登出走族级撤销；**定向撤销只杀单个会话**，同账号其它端完全不受影响。

## 多端会话管理

- 每次登录创建独立会话，可带 `label`（如设备名/UA），服务端记录 `created_at`、
  `last_active_at`（每次认证/续期更新）。
- `GET /sessions` 只返回调用者自己的活跃会话，按建立时间排序，并标记 `current`。
- `POST /sessions/revoke` 定向撤销单台设备，结果严格区分：
  - 成功 → `200`（仅该会话与其当前刷新凭据失效，其它端继续可用）
  - 撤销他人会话 → `403 auth: not the session owner`（记 `revoke_denied/reason=not_owner`，
    目标会话不发生任何变化）
  - 会话不存在 → `404 auth: session not found`（记 `revoke_denied/reason=not_found`）
  - 早已空闲/绝对过期 → `410`；已撤销重复上报 → `409`（幂等 EventID，不重复失效、
    不重复计数）

## 生命周期：空闲窗口、绝对上限与容量

- 每个会话有两个时间：
  - **空闲窗口** `IdleDeadline = 上次活动 + idle_ttl`（默认 30 分钟，测试可注入时钟）。
    续期成功只把空闲窗口向后推（并更新最近活动时间）。
  - **绝对上限** `AbsoluteDeadline = 创建时刻 + absolute_ttl`（默认 24 小时），
    **任何续期都不能突破**；滑动后的空闲截止若超过绝对上限会被钳到绝对上限。
- 空闲过期与绝对过期是两类独立错误（服务层 `ErrSessionIdle` /
  `ErrSessionAbsolute`，HTTP 均为 410 但消息可辨），与撤销/复用不混淆。
- **容量约束**：单账号活跃会话有上限（默认 5，`Config.MaxSessions`）。新登录落库前
  在同一临界区内按 **最久未活动优先**（`LastActiveAt`，再以创建时间、ID 打破平局）
  淘汰最旧会话，使总数不超限；被淘汰会话的刷新凭据**在新会话出现的同一刻即失效**，
  并各记一条 `session_evicted`（`reason=capacity_eviction`）关键审计事件。

## 并发一致性（撤销 vs 续期）

- 会话存储的所有复合变更（轮换、族撤销、单会话撤销、容量淘汰）共用同一把锁；
  因此“撤销与续期撞车”不会留下中间态：已撤销会话不可能换出新令牌；续期成功者的
  旧令牌不可能再被接受（20 轮撤销/续期对撞用例验证两种结局都自洽）。
- 容量淘汰与“新会话 + 首令牌”原子提交，外部永远观察不到“新会话已可见但旧凭据还
  活着”的窗口。

## 密钥策略

- 不变量：**任意时刻至多一个 active 密钥**。`Rotate` 在同一把锁内先退役所有 active
  密钥、再插入新密钥。
- 旧（retired）密钥永不参与签发（`Issue` 只取 `Current`），但仍可校验其在退役前
  签发的未过期凭据——轮换不踢人。
- 异常确定性：
  - 无密钥 → `ErrKeyNotFound` / `token.ErrKeyUnavailable`
  - 外部播种导致两个 active 重叠 → `Current` 确定性返回 `ErrOverlap`，绝不二选一猜测；
    执行一次 `Rotate` 即可恢复为单 active。
  - kid 找不到 → `ErrKeyUnavailable`；签名不匹配 → `ErrBadSignature`；过期 →
    `ErrExpired`，三类错误彼此可区分。

## 访问控制规则

判定顺序固定，**规则注册顺序不影响结论**（有乱序测试证明）：

1. **先跑全部 deny 规则**：任意一条命中即 `explicit_deny`，显式拒绝永远压过授权
   （admin 也无法访问 `/docs/secret/**`）。
2. **再跑 allow 规则**：按 角色 → 动作 → 资源层级 → 作用域 → ABAC 条件 的固定维度
   顺序评估；第一条全中则放行。
3. 全不命中 → `default_deny`，并给出可区分原因：
   `no_matching_policy` / `hierarchy_denied` / `scope_insufficient` /
   `attribute_condition_failed`。
4. **资源层级**：`/docs/**` 覆盖自身与任意深度子级，`/docs/*` 仅覆盖一级子级；
   `/docsy` 这类前缀巧合路径不匹配（段边界判断）。
5. **最小权限收窄**：主体作用域与规则作用域取交集；写操作必须具备 `*:write`（或 `*`）
   作用域，仅有 `docs:read` 的 editor 做 POST 被 `scope_insufficient` 拒绝。
6. **ABAC**：规则可挂 `Condition(sub, res, ctx)`（示例：仅 `dept=sales` 可访问
   `/sales/**`）。

## CSRF、消毒与脱敏

- Cookie 会话的非安全方法（POST/PUT/DELETE…）要求 `csrf_token` Cookie 与
  `X-CSRF-Token` 头双提交一致，常量时间比较；“缺失”（`unsafe method without token`）
  与“不匹配”（`token mismatch`）分别报错。GET/HEAD/OPTIONS 豁免。
- 会改变会话状态的三个入口 `/refresh`、`/logout`、`/sessions/revoke` 在校验任何
  凭据之前先过 CSRF；被拦下的请求不会被识别成复用，也不会触碰正常会话。
- 统一安全响应头：CSP、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
  `Referrer-Policy`、HSTS。
- 所有回显输入经 HTML 转义（`<script>` 不会原样返回）；审计与日志中的
  password/token/secret 一律输出 `***REDACTED***`，邮箱按首字符遮蔽。
  脱敏仅作用于日志/审计等输出通道，写入 HttpOnly Cookie 发给客户端的仍是真实凭据。

## 审计

- 关键事件（`lockout` / `refresh_reuse` / `revoke` / `revoke_denied` /
  `session_evicted` / `session_expired` / `access_denied`）显式打类型标记，
  且可通过 `CriticalEvents` 单独提取，不允许静默丢弃。
- 事件以 `EventID` 幂等落库：重放/重复上报返回 `duplicate=true` 且不再生效，
  因此不会造成重复扣减或重复锁定；同一锁定周期只产生一条 lockout 事件（以
  `LockedUntil` 去重）。
- 定向撤销成功记 `revoke`（`revokeone:<sid>` 去重），越权/不存在记
  `revoke_denied`（原因 `not_owner` / `not_found`）；容量淘汰记 `session_evicted`。
- 无 `EventID` 的事件直接报错，防止事件被意外折叠。

## 并发一致性

- 限速器、会话存储、密钥环、审计 sink 均在单写者锁内完成复合变更；
  刷新“旧令牌失效 + 新令牌生效”、密钥“旧密钥退役 + 新密钥生效”都是原子操作。
- 全量测试在 `go test -race` 下通过，包含 50 并发失败计数、16/20 并发同令牌轮换
  （恰好 1 成功、其余复用拒绝）、20 轮撤销/续期对撞、30 并发登录等场景。

## 验证方法

```bash
go test ./...                     # 全量单测
CGO_ENABLED=1 go test -race ./... # 竞态检测
go vet ./...
go test -v ./...                  # 查看每个用例打印的输入 / 判定依据 / 命中规则
```

测试重点（对应需求）：

- **限速边界**：`internal/ratelimit` —— 阈值跃迁恰好一次、throttle/lock 原因分离、
  事件重放不重复计数、50 并发无丢失更新。
- **令牌复用**：`internal/session` + `internal/auth` —— 复用触发族撤销、正常轮换后
  旧令牌拒绝、撤销与复用原因可区分、并发轮换单赢家。
- **密钥轮换**：`internal/keyring` + `internal/token` —— 退役密钥可验不可签、
  缺密钥/重叠行为确定、篡改与过期错误可区分。
- **越权判定**：`internal/authz` —— 显式拒绝优先（含乱序不变性）、层级模式、
  作用域收窄、ABAC 条件、拒绝原因矩阵。
- **端到端**：`cmd/gateway` —— 真实 HTTP 链路下的登录、CSRF、越权、轮换与
  401/403/423/429 状态码。
  - `TestHTTPRefreshRotationEndToEnd`：登录（Cookie 交付、响应体无刷新凭据）→
    CSRF 拦截可辨 → 续期双 Cookie 换新 → 新访问凭据读受保护资源 → 旧刷新凭据 409
    复用 → 同链凭据全部失效；复用审计恰好 1 条且不含明文。
  - `TestHTTPCSRFFailureDoesNotHarmSession`：缺/错 CSRF 令牌不误伤会话、不算复用。
  - `TestHTTPIdleAndAbsoluteBoundaries`：可控时钟下的空闲/绝对边界（410 消息可辨）。
  - `TestHTTPConcurrentRefreshExactlyOneWinner`：并发续期单赢家。
  - `TestHTTPRevokeVsRefreshAtomic`：撤销与续期并发无中间态。
  - `TestHTTPSessionListRevokeIsolation`：多端清单、定向撤销隔离、越权 403 与
    不存在 404 分离、重复上报幂等。
  - `TestHTTPSessionCapacityEviction`：会话上限 LRU 淘汰、凭据即时失效、审计 1 条。
  - 包级用例另见 `internal/session`（双时间窗口、LRU 淘汰、单会话撤销隔离）与
    `internal/auth`（服务层清单/撤销/淘汰/错误分类）。

> 说明：本组件为本地演示实现，内存数据重启即失；口令哈希使用加盐 SHA-256 而非
> 内存硬化 KDF。接入生产时只需替换 `CredentialStore` / `Store` / `Sink` 三个边界
> 接口，核心判定逻辑无需改动。
