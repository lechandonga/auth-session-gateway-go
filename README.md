# auth-session-gateway-go

本地可运行的身份认证与访问控制组件。使用 **纯内存存储** 模拟用户目录、会话、
刷新令牌与签名密钥，无任何外部依赖（仅 Go 标准库），聚焦于在**密钥轮换、并发
请求、异常链路**下给出可验证且一致的结论。

## 1. 目录结构

| 包 | 职责 |
|---|---|
| `internal/model` | 领域类型、拒绝原因枚举、哨兵错误（叶子包） |
| `internal/store` | 内存态、互斥保护的 用户 / 失败计数 / 会话 / 刷新令牌存储 |
| `internal/security` | 签名密钥环（轮换/退役/撤销）、HMAC 紧凑令牌、CSRF、输出转义、字段脱敏、安全头 |
| `internal/audit` | 幂等安全事件审计（按 `DedupKey` 去重） |
| `internal/auth` | 凭据校验、滑动窗口失败计数、账户锁定、按 IP 固定窗口限速 |
| `internal/session` | 会话签发、刷新令牌原子轮换、**复用检测与家族连带撤销**、访问令牌存活校验 |
| `internal/authz` | 顺序无关的 RBAC+ABAC 策略引擎（资源层级 / 作用域收窄 / 显式拒绝优先） |
| `internal/gateway` | HTTP 装配（Cookie、double-submit CSRF、Bearer、安全头） |
| `cmd/server` | 本地可运行 Demo 服务，含种子用户与策略 |

## 2. 认证流程

```
POST /login {username,password}
   │  固定判定顺序（与并发/到达顺序无关）：
   │    1) 输入缺失      -> 400 missing_input
   │    2) IP 限速       -> 429 rate_limited   （按 IP 固定窗口，独立于账户状态）
   │    3) 账户锁定      -> 423 locked         （先于密码校验，不泄露密码正误）
   │    4) 用户不存在/禁用/密码错误 -> 401 bad_credentials（未知用户与错误密码同形，
   │                                                              防用户名枚举）
   │    5) 成功          -> 200，清零失败计数
   ▼
签发：access_token(HMAC) + refresh_token(不透明，仅存 SHA-256 哈希)
      + CSRF token；refresh/session Cookie 置 HttpOnly + SameSite=Strict
```

- **失败累计与锁定**：滑动窗口（`FailWindow`）内失败计数；达到 `MaxFailures`
  在**当次请求**原子翻转锁定，之后的请求（即便密码正确）返回 `locked`，且
  「锁定」事件只产生一次。
- **限速与锁定可区分**：限速是每 IP 固定窗口（429 `rate_limited`），锁定是每
  用户名（423 `locked`）；被限速的请求**不**计入账户失败计数。
- **并发一致性**：所有计数在互斥区内完成。20 个并发错误登录（阈值 10）结果是
  计数恰好 10、锁定事件恰好 1，无漏计、无重复锁定（见 `auth` 包测试）。

## 3. 刷新令牌轮换与复用检测

```
POST /refresh  (Cookie: asg_rt; 头 X-CSRF-Token)
   rotate 是单一互斥区内的 读→校验→CAS 标记轮换→签发后继 原子序列：
     ├─ 令牌不存在/已撤销     -> 401 not_found / revoked
     ├─ 令牌已被轮换过再出现  -> 401 reuse_detected
     │     └─ 立即撤销整个 family 的全部刷新令牌 + 全部会话
     ├─ 会话已撤销/空闲超时/绝对寿命到期 -> 401 session_dead（并防御性撤销家族）
     └─ 首次使用 -> 200，同族后继令牌；旧令牌标记 Rotated
```

- 刷新令牌为不透明随机串，库内只存 `SHA-256(raw)`。
- 同一登录的所有轮换令牌共享 `FamilyID`。
- **并发轮换同一令牌**：恰好 1 个请求成功，第 1 个失败者识别为复用并撤销家族，
  其余失败者看到已撤销家族——结论由互斥序列化决定，与调度无关，绝不静默放行。
- 复用审计事件按 `family+token` 去重，只落一条。

## 4. 签名密钥轮换与历史兼容

密钥环中密钥三态：

| 状态 | 签发 | 校验 |
|---|---|---|
| `active`（全环至多一个） | ✅ | ✅ |
| `retired` | ❌（`ErrRetiredKey`） | ✅ |
| `revoked` | ❌ | ❌（其令牌报 `unknown_kid`） |

- 令牌为 `v1.<base64url(claims)>.<HMAC-SHA256>`，签名所用 `kid` 内嵌于 claims。
- **轮换原子切换**：`Rotate(k2)` 在同一写锁内把新键置 active、旧键置 retired。
  旧密钥签发的未过期凭据轮换后仍可校验；新签发全部使用新键。
- **确定性歧义处理**：
  - 已存在 active 键时再试图激活第二个键 → `ErrOverlappingKeys`，不随机选主；
  - 唯一 active 键被退役且无替代 → 后续签发确定性失败 `ErrMissingKey`；
  - kid 缺失 / 已撤销 → 校验返回 `unknown_kid`（不向前端泄露密钥拓扑）。
- 失败原因精细可区分：`malformed / bad_signature / unknown_kid / expired /
  session_revoked`。签名合法但已过期的令牌报 `expired` 而非笼统失败。

## 5. 访问控制规则（RBAC + ABAC）

策略字段：`effect / roles / actions / resource / scopes / attrMatch`。

- **显式拒绝优先**：两遍扫描所有策略，任何匹配的 `deny` 恒胜过 `allow`，即使
  存在 `*` 通配的 admin 授权。
- **顺序无关**：引擎遍历全部策略而非命中即返回；打乱策略切片顺序结论不变。
- **资源层级**：`a/*` 覆盖 `a/x/y` 子树，但不覆盖兄弟 `b/*`；裸 `*`/空为全捕获，
  不视为具体资源锚点。
- **作用域最小权限收窄**：`docs` 覆盖 `docs:read`；反之 `docs:read` 不覆盖
  `docs` 或 `docs:write`；策略要求的每个 scope 都必须被授予 scope 覆盖。
- **ABAC**：`attrMatch` 所有键必须与主体属性全等（如按 `tenant` 隔离计费数据）。
- **拒绝原因可区分且确定**：`explicit_deny / no_matching_policy / role_mismatch
  / action_mismatch / scope_insufficient / attribute_mismatch`。无具体子树策略
  接近时，通配策略的角色不匹配不会冒充更具体原因（跨租户访问稳定报
  `no_matching_policy`）。

## 6. CSRF、注入与脱敏

- Cookie 会话的所有状态变更接口（`/refresh`、`/logout`、带 Cookie 的
  `/access`、POST `/echo`）强制 double-submit CSRF：Cookie 中的会话 ID 必须与
  `X-CSRF-Token` 头匹配；缺失与不匹配分别返回 `csrf_missing` / `csrf_mismatch`。
- 所有响应带安全头：`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`、
  `Referrer-Policy: no-referrer`、`Strict-Transport-Security`、`Cache-Control: no-store`。
- 不可信输入（回显、错误详情、资源名）在输出前经 `Sanitize` 实体转义，
  `<script>` 等不会原样出现。
- `Redact` 对名称含 `password/hash/secret/token/cookie/authorization` 的字段
  一律输出 `***`；其余短值全遮罩、长值仅留首尾。

## 7. 审计（关键事件不静默、重放不重复）

事件类型：`login_success / login_failure / account_locked / rate_limited /
refresh_token_reuse / session_revoked / refresh_token_rotated / access_denied /
signing_key_rotated / signing_key_retired / csrf_rejected`。

- 记录按 `DedupKey` 幂等：重复上报/重放（如重复撤销、并发复用观察者）不会产生
  重复条目，因此不会造成重复扣减或重复锁定。
- 撤销、锁定、复用、越权、CSRF 拒绝均显式落事件。

## 8. 运行与验证

```bash
# 运行全部单元/集成测试（带 输入/判定依据/命中规则 日志）
go test ./... -v

# 竞态检测（并发不变量）
go test -race ./...

# 启动本地服务（默认 :8080，可用 ASG_ADDR 覆盖）
go run ./cmd/server
# Demo 用户：alice/alice-pw (member)，bob/bob-pw (editor)
```

手工验证示例：

```bash
BASE=http://127.0.0.1:8080
# 1) 登录，保存 Cookie，取出 access_token 与 csrf_token
curl -c cj.txt -s -X POST $BASE/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pw"}'

# 2) 无 CSRF 刷新 -> {"reason":"csrf_missing"}
curl -b cj.txt -s -X POST $BASE/refresh

# 3) 合法刷新后再用旧 refresh -> {"reason":"reuse_detected",...}
# 4) member 写 docs -> 403 action_mismatch；读 docs/sealed/x -> 403 explicit_deny
# 5) 连续错误密码 5 次 -> 第 6 次（正确密码）423 locked
curl -s "$BASE/echo?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
# -> {"echo":"&lt;script&gt;alert(1)&lt;&#47;script&gt;"}（注入不原样回显）
```

测试以**越权、令牌复用、密钥轮换、限速边界**为核心，关键用例：

| 测试 | 验证内容 |
|---|---|
| `auth.TestLockoutBoundaryAndDistinctFromRateLimit` | 阈值锁定、423/429 区分、滑窗清理 |
| `auth.TestConcurrentFailuresNoLostOrDoubleCount` | 20 并发失败：计数=10、锁定事件=1 |
| `session.TestRotationChainAndReuseRevokesFamily` | 轮换链 + 复用连带家族失效 |
| `session.TestRevokeIdempotentAndConcurrentRotate` | 撤销幂等；50 并发轮换：1 成功/1 复用/48 已撤销 |
| `session.TestSigningKeyRetiredDuringSession` | 轮换期旧令牌可校验、新令牌用新键 |
| `security.TestKeyRingRotationAndHistory` | 退役可校验、撤销不可校验、重叠/缺失确定性 |
| `authz.*` | 显式拒绝优先、顺序无关、跨租户拒绝、作用域收窄、原因稳定 |
| `gateway.TestEndToEndLoginAccessCSRFRotation` | HTTP 全链路：CSRF、复用、越权、审计齐备 |

## 9. 设计边界（本地模拟说明）

- 密码哈希为带每用户随机盐的 SHA-256（零依赖、确定性可测），用于模拟本地凭据
  存储，不宣称达到生产级 KDF（如 Argon2）强度。
- 全部状态在内存，重启即重置；HMAC 密钥为演示值。
- Cookie 置 `Secure`，本地用 curl 测试不受影响；接入 HTTPS 前置代理后可直接使用。
