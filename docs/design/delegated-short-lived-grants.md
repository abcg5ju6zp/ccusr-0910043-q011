# 可委托短期授权（Delegated Short-Lived Grants）基线设计

> 适用组件：`jupyter_server.auth.identity` / `jupyter_server.auth.authorizer` / contents 服务
>
> 解决的问题：课题负责人临时向外部审阅者开放某个目录时，不必发放整站长寿命令牌；
> 授权可以逐层转授、只能收窄；上游撤销即时级联；密钥轮换与服务重启后授权链仍可完整验证；
> 审计不泄露未获授权的路径名。

---

## 1. 目标与非目标

### 1.1 目标

1. **短期**：所有委托令牌有秒级/小时级过期时间，默认 1 小时，服务端强制 TTL 上限。
2. **可委托且单调收窄**：持票人可把自己权限的*子集*再授给下游；每一跳只能在
   路径、操作、受众、过期时间、剩余派生深度五个维度上收窄，任何维度放宽都拒绝签发。
3. **级联撤销立即生效**：撤销任一节点，其整棵子树（含已签发到第三方的后代令牌）立即失效；
   重复撤销幂等；撤销状态持久化，重启不丢。
4. **完整链验证**：验证方不只信任叶子令牌，而是能在密钥轮换、服务重启后校验
   根→叶每一跳的签名与收窄关系；任何一环记录缺失即 **fail-closed**。
5. **在途请求一致处理**：读下载与写提交遵循同一条“生效点（linearization point）”规则。
6. **审计最小泄露**：审计存储与查询接口不出现调用者无权看到的路径明文。

### 1.2 非目标

- 不做跨组织联邦身份；受众（audience）是本服务实例内登记的服务/主体标识。
- 不替代现有登录会话（cookie + 长 token 仍用于负责人本人登录）；委托令牌是会话之外的、
  作用域受限的第二条凭证通道。
- 不做细粒度单元格/Notebook 输出级控制；粒度边界是路径 + 操作。

---

## 2. 威胁模型与设计原则

| 威胁 | 对策要点 |
|---|---|
| 长寿命 token 泄露 = 整站失陷 | 委托令牌短 TTL + 路径/操作/受众受限，泄露面有界 |
| 持票人转授时偷偷放大权限 | 服务端（而非持票人）签发子令牌，并逐维做包含性校验 |
| 转发令牌给非预期受众 | `aud` 强制绑定；推荐 PoP（见 §9），无 PoP 时按网络边界部署 |
| 用已撤销的祖辈令牌衍生的叶子令牌继续访问 | 验证时遍历整条祖先链查活，任一祖先被撤销即拒 |
| 路径技巧（`..`、前缀冒充 `/foo`→`/foobar`、符号链接） | 词法规范化 + 路径段边界匹配 + 执行点 `realpath` 复核 |
| 撤销后大文件下载仍在传、写操作缓存在服务端 | 统一的生效点规则（§7） |
| 审计接口本身成为路径名枚举通道 | 路径以密钥化哈希存储；先授权后查询；无结果与无权限不可区分 |
| 签名密钥泄露 / 常规轮换 | 区分常规轮换（旧钥仅验证、重叠期）与紧急吊销（按 `kid` 整体作废） |

原则：**服务端是唯一签发信任锚**。持票人不持有签名密钥，"转授"是持票人向签发端点
出示父令牌、由服务端校验后签发新令牌；因此不需要持票人 PKI，链条伪造等同于伪造服务端签名。

---

## 3. 令牌结构

版本化令牌，头 `typ: DGT1`，签名算法 `EdDSA`（Ed25519；也允许 `HS256` 仅用于单进程部署），
二进制紧凑编码（CBOR）或紧凑 JWS 序列化均可，基线以 JSON claim 描述：

```jsonc
// header
{ "alg": "EdDSA", "typ": "DGT1", "kid": "k-20261006-01" }

// payload
{
  "ver": 1,
  "jti": "01J9X…",          // 本令牌随机标识（撤销/审计主键）
  "root": "01J9W…",         // 根授权 jti（同一棵树恒定）
  "parent": "01J9V…",       // 直接父令牌 jti；根令牌为 null
  "chain": ["01J9W…", "01J9V…"],   // 祖先 jti 有序列表，不含自身
  "links": [{"jti": "01J9W…", "sh": "…"}, {"jti": "01J9V…", "sh": "…"}],
                            // 每跳的作用域指纹，防记录被替换，见 §6.3
  "iss": "srv-a1b2",        // 签发实例 id
  "sub": "reviewer:liwei@partner.example",  // 持票主体
  "aud": "contents-api",    // 受众：只在该服务/主体上下文有效
  "iat": 1780000000, "nbf": 1780000000, "exp": 1780003600,
  "paths": [{"p": "/shared/review-x", "rec": true}],  // 规范化路径前缀
  "act": ["read"],          // 允许操作集合
  "depth": 1,               // 还可向下转授的层数；0 = 叶子，不得再转授
  "seq": 2                  // 距根的跳数；根为 0
}
```

约束：

- `act ∈ {read, write, execute}`，与 `auth/utils.py:HTTP_METHOD_TO_AUTH_ACTION` 对齐
  （GET/HEAD/OPTIONS→read，POST/PUT/PATCH/DELETE→write，WEBSOCKET→execute）。
  集合只做**子集**判断，不定义 write 隐含 read，避免隐含放大。
- `paths[].rec=true` 表示目录递归；`false` 表示仅该对象。
- 根令牌由课题负责人通过已认证会话经 `POST /api/auth/grants` 签发，`depth` 即
  “最大派生深度”。

---

## 4. 单调收窄规则

签发子令牌（delegate）时逐维校验，任一不满足返回 422：

1. **路径**：子路径集合中每一条都必须被父集合覆盖。
   - 双方先做词法规范化（拒绝绝对路径外的内容、解析 `.`/`..`、NFC 归一化、拒绝 NUL）；
   - 递归前缀匹配必须落在**路径段边界**：父 `/foo` 不覆盖 `/foobar`；
   - `rec=false` 的父只允许同一对象、且子也必须 `rec=false`；
   - 执行点（§8）还要用 `realpath` 复核，防止符号链接逃逸。
2. **操作**：`child.act ⊆ parent.act`（集合包含，严格比较）。
3. **受众**：`child.aud` 必须在父令牌允许的受众范围内；根令牌可携带
   `aud_patterns`（登记过的受众 id 列表），每跳只能从剩余列表中选一个并在 `links` 中扣减；
   验证时请求上下文的服务标识必须等于 `aud`，否则按无效令牌处理。
4. **时间**：`child.exp ≤ parent.exp` 且 `child.iat ≥ parent.iat`；
   无论请求多长，`child.exp` 都不得超过服务端配置的 `max_grant_ttl`。
5. **深度**：`parent.depth ≥ 1` 才允许转授；`child.depth ≤ parent.depth - 1`；
   `child.seq = parent.seq + 1`。
6. 子令牌**不得**引入新的路径、操作、受众，不得延长有效期，不得提升深度；
   `sub` 必须显式指定（禁止“持票人即持有人”的空白子令牌）。

`sh`（作用域指纹）= `BLAKE2s(canonical_json(paths, act, aud, exp, depth, seq), key=domain_sep)`，
随令牌签名并在签发登记中保存，使“收窄关系”本身不可被事后改写。

---

## 5. 组件与接口

新增 `jupyter_server/auth/delegation.py`，核心类 `DelegationAuthority(LoggingConfigurable)`：

```python
class DelegationAuthority(LoggingConfigurable):
    key_store = Instance(KeyStore)          # §6.4
    registry  = Instance(GrantRegistry)    # §6.1（SQLite 持久化）

    def issue_root(self, *, subject, aud, paths, actions, ttl, max_depth) -> str
    async def delegate(self, parent_token: str, *, subject, aud, paths,
                       actions, ttl, depth) -> str          # 含全部收窄校验
    async def verify(self, token: str, *, audience: str, path: str,
                     action: str) -> GrantContext            # §6.3
    async def revoke(self, jti: str, *, reason: str) -> None # 幂等级联，§6.2
    async def audit(self, requester_ctx, *, path=None, root=None) -> list[...]
```

HTTP 面（挂到现有 service handler 体系，受既有 `@authorized` 保护）：

| 方法/路径 | 鉴权 | 说明 |
|---|---|---|
| `POST /api/auth/grants` | 登录会话（负责人） | 签发根令牌 |
| `POST /api/auth/delegate` | 父委托令牌 Bearer | 转授（收窄） |
| `DELETE /api/auth/grants/{jti}` | 登录会话，或该 jti 的任一祖先持票人 | 撤销子树 |
| `GET /api/auth/grants` | 登录会话/持票人 | 审计查询，按调用者作用域过滤（§8） |

执行点集成：新增 `ScopedDelegationAuthorizer(Authorizer)`，在
`is_authorized(handler, user, action, resource)` 中从 `Authorization: Bearer`
取出委托令牌，以 `audience=当前服务标识、path=contents 路径实参、action=HTTP 映射操作`
调用 `verify()`；通过则放行，不通过一律 403（与未知令牌同一响应，不区分原因）。
现有静态长 token 通道保持不变，两条通道互斥，令牌优先于 cookie 的既有顺序不变。

---

## 6. 登记、撤销与完整链验证

### 6.1 持久化登记（SQLite，WAL 模式，落盘 fsync）

```sql
CREATE TABLE grants(
  jti        TEXT PRIMARY KEY,
  root       TEXT NOT NULL,
  parent     TEXT,
  seq        INTEGER NOT NULL,
  subject    TEXT NOT NULL,
  aud        TEXT NOT NULL,
  paths_canon TEXT NOT NULL,     -- 规范化 JSON，仅签名/校验路径用；审计不直接读它
  actions    TEXT NOT NULL,
  depth      INTEGER NOT NULL,
  iat        INTEGER NOT NULL,
  exp        INTEGER NOT NULL,
  scope_hash TEXT NOT NULL,
  kid        TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'active'  -- active | revoked
);
CREATE INDEX idx_grants_root ON grants(root);
CREATE TABLE revocations(jti TEXT PRIMARY KEY, at INTEGER NOT NULL,
                         by TEXT NOT NULL, reason TEXT);
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER, ev TEXT,           -- issue | delegate | revoke | deny
  jti TEXT, root TEXT, seq INTEGER, aud TEXT, actions TEXT,
  path_hash TEXT,                -- 只存哈希，见 §8
  result TEXT, reason_code TEXT);
```

每次 issue/delegate/revoke 在**同一事务**里写登记表与审计表；令牌签发与登记原子化，
不存在“签了但查不到”的令牌。

### 6.2 撤销与级联

- 撤销：`INSERT OR IGNORE INTO revocations ...` + 沿 `root` 索引把该 jti 子树
  （`seq` 大于等于自身的后代，可通过签发时物化的 `path_prefix` 或闭包表快速圈定）
  标记。**幂等**：jti 已撤销或已过期都返回成功且语义不变，只在审计留一条 `revoke_duplicate`。
- 立即性：单节点下撤销接口在事务提交后 bump `revocation_version` 并唤醒各事件循环中的
  版本守卫（SQLite `update_hook` 或显式发布）；验证缓存是“不可变集合 + 全局版本号”，
  守卫在写操作提交点与读操作首字节点同步拿最新版本，目标传播延迟 < 100 ms。
  多进程部署以数据库版本号短轮询（亚秒级）兜底，不接受可配置关闭。
- 撤销根 = 全树失效；撤销中间节点 = 子树失效，旁支不受影响。
- 过期行在所有可能引用它的令牌过期后 + 宽限期清理；**撤销墓碑保留期不少于最大 TTL**，
  防止重放旧令牌时查不到撤销记录而误判（fail-closed 兜底：登记表查无此行同样拒绝）。

### 6.3 验证算法（重启与轮换后仍成立）

```text
verify(token, audience, path, action) -> ctx | deny:
  1. 解析头；kid ∈ 已知密钥且未被紧急吊销（§6.4），否则 deny
  2. 用 kid 对应公钥验签；校验 nbf/exp（含 ±60s 时钟容差）、iss 为本实例
  3. audience == token.aud，否则 deny
  4. 打开持久层，在一个快照读事务里：
     a. 取 root 及 chain 中每个 jti 的登记行；任一缺失/状态 revoked → deny（fail-closed）
     b. 校验 links[j].sh == 登记行 scope_hash（链条未被换芯）
     c. 从根到叶重放收窄关系：每跳的 paths/actions/aud/exp/depth 满足 §4，
        seq/parent/root 一致；任一不满足 → deny
     d. 该 jti 不在 revocations（集合相交即拒，O(链条长度) 集合查询）
  5. 请求级判定：path 经词法规范化后按路径段边界被叶子 paths 覆盖；
     action ∈ leaf.act；realpath(path) 仍位于 realpath(授权前缀) 内（防符号链接）
  6. 返回 GrantContext(jti, root, revocation_version)；记一条 deny/allow 审计（path 仅哈希）
```

因为每一跳都由服务端签发、登记并留存 `scope_hash`，验证不依赖内存状态：
**服务重启后只需重新加载密钥库与打开 SQLite，即可重建并验证完整授权链。**
链条长度受 `max_depth` 限制（建议 ≤ 4），遍历成本恒定有界。

### 6.4 密钥轮换

- `KeyStore` 持久文件（私钥 0600；建议接 KMS/Agent 托管），每个密钥带状态：
  `signing | verify_only | retired | compromised`。
- **常规轮换**：生成新 `kid` 置为 signing；旧钥转 verify_only，保留期 = `max_grant_ttl` +
  宽限后转 retired。轮换期间旧令牌无需重签、自然到期，验证靠 `kid` 选钥。
- **紧急吊销**（疑似泄露）：把 `kid` 置 `compromised` 并持久化，验证第 1 步即拒绝
  该 `kid` 签发的**全部**令牌（等价于按签名批次撤销），受影响负责人需重新签发根令牌。
- 轮换本身记审计事件，不含任何路径信息。

---

## 7. 在途请求：统一的“生效点”规则

读与写共用一条规则，而不是各自特判：

> **授权在操作产生可观察效果的瞬间（生效点）以最新撤销版本重新判定；
> 请求到达时的判定只是入场券。**

| 操作类型 | 生效点 | 撤销时序与处理 |
|---|---|---|
| 只读下载 GET | **首字节刷新** | 首字节前被撤销 → 403，不发送任何内容；首字节后允许在**有界排空配额**（默认 30 s 或配置字节数，取先到者）内传完，连接关闭即止。新的 Range/重试请求必须重新验证，已撤销令牌不能开启新区间 |
| 写 PUT/PATCH/DELETE（contents 整文件保存模型） | **原子提交点** | 请求体只写入授权目录下的随机名暂存文件（或不可枚举的服务端暂存区）；提交（fsync + 原子 rename / checkpoint 落盘）前以最新版本重查整条链；已撤销 → 删除暂存文件、返回 403，**磁盘上不留任何可见或可恢复痕迹**。禁止提交点之外的追加写、原地写 |
| execute（kernel/terminal ws） | 每条消息 | 复用现有 ws 鉴权钩子，消息派发前查活；撤销后关闭通道，不执行新消息 |

一致性要点：

- 读的“已开始”以响应头/首字节为准，写的“已开始”**不**构成理由——写在提交前一律可撤且无痕；
  两者判定的都是同一个谓词 `chain_active_at(version)`，只是绑定的生效点不同。
- 若安全策略要求撤销即时掐断下载，可配置 `read_drain=off` 使流式循环每个 chunk 前查活；
  默认开有界排空是出于大文件可用性的显式取舍，且排空上限不可被令牌持有者修改。
- 撤销版本号随 `GrantContext` 贯穿请求，避免“入场时有效、提交时绕过检查”。

---

## 8. 审计与路径名不泄露

1. **存储侧**：`audit_events.path_hash = HMAC-SHA256(canonical_path, audit_path_pepper)`
   （pepper 与签名密钥分开存放、轮换独立）。登记表里的 `paths_canon` 仅供持令牌者
   自己验证链时使用，审计接口**不直接序列化该列**；长期看应把明文列移入加密信封或仅存哈希。
2. **先授权、后查询**：调用 `GET /api/auth/grants?path=P` 时，服务端先用调用者自身凭证
   验证其对 `P` 有 read（审计权），无权则**不做哈希查找**直接返回空页。
3. **不可区分**：“无此路径记录”与“无权查看该路径”返回完全相同的 200 空结果，
   响应大小/耗时做恒定化处理，杜绝存在性侧信道。
4. **列举脱敏**：列表结果只保留与调用者作用域有交集的条目；完全在作用域外的条目整行剔除；
   调用者持有其父前缀但不持有该子路径时，路径显示为 `redacted:<hash8>`，仅暴露
   jti、时间、动作等非路径元数据。
5. **拒绝事件**：403 响应与对外日志只带通用 reason code（如 `denied_scope`），
   不回显请求路径；路径细节仅以哈希进审计表。
6. 审计查询本身也是审计事件（`audit_query` + 参数哈希），可追溯枚举尝试。

---

## 9. 令牌持有与受众绑定

- 传输：`Authorization: Bearer <token>`；不写 cookie（避免被浏览器自动附带、CSRF 面）。
- `aud` 与服务端登记的服务标识强校验；令牌不能跨受众重放。
- 推荐叠加 **PoP**（DPoP 风格客户端签名或 mTLS）：令牌内嵌持票方公钥拇指指纹，
  使用时须证明持有对应私钥，转发令牌本身不再可用。基线实现允许 PoP 关闭，
  关闭时部署文档必须要求传输层与网络边界约束，并在启动时告警。

---

## 10. 边界情形（实现时逐条对照）

| 情形 | 规定行为 |
|---|---|
| 过期发生在下载途中 | 超过 exp 或排空配额即止；续传需新令牌 |
| depth=0 仍调用 delegate | 422 `depth_exhausted` |
| 前缀冒充（`/foo` vs `/foobar`） | 段边界比较，拒绝 |
| `..`、绝对路径注入、NUL、Unicode | 规范化后拒绝非法项；NFC 后再比较 |
| 符号链接指向授权目录外 | 执行点 realpath 复核拒绝 |
| 重复撤销 / 撤销不存在或已过期 jti | 幂等成功；审计记 duplicate/unknown |
| 服务重启 | 重载密钥库 + SQLite；链验证照常；查不到登记行 → fail-closed |
| 常规密钥轮换窗口内重启 | 多 kid 并存选钥，旧令牌持续有效至 exp |
| 紧急 kid 吊销 | 该 kid 全部令牌立即失效，根需重签 |
| 时钟偏移 | nbf/exp ±60 s 容差；以服务端时钟为准 |
| 令牌重放 | jti + aud 绑定；PoP 开启时与持票密钥绑定 |
| 审计查无权路径 | 空结果，与“无记录”不可区分 |
| 写请求在提交前被撤销 | 丢弃暂存内容、403、无落盘痕迹 |
| 数据库不可用/损坏 | 验证 fail-closed（拒绝所有委托令牌），不回退到放行 |

---

## 11. 测试矩阵（`tests/auth/test_delegation.py`）

1. 根签发：TTL 上限截断、必填 subject/aud、未认证拒绝。
2. 五维收窄：路径（含段边界、`rec`、`..`、symlink 逃逸）、动作子集、受众、
   exp 不延长、depth 递减；每维各取放宽用例断言 422。
3. 深度：`max_depth=0` 不可转授；到叶子后再转授拒绝。
4. 级联撤销：撤根/撤中间节点/撤叶子三种位置，全部后代立即 403、旁支仍可用；
   验证传播延迟上限。
5. 幂等撤销：对同一 jti、对已过期 jti 连撤，结果一致、墓碑保留。
6. 重启持久化：签发与撤销后重建 `DelegationAuthority`（新对象、同库），
   完整链验证结果一致；缺登记行 fail-closed。
7. 密钥：常规轮换后旧令牌平滑有效至到期；紧急吊销后旧 kid 令牌全拒；
   轮换窗口内重启。
8. 在途：撤销先于首字节→403；首字节后排空配额内完成、超限掐断；
   写在缓冲后/提交前撤销→403 且目标路径无文件、暂存被清理；提交后撤销不回滚已生效写。
9. 审计：有权路径可查；无权路径与不存在路径响应不可区分；
   列表中越权路径整行剔除或 `redacted:` 呈现；审计表中无明文路径。
10. 对抗：篡改叶子签名、替换中间跳登记（`sh` 不符）、aud 不匹配、
    跨服务重放、超长链（>max_depth）均拒绝。
