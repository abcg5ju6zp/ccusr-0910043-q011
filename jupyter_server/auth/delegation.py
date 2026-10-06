"""可委托短期授权（衰减能力令牌 / attenuating capability tokens）。

为外部审阅者等临时访问场景签发可转授的短期授权，每次转授只能在路径、
操作、受众和剩余派生深度上收窄，不能放宽。授权链上任一祖先被撤销，其
全部后代立即失效；签发索引、撤销记录与在途下载租约持久化到文件，服务
重启、密钥轮换后仍能验证完整授权链。

令牌是一个自包含的信封（紧凑 base64url）::

    D1.<base64url(JSON)>

JSON 为 ``{"chain": [node, ...]}``，节点自根向叶排列。每个节点::

    {
      "v": "D1", "id": "<随机>", "parent": "<父节点 id，根为空串>",
      "sub": "<签发/转授主体>", "aud": "<受众>",
      "paths": ["/*规范化前缀"], "ops": ["read|download|write"],
      "depth": <剩余可派生层数>, "iat": <签发时间>, "exp": <过期时间>,
      "kid": "<签名密钥代次>", "sig": "<HMAC-SHA256 签名>"
    }

每一跳用签发时刻的活动密钥（按 ``kid`` 区分代次）单独签名，签名负载是
该节点的规范化 JSON。验证者无需在线获取祖先：出示叶子即出示整条链，
逐跳重放签名、收窄关系、时限与撤销状态即可。

安全语义：
- 转授只能收窄：路径必须被父代覆盖、操作必须是子集、受众只能由通配
  ``"*"`` 收窄为具体受众、后代 ``exp`` 不得晚于祖先、深度每跳减一。
- 级联撤销：链上任一节点 id 出现在撤销集中，整链立即失效；撤销只需
  记录被撤节点 id，不依赖枚举后代，因此没有撤销传播延迟。
- 在途操作一致性：只读下载在开始时取得持久化租约，撤销/过期后仅在
  可配置宽限期内允许完成（默认可设为 0 立即切断）；写操作在提交点
  重新全量校验，不享受宽限，未提交写在授权失效后一律拒绝。
- 审计脱敏：审计事件流从不记录路径明文，仅记录其 SHA-256 摘要用于
  关联；面向部分授权审阅者的查询把未获授权的路径替换为
  ``redacted:<摘要前缀>``，不泄露路径名称。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import threading
import time
import typing as t
import uuid
from collections import deque
from dataclasses import dataclass

from traitlets import Integer, Unicode, validate
from traitlets.config import LoggingConfigurable

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

SCHEME_VERSION = "D1"
STATE_VERSION = "DS1"

#: 允许出现在令牌中的操作，顺序即规范化排序。
KNOWN_OPS = ("read", "download", "write")

#: 整站 / 任意受众通配。
WILDCARD = "*"

_KEYS_FILE = "delegation_keys.json"
_STATE_FILE = "delegation_state.json"

_AUDIT_TAIL = 1000


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class DelegationError(Exception):
    """委托授权相关错误的基类。"""


class InvalidTokenError(DelegationError):
    """令牌无法解析或结构不合法。"""


class InvalidSignatureError(DelegationError):
    """某一跳签名验证失败。"""


class UnknownKeyError(DelegationError):
    """签名密钥代次不在受信密钥环中（可能已被清除或状态被篡改）。"""


class ScopeNarrowingError(DelegationError):
    """转授试图放宽父代的路径、操作或受众。"""


class DepthExhaustedError(DelegationError):
    """剩余派生深度为 0，不能继续转授。"""


class TokenExpiredError(DelegationError):
    """令牌已过期。"""


class TokenNotBeforeError(DelegationError):
    """令牌尚未生效。"""


class TokenRevokedError(DelegationError):
    """授权链上存在被撤销的祖先（或自身）。"""


class AudienceMismatchError(DelegationError):
    """出示方不是令牌的目标受众。"""


class HolderMismatchError(DelegationError):
    """出示者不是令牌的登记持有者（sub）。"""


class PathDeniedError(DelegationError):
    """请求路径不在授权范围内。"""


class OperationDeniedError(DelegationError):
    """请求操作不在授权范围内。"""


class LeaseError(DelegationError):
    """下载租约不存在或已过宽限期。"""


class TamperedStateError(DelegationError):
    """持久化状态未通过完整性校验。"""


# ---------------------------------------------------------------------------
# 规范化与纯函数
# ---------------------------------------------------------------------------


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as e:
        msg = "invalid base64 in token"
        raise InvalidTokenError(msg) from e


def _canon(payload: t.Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def norm_paths(paths: t.Iterable[str]) -> tuple[str, ...]:
    """把路径前缀规范化为去重排序的元组，``*`` 表示整站。

    前缀采用段边界匹配（``/foo`` 不覆盖 ``/foobar``）。拒绝 ``..`` 穿越。
    """
    if isinstance(paths, str):
        paths = (paths,)
    out: set[str] = set()
    found = False
    for p in paths:
        found = True
        if not isinstance(p, str) or not p.strip():
            msg = f"path prefix must be a non-empty string, got {p!r}"
            raise ValueError(msg)
        token = p.strip()
        if token == WILDCARD:
            out.add(WILDCARD)
            continue
        token = token.replace("\\", "/")
        segments = [s for s in token.split("/") if s and s != "."]
        if any(s == ".." for s in segments):
            msg = f"path prefix must not contain '..': {p!r}"
            raise ValueError(msg)
        out.add("/" + "/".join(segments))
    if not found:
        msg = "at least one path prefix required"
        raise ValueError(msg)
    return tuple(sorted(out))


def norm_ops(ops: t.Iterable[str]) -> tuple[str, ...]:
    """规范化操作集合并校验为已知操作的非空子集。"""
    if isinstance(ops, str):
        ops = (ops,)
    ops = tuple(ops)
    if not ops:
        msg = "at least one operation required"
        raise ValueError(msg)
    bad = [o for o in ops if o not in KNOWN_OPS]
    if bad:
        msg = f"unknown operations {bad!r}, valid: {KNOWN_OPS}"
        raise ValueError(msg)
    return tuple(sorted(set(ops)))


def norm_aud(aud: str | None) -> str:
    """受众必须是非空字符串；``*`` 表示可在首次转授时收窄为任意受众。"""
    if aud is None or not isinstance(aud, str) or not aud.strip():
        msg = "audience must be a non-empty string"
        raise ValueError(msg)
    return aud.strip()


def path_covers(parent_paths: t.Iterable[str], child_path: str) -> bool:
    """父代路径前缀集合是否覆盖单个（已规范化的）子路径。

    采用段边界匹配：``/foo`` 覆盖 ``/foo`` 与 ``/foo/bar``，但不覆盖
    ``/foobar``。
    """
    if WILDCARD in parent_paths:
        return True
    if child_path == WILDCARD:
        return False
    return any(
        child_path == pp or child_path.startswith(pp.rstrip("/") + "/")
        for pp in parent_paths
    )


def paths_narrower(parent_paths: t.Iterable[str], child_paths: t.Iterable[str]) -> bool:
    """子路径集合是否被父路径集合完全覆盖（路径维度收窄）。"""
    if WILDCARD in child_paths:
        return WILDCARD in parent_paths
    return all(path_covers(parent_paths, cp) for cp in child_paths)


def audience_narrower(parent_aud: str, child_aud: str) -> bool:
    """受众维度收窄。

    ``aud`` 是凭证的目标受众（可在何处出示）：根可为通配 ``"*"``，第一次
    转授必须绑定为具体受众，此后各跳保持该具体受众（允许相等），永远不
    能退回通配。持有者身份（``sub``）随转授更换，不属于受众维度。
    """
    if child_aud == WILDCARD:
        return False
    if parent_aud == WILDCARD:
        return True
    return parent_aud == child_aud


def path_hash(path: str) -> str:
    """路径的不可逆短摘要，供审计事件关联而不泄露名称。"""
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:12]


def redact_paths(
    paths: t.Iterable[str], viewer_paths: t.Iterable[str] | None = None
) -> list[str]:
    """按审阅者被授权的路径前缀对路径做脱敏。

    审阅者覆盖范围内的路径原样返回；未获授权的路径只暴露稳定摘要，
    通配 ``*`` 不视为敏感路径名。
    """
    if WILDCARD in (viewer_paths or ()):
        return list(paths)
    result: list[str] = []
    for p in paths:
        if p == WILDCARD:
            result.append(p)
        elif viewer_paths and path_covers(viewer_paths, p):
            result.append(p)
        else:
            result.append(f"redacted:{path_hash(p)}")
    return result


# ---------------------------------------------------------------------------
# 只读视图
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Verification:
    """一次成功校验后呈现给调用方的叶子授权视图。"""

    token_id: str
    chain_ids: tuple[str, ...]
    subject: str
    audience: str
    paths: tuple[str, ...]
    ops: tuple[str, ...]
    depth: int
    issued_at: float
    expires_at: float

    def covers(self, path: str, op: str) -> bool:
        return op in self.ops and path_covers(self.paths, norm_paths((path,))[0])


@dataclass(frozen=True)
class DownloadLease:
    """在途只读下载租约。"""

    lease_id: str
    token_id: str
    path: str
    deadline: float
    #: 授权链全部节点 id，用于判定祖先撤销。
    chain_ids: tuple[str, ...] = ()
    #: True 时 path 字段存放的是路径摘要（服务重启后从状态文件还原）。
    is_hash: bool = False


@dataclass
class _Revocation:
    token_id: str
    revoked_at: float
    revoked_by: str
    reason: str

    def as_record(self) -> dict[str, t.Any]:
        return {
            "token_id": self.token_id,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
            "reason": self.reason,
        }

    @classmethod
    def from_record(cls, rec: dict[str, t.Any]) -> "_Revocation":
        return cls(
            token_id=rec["token_id"],
            revoked_at=float(rec["revoked_at"]),
            revoked_by=rec["revoked_by"],
            reason=rec["reason"],
        )


# ---------------------------------------------------------------------------
# 主体组件
# ---------------------------------------------------------------------------


class DelegationAuthority(LoggingConfigurable):
    """签发、转授、校验与撤销短期可委托授权。

    ``state_dir`` 为空时以纯内存模式运行（测试用）；指向目录时把密钥环、
    签发索引、撤销集与下载租约落盘，多个进程/重启后状态一致。
    """

    state_dir = Unicode(
        "",
        config=True,
        help="目录路径：持久化密钥环、撤销集、签发索引与下载租约；空为纯内存。",
    )

    root_issuer = Unicode(
        "root",
        config=True,
        help="根令牌签发者标识，记录在根节点 sub 字段与审计事件中。",
    )

    max_depth = Integer(
        3,
        config=True,
        help="根令牌允许的最大派生深度；每转授一层剩余深度减一，归零不可再转授。",
    )

    default_ttl = Integer(
        900,
        config=True,
        help="签发令牌的默认有效期（秒）。",
    )

    max_ttl = Integer(
        3600,
        config=True,
        help="单张令牌允许的最长有效期（秒），短期授权的硬上限。",
    )

    download_grace = Integer(
        300,
        config=True,
        help=(
            "只读下载在授权失效后的完成宽限期（秒）；0 表示撤销/过期立即切断。"
            " 写操作从不享受宽限。"
        ),
    )

    @validate("max_depth")
    def _validate_max_depth(self, proposal):
        if proposal["value"] < 0:
            msg = "max_depth must be >= 0"
            raise ValueError(msg)
        return proposal["value"]

    @validate("default_ttl", "max_ttl", "download_grace")
    def _validate_nonneg(self, proposal):
        if proposal["value"] < 0:
            msg = f"{proposal['trait'].name} must be >= 0"
            raise ValueError(msg)
        return proposal["value"]

    def __init__(self, **kwargs: t.Any) -> None:
        super().__init__(**kwargs)
        self._lock = threading.RLock()
        self._audit: deque[dict[str, t.Any]] = deque(maxlen=_AUDIT_TAIL)
        # kid -> 密钥字节；旧代次保留以验证轮换前签发的链。
        self._keys: dict[str, bytes] = {}
        self._active_kid = ""
        # token id -> 签发索引记录
        self._registry: dict[str, dict[str, t.Any]] = {}
        # token id -> _Revocation
        self._revoked: dict[str, _Revocation] = {}
        # lease id -> DownloadLease
        self._leases: dict[str, DownloadLease] = {}

        if self.state_dir:
            os.makedirs(self.state_dir, exist_ok=True)
            self._load_keys()
            self._load_state()
        else:
            self._activate_new_key()

    # -- 时间注入 -----------------------------------------------------------

    @staticmethod
    def _now(now: float | None) -> float:
        return time.time() if now is None else float(now)

    # -- 审计 ---------------------------------------------------------------

    def _audit_event(self, kind: str, **fields: t.Any) -> None:
        """记录审计事件。

        路径明文绝不进入事件：调用方只能传 ``path_hashes`` / ``path_count``
        / ``whole_site``，不得传 ``path``。这里做一道防御性检查。
        """
        if "path" in fields or "paths" in fields:
            msg = "audit events must use path_hashes, never raw paths"
            raise AssertionError(msg)
        event = {"t": time.time(), "event": kind}
        event.update(fields)
        self._audit.append(event)
        self.log.info("delegation-audit %s", json.dumps(event, default=str, sort_keys=True))

    def audit_events(self) -> list[dict[str, t.Any]]:
        """返回近期审计事件副本（路径仅以摘要形式出现）。"""
        with self._lock:
            return list(self._audit)

    # -- 密钥环 -------------------------------------------------------------

    def _activate_new_key(self) -> str:
        kid = uuid.uuid4().hex[:12]
        self._keys[kid] = os.urandom(32)
        self._active_kid = kid
        return kid

    def _keys_path(self) -> str:
        return os.path.join(self.state_dir, _KEYS_FILE)

    def _state_path(self) -> str:
        return os.path.join(self.state_dir, _STATE_FILE)

    def _load_keys(self) -> None:
        path = self._keys_path()
        if not os.path.exists(path):
            self._activate_new_key()
            self._save_keys()
            return
        with open(path, encoding="utf-8") as fh:
            blob = json.load(fh)
        try:
            active = blob["active"]
            keys = blob["keys"]
            ring = {kid: _b64d(val) for kid, val in keys.items()}
        except (KeyError, TypeError) as e:
            msg = "key ring file is malformed"
            raise TamperedStateError(msg) from e
        if active not in ring:
            msg = "active key id is missing from key ring"
            raise TamperedStateError(msg)
        self._keys = ring
        self._active_kid = active

    def _save_keys(self) -> None:
        blob = {
            "active": self._active_kid,
            "keys": {kid: _b64e(key) for kid, key in self._keys.items()},
        }
        self._atomic_write(self._keys_path(), json.dumps(blob, indent=2, sort_keys=True))

    def rotate_key(self) -> str:
        """生成新代次签名密钥并设为活动密钥；旧代次保留用于验证旧链。"""
        with self._lock:
            kid = self._activate_new_key()
            if self.state_dir:
                self._save_keys()
            self._audit_event("key_rotated", kid=kid, retained_generations=len(self._keys))
            return kid

    @property
    def active_key_id(self) -> str:
        return self._active_kid

    # -- 持久化状态（逐条 HMAC 防篡改） -------------------------------------

    def _seal(self, record: dict[str, t.Any]) -> dict[str, t.Any]:
        rec = dict(record)
        # 使用独立的 seal_kid，避免覆盖业务字段中节点自身的签名代次 kid。
        rec["seal_kid"] = self._active_kid
        body = {k: v for k, v in rec.items() if k != "hmac"}
        rec["hmac"] = _b64e(
            hmac.new(self._keys[self._active_kid], _canon(body), hashlib.sha256).digest()
        )
        return rec

    def _check_seal(self, rec: dict[str, t.Any]) -> None:
        kid = rec.get("seal_kid")
        tag = rec.get("hmac")
        if not isinstance(kid, str) or not isinstance(tag, str):
            msg = "state record is missing integrity tag"
            raise TamperedStateError(msg)
        key = self._keys.get(kid)
        if key is None:
            msg = f"state record references unknown key generation {kid!r}"
            raise TamperedStateError(msg)
        body = {k: v for k, v in rec.items() if k != "hmac"}
        expected = hmac.new(key, _canon(body), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(tag)):
            msg = "state record failed integrity check"
            raise TamperedStateError(msg)

    def _atomic_write(self, path: str, text: str) -> None:
        tmp = f"{path}.tmp.{uuid.uuid4().hex}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _save_state(self) -> None:
        if not self.state_dir:
            return
        blob = {
            "version": STATE_VERSION,
            "revoked": [self._seal(r.as_record()) for r in self._revoked.values()],
            "leases": [
                self._seal(
                    {
                        "lease_id": l.lease_id,
                        "token_id": l.token_id,
                        "path_hash": path_hash(l.path) if not l.is_hash else l.path,
                        "deadline": l.deadline,
                        "chain_ids": list(l.chain_ids),
                    }
                )
                for l in self._leases.values()
            ],
            # 签发索引保留路径明文以便重启后继续做前缀判定；整条记录经
            # HMAC 密封防篡改。对外查询的路径名称脱敏在查询层强制执行。
            "registry": [self._seal(rec) for rec in self._registry.values()],
        }
        self._atomic_write(self._state_path(), json.dumps(blob, indent=2, sort_keys=True))

    def _load_state(self) -> None:
        path = self._state_path()
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as fh:
            blob = json.load(fh)
        if not isinstance(blob, dict) or blob.get("version") != STATE_VERSION:
            msg = "state file version is missing or unknown"
            raise TamperedStateError(msg)
        for rec in blob.get("revoked", []):
            self._check_seal(rec)
            rev = _Revocation.from_record(rec)
            self._revoked[rev.token_id] = rev
        for rec in blob.get("leases", []):
            self._check_seal(rec)
            lease = DownloadLease(
                lease_id=rec["lease_id"],
                token_id=rec["token_id"],
                # 路径明文不落状态文件：重启后仅保留摘要供审计关联。
                path=rec["path_hash"],
                deadline=float(rec["deadline"]),
                chain_ids=tuple(rec.get("chain_ids", ())),
                is_hash=True,
            )
            self._leases[lease.lease_id] = lease
        for rec in blob.get("registry", []):
            self._check_seal(rec)
            tid = rec["token_id"]
            self._registry[tid] = rec
        self._audit_event(
            "state_loaded",
            revocations=len(self._revoked),
            leases=len(self._leases),
            registrations=len(self._registry),
        )

    # -- 令牌编解码与签名 ---------------------------------------------------

    def _sign_node(self, node: dict[str, t.Any]) -> dict[str, t.Any]:
        signed = dict(node)
        signed["kid"] = self._active_kid
        signed["sig"] = _b64e(
            hmac.new(self._keys[self._active_kid], _canon(node_payload(signed)),
                     hashlib.sha256).digest()
        )
        return signed

    def _encode(self, chain: list[dict[str, t.Any]]) -> str:
        envelope = _b64e(_canon({"chain": chain}))
        return f"{SCHEME_VERSION}.{envelope}"

    @staticmethod
    def _decode(token: str) -> list[dict[str, t.Any]]:
        if not isinstance(token, str) or token.count(".") != 1:
            msg = "malformed delegation token"
            raise InvalidTokenError(msg)
        version, envelope = token.split(".", 1)
        if version != SCHEME_VERSION:
            msg = f"unsupported token version {version!r}"
            raise InvalidTokenError(msg)
        try:
            blob = json.loads(_b64d(envelope))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            msg = "token envelope is not valid JSON"
            raise InvalidTokenError(msg) from e
        chain = blob.get("chain") if isinstance(blob, dict) else None
        if not isinstance(chain, list) or not chain:
            msg = "token must carry a non-empty chain"
            raise InvalidTokenError(msg)
        return chain

    def _build_node(
        self,
        *,
        parent: str,
        subject: str,
        aud: str,
        paths: tuple[str, ...],
        ops: tuple[str, ...],
        depth: int,
        iat: float,
        exp: float,
    ) -> dict[str, t.Any]:
        node = {
            "v": SCHEME_VERSION,
            "id": uuid.uuid4().hex,
            "parent": parent,
            "sub": subject,
            "aud": aud,
            "paths": list(paths),
            "ops": list(ops),
            "depth": depth,
            "iat": iat,
            "exp": exp,
        }
        return self._sign_node(node)

    # -- 签发 ---------------------------------------------------------------

    def issue_root(
        self,
        *,
        paths: t.Iterable[str],
        ops: t.Iterable[str],
        aud: str | None = None,
        ttl: int | None = None,
        depth: int | None = None,
        subject: str | None = None,
        now: float | None = None,
    ) -> str:
        """由身份组件直接签发根授权。

        整站权限（``paths=("*",)``）只允许出现在根上；任何转授都只能把它
        收窄为具体前缀。根令牌同样受短期 TTL、深度与撤销约束。
        """
        with self._lock:
            ts = self._now(now)
            npaths = norm_paths(paths)
            nops = norm_ops(ops)
            naud = WILDCARD if aud is None else norm_aud(aud)
            ttl = self.default_ttl if ttl is None else ttl
            if ttl <= 0 or ttl > self.max_ttl:
                msg = f"ttl must be in (0, {self.max_ttl}]"
                raise ValueError(msg)
            if depth is None:
                depth = self.max_depth
            if depth < 0 or depth > self.max_depth:
                msg = f"depth must be in [0, {self.max_depth}]"
                raise ValueError(msg)
            issuer = subject or self.root_issuer
            node = self._build_node(
                parent="",
                subject=issuer,
                aud=naud,
                paths=npaths,
                ops=nops,
                depth=depth,
                iat=ts,
                exp=ts + ttl,
            )
            token = self._encode([node])
            self._register(node, parent_id="", whole_site=WILDCARD in npaths)
            self._save_state()
            self._audit_event(
                "root_issued",
                token_id=node["id"],
                subject=issuer,
                aud=naud,
                ops=list(nops),
                path_count=len(npaths),
                path_hashes=[path_hash(p) for p in npaths if p != WILDCARD],
                whole_site=WILDCARD in npaths,
                depth=depth,
                ttl=ttl,
                kid=node["kid"],
            )
            return token

    def delegate(
        self,
        parent_token: str,
        *,
        paths: t.Iterable[str],
        ops: t.Iterable[str],
        aud: str | None = None,
        ttl: int | None = None,
        subject: str,
        now: float | None = None,
    ) -> str:
        """由当前持有者转授一张收窄后的后代令牌。

        父代必须通过在线校验（未过期、链上无撤销）。路径、操作、受众、
        有效期与深度一律只能收窄；剩余深度为 0 时拒绝。
        """
        with self._lock:
            ts = self._now(now)
            parent_chain = self._decode(parent_token)
            # 在线校验父代：签名/结构/时限/撤销全部通过才允许派生。
            parent_view = self._verify_chain(parent_chain, ts)
            leaf = parent_chain[-1]

            npaths = norm_paths(paths)
            nops = norm_ops(ops)
            naud = norm_aud(aud) if aud is not None else leaf["aud"]
            if aud is None and leaf["aud"] == WILDCARD:
                msg = "parent audience is wildcard; child audience must be specified"
                raise ScopeNarrowingError(msg)

            if leaf["depth"] < 1:
                msg = f"token {leaf['id'][:8]} has no remaining delegation depth"
                raise DepthExhaustedError(msg)
            if not paths_narrower(leaf["paths"], npaths):
                msg = "delegation may only narrow path prefixes"
                raise ScopeNarrowingError(msg)
            if not set(nops).issubset(set(leaf["ops"])):
                msg = "delegation may only narrow operations"
                raise ScopeNarrowingError(msg)
            if not audience_narrower(leaf["aud"], naud):
                msg = "delegation may only narrow the audience"
                raise ScopeNarrowingError(msg)
            # 整站通配只允许停留在根上：转授必须落到具体前缀。
            if WILDCARD in npaths:
                msg = "delegation must bind wildcard to concrete path prefixes"
                raise ScopeNarrowingError(msg)

            remaining_ttl = leaf["exp"] - ts
            ttl = self.default_ttl if ttl is None else ttl
            if ttl <= 0:
                msg = "ttl must be positive"
                raise ValueError(msg)
            if ttl > self.max_ttl:
                msg = f"ttl must be <= {self.max_ttl}"
                raise ValueError(msg)
            # 后代不得晚于祖先过期：派生凭证随上游失效而失效。
            if ttl > remaining_ttl + 1e-6:
                msg = "child token must not outlive its parent"
                raise ScopeNarrowingError(msg)

            node = self._build_node(
                parent=leaf["id"],
                subject=subject,
                aud=naud,
                paths=npaths,
                ops=nops,
                depth=leaf["depth"] - 1,
                iat=ts,
                exp=ts + ttl,
            )
            token = self._encode([*parent_chain, node])
            self._register(node, parent_id=leaf["id"], whole_site=WILDCARD in npaths)
            self._save_state()
            self._audit_event(
                "delegated",
                token_id=node["id"],
                parent_id=leaf["id"],
                subject=subject,
                aud=naud,
                ops=list(nops),
                path_count=len(npaths),
                path_hashes=[path_hash(p) for p in npaths if p != WILDCARD],
                whole_site=WILDCARD in npaths,
                depth=node["depth"],
                ttl=ttl,
                kid=node["kid"],
            )
            return token

    def _register(self, node: dict[str, t.Any], *, parent_id: str, whole_site: bool) -> None:
        self._registry[node["id"]] = {
            "token_id": node["id"],
            "parent_id": parent_id,
            "subject": node["sub"],
            "aud": node["aud"],
            "paths": list(node["paths"]),
            "ops": list(node["ops"]),
            "depth": node["depth"],
            "iat": node["iat"],
            "exp": node["exp"],
            "whole_site": whole_site,
            "kid": node["kid"],
        }

    # -- 校验 ---------------------------------------------------------------

    def _verify_signature(self, node: dict[str, t.Any]) -> None:
        kid = node.get("kid")
        tag = node.get("sig")
        key = self._keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            self._audit_event("verify_denied", reason="unknown_key", kid=kid)
            msg = f"unknown key generation {kid!r}"
            raise UnknownKeyError(msg)
        try:
            expected = hmac.new(key, _canon(node_payload(node)), hashlib.sha256).digest()
        except TypeError as e:
            msg = "token node has non-scalar fields"
            raise InvalidTokenError(msg) from e
        if not isinstance(tag, str) or not hmac.compare_digest(expected, _b64d(tag)):
            self._audit_event("verify_denied", reason="bad_signature", kid=kid)
            msg = "signature mismatch"
            raise InvalidSignatureError(msg)

    def _verify_chain(self, chain: list[dict[str, t.Any]], ts: float) -> Verification:
        """重放整条授权链：签名、结构、收窄、时限、撤销。"""
        seen: set[str] = set()
        prev: dict[str, t.Any] | None = None
        for index, node in enumerate(chain):
            if not isinstance(node, dict):
                msg = "chain node must be an object"
                raise InvalidTokenError(msg)
            required = {"v", "id", "parent", "sub", "aud", "paths", "ops", "depth", "iat",
                        "exp", "kid", "sig"}
            if not required.issubset(node):
                msg = f"chain node {index} is missing fields"
                raise InvalidTokenError(msg)
            if node["v"] != SCHEME_VERSION:
                msg = f"unsupported node version at index {index}"
                raise InvalidTokenError(msg)
            tid = node["id"]
            if not isinstance(tid, str) or not tid or tid in seen:
                msg = "duplicate or empty node id in chain"
                raise InvalidTokenError(msg)
            seen.add(tid)

            try:
                npaths = norm_paths(node["paths"])
                nops = norm_ops(node["ops"])
                naud = norm_aud(node["aud"])
                depth = int(node["depth"])
                iat = float(node["iat"])
                exp = float(node["exp"])
            except (TypeError, ValueError) as e:
                msg = f"chain node {index} has malformed claims"
                raise InvalidTokenError(msg) from e
            if iat >= exp:
                msg = f"chain node {index} has iat >= exp"
                raise InvalidTokenError(msg)
            if not isinstance(node["sub"], str) or not node["sub"]:
                msg = f"chain node {index} has empty subject"
                raise InvalidTokenError(msg)

            if index == 0:
                if node["parent"] != "":
                    msg = "root node must have empty parent"
                    raise InvalidTokenError(msg)
                if depth < 0 or depth > self.max_depth:
                    msg = "root depth exceeds configured maximum"
                    raise InvalidTokenError(msg)
            else:
                assert prev is not None
                if node["parent"] != prev["id"]:
                    msg = f"chain node {index} is not linked to its predecessor"
                    raise InvalidTokenError(msg)
                if depth != int(prev["depth"]) - 1 or depth < 0:
                    msg = "delegation depth must decrease by exactly one per hop"
                    raise InvalidTokenError(msg)
                prev_paths = tuple(prev["paths"])
                if not paths_narrower(prev_paths, npaths):
                    msg = f"chain node {index} widens path scope"
                    raise ScopeNarrowingError(msg)
                if not set(nops).issubset(set(prev["ops"])):
                    msg = f"chain node {index} widens operations"
                    raise ScopeNarrowingError(msg)
                if not audience_narrower(prev["aud"], naud):
                    msg = f"chain node {index} widens audience"
                    raise ScopeNarrowingError(msg)
                if iat < float(prev["iat"]) - 1e-6:
                    msg = f"chain node {index} predates its parent"
                    raise InvalidTokenError(msg)
                if exp > float(prev["exp"]) + 1e-6:
                    msg = f"chain node {index} outlives its parent"
                    raise InvalidTokenError(msg)
                if WILDCARD in npaths:
                    msg = f"chain node {index} keeps wildcard path beyond root"
                    raise InvalidTokenError(msg)

            self._verify_signature(node)
            prev = node

        leaf = chain[-1]
        if ts < float(leaf["iat"]):
            self._audit_event("verify_denied", reason="not_before", token_id=leaf["id"])
            msg = "token is not valid yet"
            raise TokenNotBeforeError(msg)
        if ts >= float(leaf["exp"]):
            self._audit_event("verify_denied", reason="expired", token_id=leaf["id"])
            msg = "token has expired"
            raise TokenExpiredError(msg)
        # 级联撤销：链上任一节点被撤，整条链立即失效，与跳数无关。
        for tid in seen:
            if tid in self._revoked:
                self._audit_event(
                    "verify_denied",
                    reason="revoked",
                    token_id=leaf["id"],
                    revoked_ancestor=tid[:8],
                )
                msg = "token or one of its ancestors has been revoked"
                raise TokenRevokedError(msg)

        return Verification(
            token_id=leaf["id"],
            chain_ids=tuple(chain_node_ids(chain)),
            subject=leaf["sub"],
            audience=leaf["aud"],
            paths=tuple(leaf["paths"]),
            ops=norm_ops(leaf["ops"]),
            depth=int(leaf["depth"]),
            issued_at=float(leaf["iat"]),
            expires_at=float(leaf["exp"]),
        )

    def verify(
        self,
        token: str,
        *,
        path: str,
        op: str,
        audience: str,
        presenter: str | None = None,
        now: float | None = None,
    ) -> Verification:
        """校验令牌并判定其叶子授权是否覆盖指定路径、操作与受众。

        ``presenter`` 给出示令牌的实体；提供时必须等于叶子持有者
        ``sub``，防止凭证被非持有者冒用。
        """
        with self._lock:
            ts = self._now(now)
            chain = self._decode(token)
            view = self._verify_chain(chain, ts)
            if presenter is not None and presenter != view.subject:
                self._audit_event(
                    "verify_denied",
                    reason="presenter",
                    token_id=view.token_id,
                    path_hashes=[path_hash(path)],
                )
                msg = "token presenter does not match its holder"
                raise HolderMismatchError(msg)
            if op not in KNOWN_OPS:
                msg = f"unknown operation {op!r}"
                raise ValueError(msg)
            if audience != view.audience and view.audience != WILDCARD:
                self._audit_event(
                    "verify_denied",
                    reason="audience",
                    token_id=view.token_id,
                    path_hashes=[path_hash(path)],
                )
                msg = "token was not issued for this audience"
                raise AudienceMismatchError(msg)
            if op not in view.ops:
                self._audit_event(
                    "verify_denied",
                    reason="operation",
                    token_id=view.token_id,
                    op=op,
                    path_hashes=[path_hash(path)],
                )
                msg = f"operation {op!r} is not authorized"
                raise OperationDeniedError(msg)
            target = norm_paths((path,))[0]
            if not path_covers(view.paths, target):
                self._audit_event(
                    "verify_denied",
                    reason="path",
                    token_id=view.token_id,
                    op=op,
                    path_hashes=[path_hash(path)],
                )
                msg = "path is outside the delegated prefixes"
                raise PathDeniedError(msg)
            self._audit_event(
                "verify_allowed",
                token_id=view.token_id,
                op=op,
                path_hashes=[path_hash(path)],
                chain_length=len(view.chain_ids),
            )
            return view

    # -- 在途操作：下载租约 / 写提交 ----------------------------------------

    def begin_download(
        self,
        token: str,
        *,
        path: str,
        audience: str,
        presenter: str | None = None,
        now: float | None = None,
    ) -> DownloadLease:
        """开始只读下载：此刻必须完全有效，成功则取得持久化租约。

        租约截止时间为 ``min(令牌过期, 现在 + download_grace)``；此后即使
        令牌过期，已开始的下载仍可在宽限期内完成一次。宽限期非零时撤销
        同样只在截止时间后生效（给在途下载一个一致的收尾窗口）；宽限期
        为 0 时撤销立即切断。
        """
        with self._lock:
            ts = self._now(now)
            view = self.verify(
                token,
                path=path,
                op="download",
                audience=audience,
                presenter=presenter,
                now=ts,
            )
            deadline = view.expires_at
            if self.download_grace:
                deadline = min(deadline, ts + self.download_grace)
            lease = DownloadLease(
                lease_id=uuid.uuid4().hex,
                token_id=view.token_id,
                path=path,
                deadline=deadline,
                chain_ids=view.chain_ids,
            )
            self._leases[lease.lease_id] = lease
            self._save_state()
            self._audit_event(
                "lease_begun",
                lease_id=lease.lease_id,
                token_id=view.token_id,
                path_hashes=[path_hash(path)],
                deadline=deadline,
            )
            return lease

    def finish_download(self, lease_id: str, *, now: float | None = None) -> None:
        """完成在途下载。

        统一规则：令牌（或任一祖先）在开始下载后被撤时，仅当宽限期
        ``download_grace`` 非零且未过截止时间才放行；宽限期为 0 时撤销
        立即切断。过期同理：租约截止时间已按 ``min(过期时间, 开始+宽限)``
        收紧，因此写操作不享受任何宽限，而下载有明确、一致的宽限边界。
        """
        with self._lock:
            ts = self._now(now)
            lease = self._leases.get(lease_id)
            if lease is None:
                self._audit_event("lease_denied", reason="unknown_lease", lease_id=lease_id)
                msg = f"unknown lease {lease_id!r}"
                raise LeaseError(msg)
            if self.download_grace == 0 and any(
                tid in self._revoked for tid in lease.chain_ids
            ):
                self._leases.pop(lease_id, None)
                self._save_state()
                self._audit_event(
                    "lease_denied",
                    reason="revoked_no_grace",
                    lease_id=lease_id,
                    token_id=lease.token_id,
                )
                msg = "download interrupted by revocation (grace disabled)"
                raise LeaseError(msg)
            if ts > lease.deadline:
                self._leases.pop(lease_id, None)
                self._save_state()
                self._audit_event(
                    "lease_denied",
                    reason="deadline",
                    lease_id=lease_id,
                    token_id=lease.token_id,
                )
                msg = "download lease expired"
                raise LeaseError(msg)
            self._leases.pop(lease_id, None)
            self._save_state()
            self._audit_event(
                "lease_finished",
                lease_id=lease_id,
                token_id=lease.token_id,
                path_hashes=[lease.path if lease.is_hash else path_hash(lease.path)],
            )

    def commit_write(
        self,
        token: str,
        *,
        path: str,
        audience: str,
        presenter: str | None = None,
        now: float | None = None,
    ) -> Verification:
        """写操作提交点校验：无宽限，授权失效则未提交写一律拒绝。

        与下载不同，写不设租约；调用方应在真正落盘前调用本方法，链上任一
        祖先撤销、令牌过期或范围不匹配都会在此刻拒绝提交。
        """
        with self._lock:
            return self.verify(
                token,
                path=path,
                op="write",
                audience=audience,
                presenter=presenter,
                now=now,
            )

    # -- 撤销 ---------------------------------------------------------------

    def revoke(
        self,
        token: str,
        *,
        revoked_by: str,
        reason: str = "",
        now: float | None = None,
    ) -> _Revocation:
        """撤销令牌（叶子或链上任一节点）；级联使其全部后代立即失效。

        重复撤销幂等：返回既有记录并记一条 ``revoke_duplicate`` 审计。
        """
        with self._lock:
            ts = self._now(now)
            chain = self._decode(token)
            target = chain[-1]["id"]
            existing = self._revoked.get(target)
            if existing is not None:
                self._audit_event(
                    "revoke_duplicate",
                    token_id=target,
                    revoked_by=revoked_by,
                    prior_by=existing.revoked_by,
                )
                return existing
            record = _Revocation(
                token_id=target, revoked_at=ts, revoked_by=revoked_by, reason=reason
            )
            self._revoked[target] = record
            self._save_state()
            affected = self.descendant_ids(target)
            self._audit_event(
                "revoked",
                token_id=target,
                revoked_by=revoked_by,
                reason_hash=path_hash(reason) if reason else "",
                descendants_known=len(affected),
            )
            return record

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._revoked

    # -- 签发索引与脱敏查询 -------------------------------------------------

    def descendant_ids(self, token_id: str) -> list[str]:
        """返回签发索引中该令牌的全部后代 id（按派生顺序）。"""
        with self._lock:
            children: dict[str, list[str]] = {}
            for rec in self._registry.values():
                children.setdefault(rec["parent_id"], []).append(rec["token_id"])
            out: list[str] = []
            stack = list(children.get(token_id, ()))
            while stack:
                tid = stack.pop(0)
                out.append(tid)
                stack.extend(children.get(tid, ()))
            return out

    def list_effective(
        self,
        token_id: str,
        *,
        viewer_paths: t.Iterable[str] | None = None,
        now: float | None = None,
    ) -> list[dict[str, t.Any]]:
        """列出某令牌当前仍有效的派生凭证（人员离场清点用）。

        有效 = 未过期且链上无撤销。输出路径按 ``viewer_paths`` 脱敏：
        审阅者未获授权的路径名称替换为 redacted 摘要。
        """
        with self._lock:
            ts = self._now(now)
            result = []
            for tid in self.descendant_ids(token_id):
                rec = self._registry[tid]
                if float(rec["exp"]) <= ts:
                    continue
                chain = list(reversed(self._ancestor_chain(tid)))
                if any(a in self._revoked for a in chain):
                    continue
                result.append(self._describe(rec, viewer_paths))
            return result

    def _ancestor_chain(self, token_id: str) -> list[str]:
        chain = [token_id]
        cur = token_id
        while True:
            rec = self._registry.get(cur)
            if rec is None or not rec["parent_id"]:
                break
            cur = rec["parent_id"]
            chain.append(cur)
        return chain

    def describe_token(
        self, token_id: str, *, viewer_paths: t.Iterable[str] | None = None
    ) -> dict[str, t.Any]:
        """按审阅者被授权范围返回单张凭证的脱敏描述。"""
        with self._lock:
            rec = self._registry.get(token_id)
            if rec is None:
                msg = f"unknown token {token_id!r}"
                raise KeyError(msg)
            return self._describe(rec, viewer_paths)

    def _describe(
        self, rec: dict[str, t.Any], viewer_paths: t.Iterable[str] | None
    ) -> dict[str, t.Any]:
        return {
            "token_id": rec["token_id"],
            "parent_id": rec["parent_id"],
            "subject": rec["subject"],
            "aud": rec["aud"],
            "ops": list(rec["ops"]),
            "paths": redact_paths(rec["paths"], tuple(viewer_paths) if viewer_paths else ()),
            "depth": rec["depth"],
            "exp": rec["exp"],
            "revoked": rec["token_id"] in self._revoked,
        }

    # -- 维护 ---------------------------------------------------------------

    def prune(self, *, now: float | None = None) -> dict[str, int]:
        """清理过期签发索引与到点下载租约；撤销记录永久保留防重放。"""
        with self._lock:
            ts = self._now(now)
            expired_reg = [tid for tid, r in self._registry.items() if float(r["exp"]) <= ts]
            for tid in expired_reg:
                self._registry.pop(tid, None)
            dead_leases = [lid for lid, l in self._leases.items() if l.deadline <= ts]
            for lid in dead_leases:
                self._leases.pop(lid, None)
            if expired_reg or dead_leases:
                self._save_state()
            return {"registrations": len(expired_reg), "leases": len(dead_leases)}


# ---------------------------------------------------------------------------
# 模块级辅助
# ---------------------------------------------------------------------------


def node_payload(node: dict[str, t.Any]) -> dict[str, t.Any]:
    """签名/验签的规范化负载：节点全部字段除签名本身。"""
    return {k: v for k, v in node.items() if k != "sig"}


def chain_node_ids(chain: list[dict[str, t.Any]]) -> list[str]:
    return [n["id"] for n in chain]
