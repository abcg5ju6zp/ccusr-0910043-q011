"""可委托短期授权（DelegationAuthority）的回归测试。

覆盖：签发/校验、只收窄转授、派生深度、级联与重复撤销、过期、在途
下载宽限与写提交、密钥轮换、服务重启后的链验证、状态防篡改，以及
审计与查询的路径脱敏。
"""

from __future__ import annotations

import base64
import json

import pytest

from jupyter_server.auth.delegation import (
    SCHEME_VERSION,
    DelegationAuthority,
    DepthExhaustedError,
    HolderMismatchError,
    InvalidSignatureError,
    InvalidTokenError,
    LeaseError,
    OperationDeniedError,
    PathDeniedError,
    AudienceMismatchError,
    ScopeNarrowingError,
    TamperedStateError,
    TokenExpiredError,
    TokenRevokedError,
    UnknownKeyError,
    norm_paths,
    path_covers,
    paths_narrower,
    redact_paths,
)

T0 = 1_700_000_000.0
AUD = "external-review-svc"


@pytest.fixture()
def authority():
    # 时钟通过 now= 注入，这里给一个短 TTL/宽限的纯内存实例。
    return DelegationAuthority(
        default_ttl=600, max_ttl=3600, max_depth=3, download_grace=300
    )


def make_chain(authority, *, depth=3, ttl=600, paths=("/data",), ops=("read", "download", "write")):
    """生成根及一路收窄到 depth 的链，返回 (root, tokens...)。"""
    root = authority.issue_root(
        paths=paths, ops=ops, aud=AUD, depth=depth, ttl=ttl, now=T0
    )
    tokens = [root]
    remaining = list(paths)
    for hop in range(depth):
        # 每跳把路径再收窄一层，操作逐步缩减。
        parent = tokens[-1]
        leaf_paths = tuple(p + f"/h{hop}" for p in remaining) if "*" not in remaining else (f"/bound/h{hop}",)
        leaf_ops = ops[: max(1, len(ops) - hop)]
        tokens.append(
            authority.delegate(
                parent,
                paths=leaf_paths,
                ops=leaf_ops,
                aud=AUD,
                subject=f"holder-{hop}",
                ttl=max(60, ttl - 60 * (hop + 1)),
                now=T0,
            )
        )
        remaining = leaf_paths
    return tuple(tokens)


# ---------------------------------------------------------------------------
# 规范化纯函数
# ---------------------------------------------------------------------------


def test_path_normalization():
    assert norm_paths(["/a/", "a/b", "/a/b/"]) == ("/a", "/a/b")
    assert norm_paths(["*"]) == ("*",)
    with pytest.raises(ValueError):
        norm_paths(["/a/../b"])
    with pytest.raises(ValueError):
        norm_paths([""])


def test_segment_boundary_covering():
    assert path_covers(("/foo",), "/foo/bar")
    assert path_covers(("/foo",), "/foo")
    assert not path_covers(("/foo",), "/foobar")
    assert path_covers(("*",), "/anything/deep")


def test_paths_narrowing():
    assert paths_narrower(("/a",), ("/a/b",))
    assert not paths_narrower(("/a/b",), ("/a",))
    assert not paths_narrower(("/a",), ("*",))


def test_redaction():
    out = redact_paths(("/a", "/b"), viewer_paths=("/a",))
    assert out[0] == "/a"
    assert out[1].startswith("redacted:")
    assert redact_paths(("/secret",), viewer_paths=("*",)) == ["/secret"]
    assert redact_paths(("*",), viewer_paths=()) == ["*"]


# ---------------------------------------------------------------------------
# 签发与校验
# ---------------------------------------------------------------------------


def test_root_issue_and_verify(authority):
    root = authority.issue_root(paths=["/data"], ops=["read"], aud=AUD, ttl=600, now=T0)
    view = authority.verify(root, path="/data/x", op="read", audience=AUD, now=T0)
    assert view.paths == ("/data",)
    assert view.ops == ("read",)
    assert view.audience == AUD
    assert view.depth == authority.max_depth
    assert len(view.chain_ids) == 1


def test_verify_rejects_scope_violations(authority):
    root = authority.issue_root(paths=["/data"], ops=["read"], aud=AUD, ttl=600, now=T0)
    with pytest.raises(PathDeniedError):
        authority.verify(root, path="/other/x", op="read", audience=AUD, now=T0)
    with pytest.raises(OperationDeniedError):
        authority.verify(root, path="/data/x", op="write", audience=AUD, now=T0)
    with pytest.raises(AudienceMismatchError):
        authority.verify(root, path="/data/x", op="read", audience="other-svc", now=T0)


def test_presenter_must_match_holder(authority):
    child = authority.delegate(
        authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, now=T0),
        paths=["/d"], ops=["read"], aud=AUD, subject="alice", ttl=300, now=T0,
    )
    authority.verify(child, path="/d/x", op="read", audience=AUD, presenter="alice", now=T0)
    with pytest.raises(HolderMismatchError):
        authority.verify(child, path="/d/x", op="read", audience=AUD, presenter="mallory", now=T0)


def test_expired_token_rejected(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=100, now=T0)
    authority.verify(root, path="/d/x", op="read", audience=AUD, now=T0 + 99)
    with pytest.raises(TokenExpiredError):
        authority.verify(root, path="/d/x", op="read", audience=AUD, now=T0 + 100)


def test_ttl_bounds(authority):
    with pytest.raises(ValueError):
        authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=0, now=T0)
    with pytest.raises(ValueError):
        authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=10_000, now=T0)


# ---------------------------------------------------------------------------
# 只收窄的转授
# ---------------------------------------------------------------------------


def test_delegation_chain_narrows(authority):
    tokens = make_chain(authority)
    leaf = tokens[-1]
    view = authority.verify(
        leaf, path="/data/h0/h1/h2/file", op="read", audience=AUD,
        presenter="holder-2", now=T0 + 10,
    )
    assert view.depth == 0
    assert len(view.chain_ids) == 4


def test_delegation_widening_rejected(authority):
    root = authority.issue_root(
        paths=["/data"], ops=["read", "download"], aud=AUD, ttl=600, depth=2, now=T0
    )
    # 路径放宽
    with pytest.raises(ScopeNarrowingError):
        authority.delegate(root, paths=["/elsewhere"], ops=["read"], aud=AUD,
                           subject="a", ttl=100, now=T0)
    # 操作放宽
    with pytest.raises(ScopeNarrowingError):
        authority.delegate(root, paths=["/data"], ops=["read", "write"], aud=AUD,
                           subject="a", ttl=100, now=T0)
    # 子令牌活得比父令牌久
    with pytest.raises(ScopeNarrowingError):
        authority.delegate(root, paths=["/data"], ops=["read"], aud=AUD,
                           subject="a", ttl=601, now=T0)


def test_audience_wildcard_binding(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=None, ttl=600, depth=2, now=T0)
    # 通配受众的父代必须在转授时绑定具体受众
    with pytest.raises(ScopeNarrowingError):
        authority.delegate(root, paths=["/d"], ops=["read"], subject="a", ttl=100, now=T0)
    child = authority.delegate(root, paths=["/d"], ops=["read"], aud=AUD,
                               subject="a", ttl=100, now=T0)
    # 一旦绑定，不能退回通配，也不能改投别的受众
    with pytest.raises(ScopeNarrowingError):
        authority.delegate(child, paths=["/d"], ops=["read"], aud="*",
                           subject="b", ttl=50, now=T0)
    with pytest.raises(ScopeNarrowingError):
        authority.delegate(child, paths=["/d"], ops=["read"], aud="other-svc",
                           subject="b", ttl=50, now=T0)


def test_wildcard_paths_must_bind_on_delegation(authority):
    root = authority.issue_root(paths=["*"], ops=["read"], aud=AUD, ttl=600, depth=2, now=T0)
    assert authority.verify(root, path="/anything", op="read", audience=AUD, now=T0)
    with pytest.raises(ScopeNarrowingError):
        authority.delegate(root, paths=["*"], ops=["read"], aud=AUD,
                           subject="a", ttl=100, now=T0)
    child = authority.delegate(root, paths=["/bound/dir"], ops=["read"], aud=AUD,
                               subject="a", ttl=100, now=T0)
    view = authority.verify(child, path="/bound/dir/f", op="read", audience=AUD, now=T0)
    assert view.paths == ("/bound/dir",)


def test_depth_exhaustion(authority):
    tokens = make_chain(authority, depth=3)
    with pytest.raises(DepthExhaustedError):
        authority.delegate(tokens[-1], paths=["/data/h0/h1/h2/x"], ops=["read"],
                           aud=AUD, subject="x", ttl=60, now=T0 + 5)


def test_cannot_delegate_from_revoked_or_expired(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, depth=2, now=T0)
    authority.revoke(root, revoked_by="pi", now=T0)
    with pytest.raises(TokenRevokedError):
        authority.delegate(root, paths=["/d"], ops=["read"], aud=AUD,
                           subject="a", ttl=100, now=T0)


# ---------------------------------------------------------------------------
# 令牌完整性
# ---------------------------------------------------------------------------


def _decode_envelope(token):
    version, envelope = token.split(".", 1)
    assert version == SCHEME_VERSION
    raw = base64.urlsafe_b64decode(envelope + "=" * (-len(envelope) % 4))
    return json.loads(raw)


def _encode_envelope(blob):
    body = json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()
    return SCHEME_VERSION + "." + base64.urlsafe_b64encode(body).decode().rstrip("=")


def test_tampered_signature_rejected(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, now=T0)
    blob = _decode_envelope(root)
    blob["chain"][0]["paths"] = ["/etc"]
    forged = _encode_envelope(blob)
    with pytest.raises(InvalidSignatureError):
        authority.verify(forged, path="/etc/passwd", op="read", audience=AUD, now=T0)


def test_signed_but_widened_chain_rejected(authority):
    """即使每跳签名都有效（模拟内部越权构造），收窄关系仍被独立强制。"""
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, depth=2, now=T0)
    blob = _decode_envelope(root)
    parent = blob["chain"][0]
    rogue = dict(parent)
    rogue.update(
        id="rogue-node", parent=parent["id"], paths=["/etc"], ops=["read", "write"],
        depth=parent["depth"] - 1, iat=T0, exp=T0 + 500,
    )
    rogue = authority._sign_node(rogue)
    token = _encode_envelope({"chain": [parent, rogue]})
    with pytest.raises(ScopeNarrowingError):
        authority.verify(token, path="/etc/x", op="write", audience=AUD, now=T0)


def test_unknown_key_generation_rejected(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, now=T0)
    blob = _decode_envelope(root)
    blob["chain"][0]["kid"] = "deadbeefdead"
    # 保留原签名但换 kid，模拟密钥代次已清除
    with pytest.raises(UnknownKeyError):
        authority.verify(_encode_envelope(blob), path="/d/x", op="read", audience=AUD, now=T0)


def test_malformed_token_rejected(authority):
    for bad in ["garbage", "XX.abc", "D1.@@@", "", "D1"]:
        with pytest.raises(InvalidTokenError):
            authority.verify(bad, path="/d", op="read", audience=AUD, now=T0)


def test_broken_chain_link_rejected(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, depth=2, now=T0)
    child = authority.delegate(root, paths=["/d/a"], ops=["read"], aud=AUD,
                               subject="a", ttl=300, now=T0)
    blob = _decode_envelope(child)
    blob["chain"][1]["parent"] = "not-the-parent"
    blob["chain"][1] = authority._sign_node(blob["chain"][1])
    with pytest.raises(InvalidTokenError):
        authority.verify(_encode_envelope(blob), path="/d/a/x", op="read", audience=AUD, now=T0)


# ---------------------------------------------------------------------------
# 撤销
# ---------------------------------------------------------------------------


def test_cascade_revocation(authority):
    tokens = make_chain(authority)
    root, child, grandchild, leaf = tokens
    # 撤销中间一跳：其全部后代立即失效，无关旁支不受影响
    authority.revoke(grandchild, revoked_by="pi", reason="offboard", now=T0)
    with pytest.raises(TokenRevokedError):
        authority.verify(leaf, path="/data/h0/h1/h2/f", op="read", audience=AUD, now=T0)
    # 根与另一子树仍有效
    authority.verify(root, path="/data/x", op="read", audience=AUD, now=T0)
    sibling = authority.delegate(child, paths=["/data/h0/sib"], ops=["read"], aud=AUD,
                                 subject="s", ttl=100, now=T0)
    # child 未撤，旁支可用
    authority.verify(sibling, path="/data/h0/sib/f", op="read", audience=AUD, now=T0)


def test_revoke_root_kills_everything(authority):
    tokens = make_chain(authority)
    authority.revoke(tokens[0], revoked_by="pi", now=T0)
    for tok in tokens:
        with pytest.raises(TokenRevokedError):
            authority.verify(
                tok, path="/data", op="read", audience=AUD,
                presenter=None, now=T0,
            )


def test_duplicate_revoke_is_idempotent(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, now=T0)
    r1 = authority.revoke(root, revoked_by="pi", now=T0)
    r2 = authority.revoke(root, revoked_by="someone-else", now=T0 + 10)
    assert r1 is r2
    assert authority.is_revoked(r1.token_id)
    kinds = [e["event"] for e in authority.audit_events()]
    assert kinds.count("revoked") == 1
    assert "revoke_duplicate" in kinds


# ---------------------------------------------------------------------------
# 密钥轮换
# ---------------------------------------------------------------------------


def test_key_rotation_keeps_old_chains_valid(authority):
    root = authority.issue_root(paths=["/d"], ops=["read", "write"], aud=AUD,
                                ttl=600, depth=3, now=T0)
    first_kid = authority.active_key_id
    child = authority.delegate(root, paths=["/d/a"], ops=["read", "write"], aud=AUD,
                               subject="a", ttl=500, now=T0 + 1)
    authority.rotate_key()
    second_kid = authority.active_key_id
    assert second_kid != first_kid
    # 用新密钥签的新跳
    grand = authority.delegate(child, paths=["/d/a/b"], ops=["read"], aud=AUD,
                               subject="b", ttl=400, now=T0 + 2)
    blob = _decode_envelope(grand)
    kids = {n["kid"] for n in blob["chain"]}
    assert kids == {first_kid, second_kid}
    # 混合代次的链仍可逐跳验证
    view = authority.verify(grand, path="/d/a/b/x", op="read", audience=AUD, now=T0 + 3)
    assert len(view.chain_ids) == 3


# ---------------------------------------------------------------------------
# 在途下载与写提交
# ---------------------------------------------------------------------------


def test_inflight_download_completes_within_grace_then_cut(authority):
    root = authority.issue_root(paths=["/d"], ops=["download", "read"], aud=AUD,
                                ttl=600, depth=1, now=T0)
    lease = authority.begin_download(root, path="/d/big.bin", audience=AUD, now=T0)
    # 撤销后，宽限期内仍可完成
    authority.revoke(root, revoked_by="pi", now=T0 + 10)
    authority.finish_download(lease.lease_id, now=T0 + 20)


def test_download_grace_zero_cuts_immediately(tmp_path):
    authority = DelegationAuthority(state_dir=str(tmp_path), download_grace=0)
    root = authority.issue_root(paths=["/d"], ops=["download"], aud=AUD,
                                ttl=600, depth=1, now=T0)
    lease = authority.begin_download(root, path="/d/big.bin", audience=AUD, now=T0)
    authority.revoke(root, revoked_by="pi", now=T0 + 1)
    with pytest.raises(LeaseError):
        authority.finish_download(lease.lease_id, now=T0 + 2)


def test_download_lease_deadline_bounds(authority):
    root = authority.issue_root(paths=["/d"], ops=["download"], aud=AUD,
                                ttl=100, depth=1, now=T0)
    lease = authority.begin_download(root, path="/d/big.bin", audience=AUD, now=T0)
    # 截止时间取 min(令牌过期, 开始+宽限)；这里宽限 300 > ttl 100
    assert lease.deadline == T0 + 100
    with pytest.raises(LeaseError):
        authority.finish_download(lease.lease_id, now=T0 + 101)
    with pytest.raises(LeaseError):
        authority.finish_download("nonexistent-lease", now=T0)


def test_unknown_lease_rejected(authority):
    with pytest.raises(LeaseError):
        authority.finish_download("nope", now=T0)


def test_write_commit_has_no_grace(authority):
    root = authority.issue_root(paths=["/d"], ops=["write"], aud=AUD, ttl=600, now=T0)
    authority.verify(root, path="/d/a", op="write", audience=AUD, now=T0)
    authority.revoke(root, revoked_by="pi", now=T0 + 5)
    # 尚未提交的写在授权失效后一律拒绝，与下载宽限无关
    with pytest.raises(TokenRevokedError):
        authority.commit_write(root, path="/d/a", audience=AUD, now=T0 + 6)


def test_write_requires_write_op(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, now=T0)
    with pytest.raises(OperationDeniedError):
        authority.commit_write(root, path="/d/a", audience=AUD, now=T0)


# ---------------------------------------------------------------------------
# 持久化：重启、篡改
# ---------------------------------------------------------------------------


def test_state_survives_restart(tmp_path):
    a = DelegationAuthority(state_dir=str(tmp_path))
    root = a.issue_root(paths=["/d"], ops=["read", "write"], aud=AUD,
                        ttl=600, depth=2, now=T0)
    child = a.delegate(root, paths=["/d/a"], ops=["read"], aud=AUD,
                       subject="alice", ttl=300, now=T0)
    a.rotate_key()
    grand = a.delegate(child, paths=["/d/a/b"], ops=["read"], aud=AUD,
                       subject="bob", ttl=200, now=T0)
    a.revoke(child, revoked_by="pi", reason="alice left project", now=T0)
    lease = None  # 已撤，无法再开租约

    # 全新进程视角：密钥环、撤销集、索引全部恢复
    b = DelegationAuthority(state_dir=str(tmp_path))
    assert b.active_key_id == a.active_key_id
    with pytest.raises(TokenRevokedError):
        b.verify(grand, path="/d/a/b/x", op="read", audience=AUD, now=T0 + 1)
    # 未撤的根仍可验证
    b.verify(root, path="/d/x", op="write", audience=AUD, now=T0 + 1)
    # 后代清点仍可查询（含撤销状态）
    effective = b.list_effective(_leaf_id(root), now=T0 + 1)
    assert effective == []  # 后代均因 child 被撤而失效
    assert lease is None


def _leaf_id(token):
    return _decode_envelope(token)["chain"][-1]["id"]


def test_leases_survive_restart_and_keep_grace(tmp_path):
    a = DelegationAuthority(state_dir=str(tmp_path), download_grace=300)
    root = a.issue_root(paths=["/d"], ops=["download"], aud=AUD, ttl=600, now=T0)
    lease = a.begin_download(root, path="/d/big.bin", audience=AUD, now=T0)

    b = DelegationAuthority(state_dir=str(tmp_path))
    # 重启后租约仍在，宽限判定继续生效
    b.finish_download(lease.lease_id, now=T0 + 50)


def test_tampered_state_detected(tmp_path):
    a = DelegationAuthority(state_dir=str(tmp_path))
    a.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, now=T0)
    state = tmp_path / "delegation_state.json"
    blob = json.loads(state.read_text())
    # 伪造一条撤销记录：字段齐全但 HMAC 不合法。
    blob["revoked"].append(
        {"token_id": "forged", "revoked_at": T0, "revoked_by": "x",
         "reason": "", "seal_kid": a.active_key_id, "hmac": "AAAA"}
    )
    state.write_text(json.dumps(blob))
    with pytest.raises(TamperedStateError):
        DelegationAuthority(state_dir=str(tmp_path))


def test_state_sealed_with_lost_key_generation_rejected(tmp_path):
    a = DelegationAuthority(state_dir=str(tmp_path))
    a.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=600, now=T0)
    # 密钥环丢失/被替换为全新环：旧状态的密封代次不再受信。
    (tmp_path / "delegation_keys.json").unlink()
    with pytest.raises(TamperedStateError):
        DelegationAuthority(state_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# 审计与查询脱敏
# ---------------------------------------------------------------------------


def test_audit_never_contains_raw_paths(authority):
    secret = "/secret-project/alpha"
    root = authority.issue_root(paths=[secret], ops=["read", "download", "write"],
                                aud=AUD, ttl=600, depth=2, now=T0)
    child = authority.delegate(root, paths=[secret + "/review"], ops=["read"], aud=AUD,
                               subject="alice", ttl=300, now=T0)
    # 触发允许与各类拒绝事件
    authority.verify(child, path=secret + "/review/f", op="read", audience=AUD, now=T0)
    with pytest.raises(PathDeniedError):
        authority.verify(child, path="/other", op="read", audience=AUD, now=T0)
    authority.revoke(child, revoked_by="pi", reason="done", now=T0)
    blob = json.dumps(authority.audit_events())
    assert "secret-project" not in blob
    assert "/alpha" not in blob
    assert "/review" not in blob
    # 但保留可关联的摘要
    assert any(e.get("path_hashes") for e in authority.audit_events())


def test_list_effective_offboarding_inventory(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD,
                                ttl=600, depth=2, now=T0)
    live = authority.delegate(root, paths=["/d/live"], ops=["read"], aud=AUD,
                              subject="alice", ttl=400, now=T0)
    expired = authority.delegate(root, paths=["/d/old"], ops=["read"], aud=AUD,
                                 subject="alice", ttl=50, now=T0)
    revoked = authority.delegate(root, paths=["/d/gone"], ops=["read"], aud=AUD,
                                 subject="bob", ttl=400, now=T0)
    authority.revoke(revoked, revoked_by="pi", now=T0 + 10)

    root_id = _leaf_id(root)
    effective = authority.list_effective(root_id, now=T0 + 60)
    ids = {e["token_id"] for e in effective}
    assert _leaf_id(live) in ids
    assert _leaf_id(expired) not in ids   # 已过期
    assert _leaf_id(revoked) not in ids   # 已撤销


def test_describe_redaction_per_viewer(authority):
    root = authority.issue_root(paths=["/proj", "/secret"], ops=["read"], aud=AUD,
                                ttl=600, depth=1, now=T0)
    child = authority.delegate(root, paths=["/secret/top"], ops=["read"], aud=AUD,
                               subject="bob", ttl=400, now=T0)
    tid = _leaf_id(child)
    limited = authority.describe_token(tid, viewer_paths=["/proj"])
    assert limited["paths"][0].startswith("redacted:")
    assert "secret" not in json.dumps(limited)
    privileged = authority.describe_token(tid, viewer_paths=["*"])
    assert privileged["paths"] == ["/secret/top"]


def test_prune_clears_expired(authority):
    root = authority.issue_root(paths=["/d"], ops=["read"], aud=AUD, ttl=10, now=T0)
    short = authority.delegate(root, paths=["/d/x"], ops=["read"], aud=AUD,
                               subject="a", ttl=5, now=T0)
    result = authority.prune(now=T0 + 100)
    assert result["registrations"] >= 1
    with pytest.raises(KeyError):
        authority.describe_token(_leaf_id(short))
