"""规范转录编码（单一来源）。15 号补丁后版本：λ_H 默认 48 B（32 为对照）。
所有 Sign/Verify 一律调用本模块；任何算法不得内联拼接。"""
import hashlib
import struct

LAMBDA_H = 48  # 优先候选（15号 §5.2）；G6 对照时改为 32
Y_LEN = 32     # 合成测试默认字段值长度（v3 起序列化用长度前缀，不再要求定长）

ROLES = {b"signer": 0, b"physician": 1, b"nurse": 2, b"admin": 3, b"auditor": 4}
ROLE_BY_CODE = {v: k for k, v in ROLES.items()}
WILD = b"*"          # 通配符：只能是整体全集值（15号 §二）
CTX_CERT = b"qprss-cert"
CTX_ORIG = b"qprss-orig"
CTX_RED = b"qprss-red"
CTX_ANC = b"qprss-anc"
CTX_REG = b"qprss-reg"


def H(x: bytes) -> bytes:
    return hashlib.shake_256(b"QPRSS-H|" + x).digest(LAMBDA_H)


def H_L(x: bytes) -> bytes:
    return hashlib.shake_256(b"QPRSS-HL|" + x).digest(LAMBDA_H)


def enc32(v: int) -> bytes:
    return struct.pack(">I", v)


def enc64(v: int) -> bytes:
    return struct.pack(">Q", v)


def enc_field(j: int, y: bytes) -> bytes:
    """v3 可变长字段编码：enc32(j)‖enc32(len(y))‖y（2B-2 任务四(2)）。
    签名与验证使用完全相同的字节表示——y 由调用方规范化产生（如 FHIR canonical_json）。"""
    return enc32(j) + enc32(len(y)) + y


def dec_field(buf, off: int):
    """返回 (j, y, 结束偏移)；越界即拒（自定界流的截断守卫）。"""
    if off + 8 > len(buf):
        raise ValueError("field header truncated")
    j = struct.unpack(">I", buf[off:off + 4])[0]
    ln = struct.unpack(">I", buf[off + 4:off + 8])[0]
    if off + 8 + ln > len(buf):
        raise ValueError("field body truncated")
    return j, buf[off + 8:off + 8 + ln], off + 8 + ln


def enc256(v: bytes) -> bytes:
    assert len(v) == 32
    return v


def bmp(I, n: int) -> bytes:
    """位图：索引 j（1..n）→ 第 j-1 位。长度恰 ⌈n/8⌉。"""
    out = bytearray((n + 7) // 8)
    for j in I:
        assert 1 <= j <= n, f"index {j} out of range"
        out[(j - 1) // 8] |= 1 << ((j - 1) % 8)
    return bytes(out)


def bmp_decode(b: bytes, n: int):
    assert len(b) == (n + 7) // 8, "bitmap length mismatch"
    return {j for j in range(1, n + 1) if b[(j - 1) // 8] >> ((j - 1) % 8) & 1}


# ---------- 策略编码 ----------
# encP = admLen(1) | 每项 role(1)+tag(1)+[n(1)+ids*16] | bmp(W) | d(4)

def enc_adm_entry(role: bytes, idpat) -> bytes:
    code = ROLES[role]
    if idpat == WILD or idpat == "*":
        return bytes([code, 1])
    ids = [i for i in idpat]
    assert all(len(i) == 16 for i in ids)
    return bytes([code, 0, len(ids)]) + b"".join(ids)


def encP(P) -> bytes:
    adm = b"".join(enc_adm_entry(r, x) for (r, x) in P.adm)
    return bytes([len(P.adm)]) + adm + bmp(P.w, P.n) + enc32(P.d)


# ---------- 证书消息 ----------
# scope = ridTag(1)+[n(1)+rids*16] + jTag(1)+[n(1)+j*2]

def enc_scope(scope) -> bytes:
    rids, jset = scope
    if rids == WILD or rids == "*":
        out = bytes([1])
    else:
        rl = list(rids)
        out = bytes([0, len(rl)]) + b"".join(rl)
    if jset == WILD or jset == "*":
        return out + bytes([1])
    jl = sorted(jset)
    return out + bytes([0, len(jl)]) + b"".join(struct.pack(">H", j) for j in jl)


def M_certS(id_s: bytes, pk_s: bytes, scope, nb: int, na: int) -> bytes:
    return (b"QPRSS-v2|certS" + id_s + pk_s + bytes([ROLES[b"signer"]])
            + enc_scope(scope) + enc64(nb) + enc64(na))


def M_certR(rid_id: bytes, pk: bytes, role: bytes, scope, nb: int, na: int) -> bytes:
    return (b"QPRSS-v2|certR" + rid_id + pk + bytes([ROLES[role]])
            + enc_scope(scope) + enc64(nb) + enc64(na))


def M_orig(rid: bytes, n: int, acc0: bytes, P0, I0, sd: bytes = None) -> bytes:
    """sd（schema_digest，17号）：提供时绑定字段语义映射（j→path/type 表的摘要）。
    不提供时字节与 2B-2 完全一致（合成层锚点不变）。"""
    out = b"QPRSS-v2|orig" + rid + enc32(n) + acc0 + encP(P0) + bmp(I0, n)
    return out if sd is None else out + b"|sd|" + sd


def M_init(rid: bytes, n: int, acc0: bytes, P0, I0, sd: bytes = None) -> bytes:
    """审计链锚（h₀ = H_L(M_init)）。2B-3 P2：提供时追加 schema_digest——
    否则同 acc0/P0 不同 sd 的两条记录 h₀ 相同，删改者审计签名（M_red 经 h_prev）
    可跨 schema 上下文移植（attack_prefix_2b3.py [P2] 实证）。不提供时字节与
    2B-2 一致（无 sd 流锚点不变）。"""
    out = b"QPRSS-v2|init" + rid + enc32(n) + acc0 + encP(P0) + bmp(I0, n)
    return out if sd is None else out + b"|sd|" + sd


def M_red(rid: bytes, i: int, e_bytes: bytes, h_prev: bytes, h_i: bytes) -> bytes:
    return b"QPRSS-v2|red" + rid + enc32(i) + e_bytes + h_prev + h_i


def M_resp(nonce: bytes, rid: bytes, h_star: bytes, t_star: int, ts: int) -> bytes:
    return b"QPRSS-v2|resp" + nonce + rid + h_star + enc32(t_star) + enc64(ts)


def M_gaz(period: int, rid: bytes, h_star: bytes, t_star: int, ts: int) -> bytes:
    return b"QPRSS-v2|gaz" + enc32(period) + rid + h_star + enc32(t_star) + enc64(ts)


# Stage-5.9 P0.2-r2（SECREV1-F3/AUD-04）：锚定域绑定撤销 epoch——新鲜/公报
# 响应携带 RA.epoch，验证器据以拒绝过期 revsnap（rv_epoch < anchor_epoch）。
# v3 前缀与 v2 域零交集（旧签名锚仍按 v2 解析=legacy，无 epoch 可比对）。

def M_resp3(nonce: bytes, rid: bytes, h_star: bytes, t_star: int, ts: int,
            epoch: int) -> bytes:
    return (b"QPRSS-v3|resp" + nonce + rid + h_star
            + enc32(t_star) + enc64(ts) + enc64(epoch))


def M_gaz3(period: int, rid: bytes, h_star: bytes, t_star: int, ts: int,
           epoch: int) -> bytes:
    return (b"QPRSS-v3|gaz" + enc32(period) + rid + h_star
            + enc32(t_star) + enc64(ts) + enc64(epoch))


def parse_resp3(msg: bytes):
    """M_resp3 对偶解析；结构不符 ValueError（不可信输入，拒绝）。"""
    if msg[:13] != b"QPRSS-v3|resp" or len(msg) != 13 + 32 + 16 + 32 + 4 + 8 + 8:
        raise ValueError("bad resp3")
    p = 13
    nonce, rid, h_star = msg[p:p + 32], msg[p + 32:p + 48], msg[p + 48:p + 80]
    p = 80
    t_star, ts, epoch = struct.unpack(">I", msg[p:p + 4])[0], \
        struct.unpack(">Q", msg[p + 4:p + 12])[0], \
        struct.unpack(">Q", msg[p + 12:p + 20])[0]
    return nonce, rid, h_star, t_star, ts, epoch


def parse_gaz3(msg: bytes):
    """M_gaz3 对偶解析；结构不符 ValueError。"""
    if msg[:12] != b"QPRSS-v3|gaz" or len(msg) != 12 + 4 + 16 + 32 + 4 + 8 + 8:
        raise ValueError("bad gaz3")
    p = 12
    period = struct.unpack(">I", msg[p:p + 4])[0]
    rid, h_star = msg[p + 4:p + 20], msg[p + 20:p + 52]
    p = 52
    t_star, ts, epoch = struct.unpack(">I", msg[p:p + 4])[0], \
        struct.unpack(">Q", msg[p + 4:p + 12])[0], \
        struct.unpack(">Q", msg[p + 12:p + 20])[0]
    return period, rid, h_star, t_star, ts, epoch


def M_reginit(rid: bytes, n: int, acc0: bytes, P0, cid: bytes, sd: bytes = None) -> bytes:
    """16号 §二：初始登记转录（绑定 Cert_S）；17号：提供时追加 schema_digest
    （RA 初登锚定字段语义映射）。不提供时字节与 16号 一致。"""
    out = b"QPRSS-v2|reginit" + rid + enc32(n) + acc0 + encP(P0) + cid
    return out if sd is None else out + b"|sd|" + sd


# ---------- schema 编码与摘要（17号：字段语义映射的认证） ----------
# entries = [(j, path, ftype), ...]，path 元素为 str（dict 键）或 int（list 下标），
# ftype ∈ {"str","int","bool","list","dict"}（白名单，17号 §3：JCS 安全子集）。

def enc_schema(entries) -> bytes:
    out = b""
    for (j, path, ftype) in sorted(entries, key=lambda e: e[0]):
        pe = b""
        for el in path:
            if isinstance(el, str):
                eb = el.encode("utf-8")
                pe += bytes([0]) + enc32(len(eb)) + eb
            else:
                pe += bytes([1]) + enc32(el)
        ft = ftype.encode("ascii")
        out += enc32(j) + enc32(len(pe)) + pe + enc32(len(ft)) + ft
    return out


def schema_digest(entries) -> bytes:
    """sd = H("QPRSS-v3|schema" ‖ count ‖ enc_schema)。长度 = λ_H。"""
    ent = list(entries)
    assert len({e[0] for e in ent}) == len(ent), "schema j 重复"
    return H(b"QPRSS-v3|schema" + enc32(len(ent)) + enc_schema(ent))


def M_reg(rid: bytes, ver_old: int, h_old: bytes, ver_new: int, h_new: bytes,
          t_new: int, cid: bytes, id16: bytes, role: bytes) -> bytes:
    """16号 §三：扩展登记转录（旧/新链头+版本+请求者认证信息）。"""
    return (b"QPRSS-v2|reg" + rid + enc32(ver_old) + h_old
            + enc32(ver_new) + h_new + enc32(t_new) + cid + id16 + bytes([ROLES[role]]))


def M_revlist(epoch: int, ids) -> bytes:
    return b"QPRSS-v2|revlist" + enc64(epoch) + b"".join(sorted(ids))


def h0_of(rid: bytes, n: int, acc0: bytes, P0, sd: bytes = None) -> bytes:
    return H_L(M_init(rid, n, acc0, P0, set(range(1, n + 1)), sd=sd))


def hi_of(e_bytes: bytes, h_prev: bytes) -> bytes:
    return H_L(e_bytes + h_prev)


# ---------- 审计条目编码 ----------
# e = seq(4) ID(16) role(1) H(Cert)(λ) op(1) bmp(I_{i-1}) bmp(I_i) encP(P_{i-1}) encP(P_i) ts(8)
# 15号 P1：ts 为声明性元数据，不参与判定；t_rev^seen 已删除。

def enc_e(seq, rid_id: bytes, role: bytes, cert_h: bytes, I_prev, I_new, P_prev, P_new, ts, n):
    return (enc32(seq) + rid_id + bytes([ROLES[role]]) + cert_h + b"R"
            + bmp(I_prev, n) + bmp(I_new, n) + encP(P_prev) + encP(P_new) + enc64(ts))


# ---------- Stage-5.9 撤销快照（s59 新增；与既有签名域零交集） ----------

def M_revsnap(epoch: int, entries) -> bytes:
    """RA 撤销快照：b"QPRSS-v3|revsnap"|epoch|count|每项 id16(16B)|enc64(eff_ts)。
    entries = [(id16, eff_ts), ...]；eff_ts 与 e.ts 同一声明性墙钟域
    （hop 声称时间 ≥ eff_ts ⟹ 该 hop 属撤销后授权，验证拒绝；之前的合法
    hop 不受其后撤销牵连）。RA 签名（CTX_ANC）后才是可信撤销状态。"""
    ent = sorted(entries)
    out = b"QPRSS-v3|revsnap" + enc64(epoch) + enc32(len(ent))
    for (id16, eff_ts) in ent:
        assert len(id16) == 16
        out += id16 + enc64(eff_ts)
    return out


def parse_revsnap(msg: bytes):
    """M_revsnap 的对偶解析；结构不符即 ValueError（= 不可信输入，拒绝）。
    P0.2-r2（AUD-03）：截断体在此抛 ValueError 而非 struct.error——verify 的
    except 子句才接得住。"""
    if msg[:16] != b"QPRSS-v3|revsnap":
        raise ValueError("bad revsnap prefix")
    if len(msg) < 28:
        raise ValueError("revsnap truncated")
    epoch = struct.unpack(">Q", msg[16:24])[0]
    cnt = struct.unpack(">I", msg[24:28])[0]
    p, out = 28, []
    for _ in range(cnt):
        if p + 24 > len(msg):
            raise ValueError("revsnap truncated")
        out.append((msg[p:p + 16], struct.unpack(">Q", msg[p + 16:p + 24])[0]))
        p += 24
    if p != len(msg):
        raise ValueError("revsnap trailing bytes")
    return epoch, out
