"""Canonical transcription encodings (single source). λ_H defaults to 48 B
(32 B is the comparison setting). All Sign/Verify paths go through this
module; no algorithm is allowed to inline its own concatenations."""
import hashlib
import struct

LAMBDA_H = 48  # default; switch to 32 for the ablation comparison
Y_LEN = 32     # default synthetic field-value length (v3 serialization uses
               # length prefixes, so fixed length is no longer required)

ROLES = {b"signer": 0, b"physician": 1, b"nurse": 2, b"admin": 3, b"auditor": 4}
ROLE_BY_CODE = {v: k for k, v in ROLES.items()}
WILD = b"*"          # wildcard: whole-universe value only, never a pattern
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
    """v3 variable-length field encoding: enc32(j)‖enc32(len(y))‖y.
    Signing and verification use exactly these bytes — y is produced by the
    caller's canonicalization (e.g. FHIR canonical_json)."""
    return enc32(j) + enc32(len(y)) + y


def dec_field(buf, off: int):
    """Returns (j, y, end offset); out-of-bounds raises (truncation guard
    for the self-delimiting stream)."""
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
    """Bitmap: index j (1..n) → bit j−1. Length exactly ⌈n/8⌉."""
    out = bytearray((n + 7) // 8)
    for j in I:
        assert 1 <= j <= n, f"index {j} out of range"
        out[(j - 1) // 8] |= 1 << ((j - 1) % 8)
    return bytes(out)


def bmp_decode(b: bytes, n: int):
    assert len(b) == (n + 7) // 8, "bitmap length mismatch"
    return {j for j in range(1, n + 1) if b[(j - 1) // 8] >> ((j - 1) % 8) & 1}


# ---------- policy encodings ----------
# encP = admLen(1) | per-entry role(1)+tag(1)+[n(1)+ids*16] | bmp(W) | d(4)

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


# ---------- certificate messages ----------
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
    """sd (schema digest), when provided, binds the field semantic map (the
    digest of the j→path/type table). Without it the bytes match the older
    synthetic-layer artifacts exactly (that anchor stays unchanged)."""
    out = b"QPRSS-v2|orig" + rid + enc32(n) + acc0 + encP(P0) + bmp(I0, n)
    return out if sd is None else out + b"|sd|" + sd


def M_init(rid: bytes, n: int, acc0: bytes, P0, I0, sd: bytes = None) -> bytes:
    """Audit-chain anchor (h₀ = H_L(M_init)). The sd append exists because
    without it two records with the same acc0/P0 but different schemas share
    h₀ — an editor's audit signature (M_red chains through h_prev) could
    then be transplanted across schema contexts. Without sd the bytes match
    the older anchor exactly."""
    out = b"QPRSS-v2|init" + rid + enc32(n) + acc0 + encP(P0) + bmp(I0, n)
    return out if sd is None else out + b"|sd|" + sd


def M_red(rid: bytes, i: int, e_bytes: bytes, h_prev: bytes, h_i: bytes) -> bytes:
    return b"QPRSS-v2|red" + rid + enc32(i) + e_bytes + h_prev + h_i


def M_resp(nonce: bytes, rid: bytes, h_star: bytes, t_star: int, ts: int) -> bytes:
    return b"QPRSS-v2|resp" + nonce + rid + h_star + enc32(t_star) + enc64(ts)


def M_gaz(period: int, rid: bytes, h_star: bytes, t_star: int, ts: int) -> bytes:
    return b"QPRSS-v2|gaz" + enc32(period) + rid + h_star + enc32(t_star) + enc64(ts)


# v3 anchors the revocation epoch into the response domain: fresh/gazette
# responses carry RA.epoch, and verifiers use it to reject stale revsnaps
# (rv_epoch < anchor_epoch). The v3 prefix is disjoint from the v2 domains
# (old signature anchors still parse as v2 = legacy, with no epoch to
# compare against).

def M_resp3(nonce: bytes, rid: bytes, h_star: bytes, t_star: int, ts: int,
            epoch: int) -> bytes:
    return (b"QPRSS-v3|resp" + nonce + rid + h_star
            + enc32(t_star) + enc64(ts) + enc64(epoch))


def M_gaz3(period: int, rid: bytes, h_star: bytes, t_star: int, ts: int,
           epoch: int) -> bytes:
    return (b"QPRSS-v3|gaz" + enc32(period) + rid + h_star
            + enc32(t_star) + enc64(ts) + enc64(epoch))


def parse_resp3(msg: bytes):
    """Dual parse of M_resp3; structural mismatch raises ValueError
    (untrusted input → reject)."""
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
    """Dual parse of M_gaz3; structural mismatch raises ValueError."""
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
    """Initial registration transcript (binds Cert_S); the optional sd
    anchors the field semantic map at first registration. Without sd the
    bytes match the earlier form."""
    out = b"QPRSS-v2|reginit" + rid + enc32(n) + acc0 + encP(P0) + cid
    return out if sd is None else out + b"|sd|" + sd


# ---------- schema encoding and digest (authenticating the semantic map) ----------
# entries = [(j, path, ftype), ...], path elements are str (dict keys) or
# int (list indices), ftype ∈ {"str","int","bool","list","dict"} (the
# JCS-safe whitelist).

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
    """sd = H("QPRSS-v3|schema" ‖ count ‖ enc_schema). Length = λ_H."""
    ent = list(entries)
    assert len({e[0] for e in ent}) == len(ent), "schema j 重复"
    return H(b"QPRSS-v3|schema" + enc32(len(ent)) + enc_schema(ent))


def M_reg(rid: bytes, ver_old: int, h_old: bytes, ver_new: int, h_new: bytes,
          t_new: int, cid: bytes, id16: bytes, role: bytes) -> bytes:
    """Extended registration transcript (old/new chain heads + version +
    requester authentication)."""
    return (b"QPRSS-v2|reg" + rid + enc32(ver_old) + h_old
            + enc32(ver_new) + h_new + enc32(t_new) + cid + id16 + bytes([ROLES[role]]))


def M_revlist(epoch: int, ids) -> bytes:
    return b"QPRSS-v2|revlist" + enc64(epoch) + b"".join(sorted(ids))


def h0_of(rid: bytes, n: int, acc0: bytes, P0, sd: bytes = None) -> bytes:
    return H_L(M_init(rid, n, acc0, P0, set(range(1, n + 1)), sd=sd))


def hi_of(e_bytes: bytes, h_prev: bytes) -> bytes:
    return H_L(e_bytes + h_prev)


# ---------- audit-entry encoding ----------
# e = seq(4) ID(16) role(1) H(Cert)(λ) op(1) bmp(I_{i-1}) bmp(I_i) encP(P_{i-1}) encP(P_i) ts(8)
# ts is declared metadata and takes no part in any decision.

def enc_e(seq, rid_id: bytes, role: bytes, cert_h: bytes, I_prev, I_new, P_prev, P_new, ts, n):
    return (enc32(seq) + rid_id + bytes([ROLES[role]]) + cert_h + b"R"
            + bmp(I_prev, n) + bmp(I_new, n) + encP(P_prev) + encP(P_new) + enc64(ts))


# ---------- revocation snapshots (disjoint from all signed domains) ----------

def M_revsnap(epoch: int, entries) -> bytes:
    """RA revocation snapshot:
    b"QPRSS-v3|revsnap"|epoch|count|per-entry id16(16 B)|enc64(eff_ts).
    entries = [(id16, eff_ts), ...]; eff_ts lives in the same declared
    wall-clock domain as e.ts (a hop claiming a time ≥ eff_ts belongs to
    post-revocation authorization → verification rejects it; legal hops
    from before are unaffected by a later revocation). Trusted revocation
    state only after the RA signature (CTX_ANC)."""
    ent = sorted(entries)
    out = b"QPRSS-v3|revsnap" + enc64(epoch) + enc32(len(ent))
    for (id16, eff_ts) in ent:
        assert len(id16) == 16
        out += id16 + enc64(eff_ts)
    return out


def parse_revsnap(msg: bytes):
    """Dual parse of M_revsnap; structural mismatch raises ValueError (=
    untrusted input → reject). A truncated body must raise ValueError here
    rather than struct.error — that is what verify's except clause can
    actually catch."""
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
