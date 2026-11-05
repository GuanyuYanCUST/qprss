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
NONCE_LEN = 32       # fresh challenge/response nonce, exactly 32 B (CSPRNG;
                     # tests may inject their own)
CTX_CERT = b"qprss-cert"
CTX_ORIG = b"qprss-orig"
CTX_RED = b"qprss-red"
CTX_ANC = b"qprss-anc"
CTX_REG = b"qprss-reg"


def H(x: bytes) -> bytes:
    return hashlib.shake_256(b"QPRSS-H|" + x).digest(LAMBDA_H)


def H_L(x: bytes) -> bytes:
    return hashlib.shake_256(b"QPRSS-HL|" + x).digest(LAMBDA_H)


def H_B(x: bytes) -> bytes:
    """BindId's own domain label (prefix disjoint from H/H_L)."""
    return hashlib.shake_256(b"QPRSS-HB|" + x).digest(LAMBDA_H)


def H_cert(x: bytes) -> bytes:
    """H_cert of §4.1(2): digest over the canonical encoding of the complete
    certificate including the administrator signature. Own domain label
    (disjoint prefixes); input = cert.bytes() = sig‖msg."""
    return hashlib.shake_256(b"QPRSS-Hcert|" + x).digest(LAMBDA_H)


def cert_digest(cert) -> bytes:
    """Audit-hop binding digest d_r = H_cert(cert_r) (§4.4(4): the 4th
    component of a_t, administrator signature included). cert must provide
    .bytes() (sig‖msg)."""
    return H_cert(cert.bytes())


def CertId(cert_msg: bytes) -> bytes:
    """cid_S = CertId(M_S^cert) (paper notation alias): digest of the
    certificate body, 48 B. Covers id/pk/role/scope/validity — an
    authentication-era identity; it changes on every renewal."""
    return H(cert_msg)


def BindId(rid: bytes, id16: bytes, pk: bytes) -> bytes:
    """bid_S = BindId(RID, ID_S, PK): the renewal-stable identity digest,
    384-bit (LAMBDA_H = 48 B, not 256-bit). Binds exactly the
    certificate-authenticated RID‖ID_S(16 B)‖PK in that fixed order; it
    excludes validity/serial/issuance version/signature randomness — so it
    stays the same across renewals of the same (RID, ID_S, PK). A different
    object from H_cert(EncCert(cert)), which is the signature-bearing audit
    digest."""
    if len(rid) != 16:
        raise ValueError("BindId: rid must be 16 bytes")
    if len(id16) != 16:
        raise ValueError("BindId: id16 must be 16 bytes")
    return H_B(rid + id16 + pk)


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
# adm has exactly one deterministic encoding: entries in strict ascending
# (role code, tag, ids) order (wildcard first, enumerated ids in
# lexicographic order within a role), ids sorted and deduplicated within an
# entry; the decode side (s5_qprss.dec_encP) rejects the duals: illegal
# tag / empty enumeration / duplicate ids / duplicate or out-of-order
# entries / truncation.

def adm_key(role: bytes, idpat):
    """Canonical ordering key of an adm entry. Wildcard = 0, enumeration =
    1; within a role the wildcard sorts first."""
    if idpat == WILD or idpat == "*":
        return (ROLES[role], 0, ())
    ids = tuple(sorted(set(idpat)))
    assert all(len(i) == 16 for i in ids)
    return (ROLES[role], 1, ids)


def enc_adm_entry(role: bytes, idpat) -> bytes:
    code = ROLES[role]
    if idpat == WILD or idpat == "*":
        return bytes([code, 1])
    ids = sorted(set(idpat))                     # canonical order + dedup
    if not ids:
        raise ValueError("empty adm id enumeration")
    assert all(len(i) == 16 for i in ids)
    return bytes([code, 0, len(ids)]) + b"".join(ids)


def encP(P) -> bytes:
    """Restricted-instance encoding (ver=1, §4.3 "restricted policy
    instances use the deterministic encoding version fixed by Setup"):
    admLen|adm|bits_n(W)|enc32(b). Legal only in the M=U∖W subfamily."""
    if getattr(P, "ver", 1) != 1:
        raise ValueError("encP: general policy must use enc_pol (ver=2)")
    adm = b"".join(enc_adm_entry(r, x) for (r, x) in P.adm)
    return bytes([len(P.adm)]) + adm + bmp(P.w, P.n) + enc32(P.d)


# ---------- general policy descriptor encoding of eq. (2) (§2.2) ----------
# Artifact-level policy field ver=2 = POL2_PREFIX + canonical adm profiles
# + descriptor:
#   "pol-v1" ∥ enc_u(n) ∥ bits_n(W) ∥ bits_n(M) ∥ enc_u(b)
# enc_u = length-prefixed minimal-width unsigned int (L ≤ 4 bytes
# big-endian; leading zeros are non-canonical and rejected on decode).
# POL2_PREFIX and the restricted stream are structurally mutually exclusive:
# a restricted stream starts with admLen, whose successor byte must be a
# legal role code 0..4, while "Q"=0x51/"P"=0x50 always fails that decoder
# (and vice versa).

POL2_PREFIX = b"QPRSS-pol2|"
POLV1 = b"pol-v1"
ENC_U_MAX = 4          # ints at most 4 bytes (< 2^32, same domain as enc32)


def enc_u(v: int) -> bytes:
    """Length-prefixed minimal-width unsigned int: L(1 B) + L bytes
    big-endian; v=0 → L=0."""
    if not isinstance(v, int) or v < 0 or v >= 1 << (8 * ENC_U_MAX):
        raise ValueError(f"enc_u: value out of range [0, 2^{8 * ENC_U_MAX})")
    L = (v.bit_length() + 7) // 8
    return bytes([L]) + v.to_bytes(L, "big")


def dec_u_at(buf, off: int):
    """Dual parse of enc_u; non-minimal int (leading zero byte) / overlong /
    truncated → ValueError."""
    if off >= len(buf):
        raise ValueError("enc_u truncated (length byte)")
    L = buf[off]
    off += 1
    if L > ENC_U_MAX:
        raise ValueError(f"enc_u length {L} > {ENC_U_MAX}")
    if off + L > len(buf):
        raise ValueError("enc_u truncated (body)")
    if L > 0 and buf[off] == 0:
        raise ValueError("enc_u non-minimal (leading zero byte)")
    return int.from_bytes(buf[off:off + L], "big"), off + L


def bmp_checked(b: bytes, n: int):
    """Dual parse of bits_n: length exactly ⌈n/8⌉ and the trailing padding
    bits zero (decode rule of eq. (2))."""
    B = (n + 7) // 8
    if len(b) != B:
        raise ValueError(f"bits_n length {len(b)} != ⌈{n}/8⌉={B}")
    # Padding = the HIGH bits of the last byte (bmp writes bit (j-1)%8
    # little-endian style, j ≤ n ⇒ bits 0..n%8-1 carry data). Getting the
    # mask direction wrong rejects legal data bits — it triggers on an
    # n=102 chain whose W contains {97,98}, as the multi-hop experiment
    # demonstrated. So: check the high pad bits.
    pad = 8 * B - n
    if pad and b[-1] >> (8 - pad):
        raise ValueError("bits_n nonzero padding bits")
    return bmp_decode(b, n)


def enc_pol(P) -> bytes:
    """EncPol(P) (dispatch over the versions of eq. (2)): ver=1 → the
    restricted-instance encP bytes; ver=2 → POL2_PREFIX + admLen|adm +
    "pol-v1"|enc_u(n)|bits_n(W)|bits_n(M)|enc_u(b). One policy object has a
    unique encoding for a given ver (adm is canonicalized at construction)."""
    if getattr(P, "ver", 1) == 1:
        return encP(P)
    adm = b"".join(enc_adm_entry(r, x) for (r, x) in P.adm)
    return (POL2_PREFIX + bytes([len(P.adm)]) + adm
            + POLV1 + enc_u(P.n) + bmp(P.w, P.n) + bmp(P.M, P.n) + enc_u(P.d))


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
    out = b"QPRSS-v2|orig" + rid + enc32(n) + acc0 + enc_pol(P0) + bmp(I0, n)
    return out if sd is None else out + b"|sd|" + sd


def M_init(rid: bytes, n: int, acc0: bytes, P0, I0, sd: bytes = None) -> bytes:
    """Audit-chain anchor (h₀ = H_L(M_init)). The sd append exists because
    without it two records with the same acc0/P0 but different schemas share
    h₀ — an editor's audit signature (M_red chains through h_prev) could
    then be transplanted across schema contexts. Without sd the bytes match
    the older anchor exactly."""
    out = b"QPRSS-v2|init" + rid + enc32(n) + acc0 + enc_pol(P0) + bmp(I0, n)
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


# v4 fresh response: v3 (nonce+rid+head+t*+ts+epoch) plus the registration
# identity cid = H(Cert_S.msg) (the RegisterInitial authentication marker).
# The nonce is exactly NONCE_LEN = 32 B; the v4 prefix is disjoint from the
# v2/v3 domains.

def M_resp4(nonce: bytes, rid: bytes, h_star: bytes, t_star: int, ts: int,
            epoch: int, cid: bytes) -> bytes:
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be exactly {NONCE_LEN} bytes")
    return (b"QPRSS-v4|resp" + bytes(nonce) + rid + h_star
            + enc32(t_star) + enc64(ts) + enc64(epoch) + cid)


def parse_resp4(msg: bytes):
    """Dual parse of M_resp4; structural mismatch raises ValueError
    (untrusted input → reject)."""
    if msg[:13] != b"QPRSS-v4|resp":
        raise ValueError("bad resp4 prefix")
    if len(msg) != 13 + NONCE_LEN + 16 + 2 * LAMBDA_H + 4 + 8 + 8:
        raise ValueError("bad resp4 length")
    p = 13
    nonce = msg[p:p + NONCE_LEN]
    rid = msg[p + NONCE_LEN:p + NONCE_LEN + 16]
    p += NONCE_LEN + 16
    h_star = msg[p:p + LAMBDA_H]
    t_star = struct.unpack(">I", msg[p + LAMBDA_H:p + LAMBDA_H + 4])[0]
    ts = struct.unpack(">Q", msg[p + LAMBDA_H + 4:p + LAMBDA_H + 12])[0]
    epoch = struct.unpack(">Q", msg[p + LAMBDA_H + 12:p + LAMBDA_H + 20])[0]
    cid = msg[p + LAMBDA_H + 20:p + 2 * LAMBDA_H + 20]
    return nonce, rid, h_star, t_star, ts, epoch, cid


# v5 fresh response (the paper's EncResp_5) replaces v4's cid field (a
# certificate-BODY digest, which changes on renewal ⇒ a legitimate renewal
# would be wrongly rejected) with the renewal-stable identity digest
# bid = BindId(RID, ID_S, PK). Same layout length as v4 (177 B): the 8th
# prefix byte '4'/'5' makes the two versions mutually exclusive, so old and
# new can never be mixed or misread; the signature covers the complete
# canonical encoding.

def M_resp5(nonce: bytes, rid: bytes, h_star: bytes, t_star: int, ts: int,
            epoch: int, bid: bytes) -> bytes:
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be exactly {NONCE_LEN} bytes")
    if not isinstance(bid, (bytes, bytearray)) or len(bid) != LAMBDA_H:
        raise ValueError(f"bid must be exactly {LAMBDA_H} bytes")
    return (b"QPRSS-v5|resp" + bytes(nonce) + rid + h_star
            + enc32(t_star) + enc64(ts) + enc64(epoch) + bytes(bid))


def parse_resp5(msg: bytes):
    """Dual parse of M_resp5; structural mismatch raises ValueError
    (untrusted input → reject). v4/v5 prefixes are mutually exclusive:
    parse_resp5 rejects a v4 message and vice versa."""
    if msg[:13] != b"QPRSS-v5|resp":
        raise ValueError("bad resp5 prefix")
    if len(msg) != 13 + NONCE_LEN + 16 + 2 * LAMBDA_H + 4 + 8 + 8:
        raise ValueError("bad resp5 length")
    p = 13
    nonce = msg[p:p + NONCE_LEN]
    rid = msg[p + NONCE_LEN:p + NONCE_LEN + 16]
    p += NONCE_LEN + 16
    h_star = msg[p:p + LAMBDA_H]
    t_star = struct.unpack(">I", msg[p + LAMBDA_H:p + LAMBDA_H + 4])[0]
    ts = struct.unpack(">Q", msg[p + LAMBDA_H + 4:p + LAMBDA_H + 12])[0]
    epoch = struct.unpack(">Q", msg[p + LAMBDA_H + 12:p + LAMBDA_H + 20])[0]
    bid = msg[p + LAMBDA_H + 20:p + 2 * LAMBDA_H + 20]
    return nonce, rid, h_star, t_star, ts, epoch, bid


def M_reginit(rid: bytes, n: int, acc0: bytes, P0, cid: bytes, sd: bytes = None) -> bytes:
    """Initial registration transcript (binds Cert_S); the optional sd
    anchors the field semantic map at first registration. Without sd the
    bytes match the earlier form."""
    out = b"QPRSS-v2|reginit" + rid + enc32(n) + acc0 + enc_pol(P0) + cid
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
    assert len({e[0] for e in ent}) == len(ent), "duplicate schema j"
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
# e = seq(4) ID(16) role(1) H_cert(cert)(λ) op(1) bmp(I_{i-1}) bmp(I_i)
#     enc_pol(P_{i-1}) enc_pol(P_i) ts(8)
# ts is declared metadata and takes no part in any decision.

def enc_e(seq, rid_id: bytes, role: bytes, cert_h: bytes, I_prev, I_new, P_prev, P_new, ts, n):
    return (enc32(seq) + rid_id + bytes([ROLES[role]]) + cert_h + b"R"
            + bmp(I_prev, n) + bmp(I_new, n) + enc_pol(P_prev) + enc_pol(P_new) + enc64(ts))


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
