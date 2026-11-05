# -*- coding: utf-8 -*-
"""论文门面接口（Task A）：以论文 §3.1 定义 5 的五算法签名为准的薄委托层。

不新增论文之外的正式算法接口——仅将内部实现函数以论文记号命名对齐；
语义、字节与内部函数完全一致（289 项存量测试经内部函数覆盖）。

    Setup(1^λ)              → pp                    委托 s5_qprss.setup
    KeyGen(pp)              → (PK, SK)             委托 s5_sig.core.keygen
    Signing(PK,SK,S,P;ρ)    → σ_S                  委托 s5_qprss.signing
    Redact(S,σ,S',P',ID_R,role_R,vk_R,sk_R;ρ)      委托 s5_qprss.redact
    Verify(PK,S,σ,mode;ρ)   → {accept, ⊥}          委托 s5_qprss.verify

ρ = (RID, sd)：S 为 j→y 字段映射（或已构造的记录）；σ 为 Sigma 工件。
证书（cert_S/cert_R）按论文 §3.1 属公开认证材料 Aux，由 RA 事先签发、
随工件提供——门面以 Cert 对象承载 (ID_X, role_X, vk_X) 三元组。
"""
from . import s5_qprss as _Q
from . import s5_sig, canon, policy as _pol

POL_VER_LEGACY = _pol.POL_VER_LEGACY
POL_VER_GENERAL = _pol.POL_VER_GENERAL


def Setup(lam: int = None, *, scheme: str = "B1", pol_ver: int = 1,
          B_max: int = (1 << 32) - 1, seed: bytes = None):
    """Setup(1^λ) → pp。λ 经方案档（B1-65 格参数集）固定；pol_ver/B_max
    为论文 §2.2/§4.1 公共参数（策略编码版本与最大编辑预算）。"""
    return _Q.setup(scheme, seed=seed, pol_ver=pol_ver, B_max=B_max)


def KeyGen(pp):
    """KeyGen(pp) → (PK, SK)。论文序（B1-65：PK=3,712B 种子化公钥）。"""
    sk, pk = s5_sig.core(pp["scheme"]).keygen()
    return pk, sk


def Signing(PK, SK, S, P, rho, pp, cert_s, *, rng=None,
            schema_digest=None, sig_rng=None):
    """Signing(PK,SK,S,P;ρ) → σ_S。

    S: {j: y_bytes}（FHIR canonical_json 产物）；P: policy.Policy（W,M,b）；
    rho: (RID, sd)；pp: Setup 产物（承诺 G/D 与 pol_ver/B_max）；
    cert_s: RA 签发的签名者证书（Aux 材料，论文 §3.1）。SK 必须与
    cert_s.pk 对应（由 RA 签发时绑定）。
    """
    rid, sd = rho
    return _Q.signing(pp, SK, cert_s, rid, S, P, rng=rng,
                      schema_digest=sd, sig_rng=sig_rng)


def Redact(S, sigma, S_prime, P_prime, ID_R, role_R, vk_R, sk_R, rho,
           *, pp=None, ts: int = 0, legacy=False, sig_rng=None):
    """Redact(S,σ,S',P',ID_R,role_R,vk_R,sk_R;ρ) → σ_S' ∣ ⊥。

    S_prime: 保留索引集 I'_S；P_prime: 更新策略；ID_R/role_R/vk_R 经证书
    cert_R=(μ,τ) 认证（vk_R 参数即 cert_R 对象——公钥由证书自证）；
    失败抛 RedactRefused（= ⊥）。
    """
    return _Q.redact(pp, sigma, S_prime, P_prime, vk_R, sk_R, ts,
                     legacy=legacy, sig_rng=sig_rng)


def Verify(PK, S, sigma, mode: str, rho, *, cfg=None, ra=None, nonce=None,
           revsnap=None, **kw):
    """Verify(PK,S,σ,mode;ρ) → {accept, ⊥}。mode ∈ {hist, fresh}。

    accept 返回 "accept_historical"/"accept_fresh"；任一检查失败抛
    VerifyReject(step)（= ⊥）。cfg 需含 pk_ra（管理员验证钥）。
    """
    if cfg is None:
        cfg = {"pk_ra": PK}
    return _Q.verify(cfg, sigma, mode, ra=ra, nonce=nonce, revsnap=revsnap, **kw)
