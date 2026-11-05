# -*- coding: utf-8 -*-
"""Paper-facing API (Def. 5 in §3.1): a thin delegation layer over the
internal modules. No new algorithms — the five algorithms are the internal
functions renamed to the paper's notation; bytes and semantics are identical.

    Setup(1^λ)              → pp                    s5_qprss.setup
    KeyGen(pp)              → (PK, SK)             s5_sig.core.keygen
    Signing(PK,SK,S,P;ρ)    → σ_S                  s5_qprss.signing
    Redact(S,σ,S',P',ID_R,role_R,vk_R,sk_R;ρ)      s5_qprss.redact
    Verify(PK,S,σ,mode;ρ)   → {accept, ⊥}          s5_qprss.verify

ρ = (RID, sd); S is the j→y field map (or an already-built record); σ is the
Sigma artifact. Certificates (cert_S/cert_R) are public RA-issued material
(Aux in §3.1) and are carried here as Cert objects holding (ID_X, role_X, vk_X).
"""
from . import s5_qprss as _Q
from . import s5_sig, canon, policy as _pol

POL_VER_LEGACY = _pol.POL_VER_LEGACY
POL_VER_GENERAL = _pol.POL_VER_GENERAL


def Setup(lam: int = None, *, scheme: str = "B1", pol_ver: int = 1,
          B_max: int = (1 << 32) - 1, seed: bytes = None):
    """Setup(1^λ) → pp. λ is fixed through the scheme profile (B1-65 lattice
    parameter set); pol_ver/B_max are the public parameters of §2.2/§4.1
    (policy encoding version, maximum edit budget)."""
    return _Q.setup(scheme, seed=seed, pol_ver=pol_ver, B_max=B_max)


def KeyGen(pp):
    """KeyGen(pp) → (PK, SK) in paper order (B1-65: PK = 3,712 B seeded key)."""
    sk, pk = s5_sig.core(pp["scheme"]).keygen()
    return pk, sk


def Signing(PK, SK, S, P, rho, pp, cert_s, *, rng=None,
            schema_digest=None, sig_rng=None):
    """Signing(PK,SK,S,P;ρ) → σ_S.

    S: {j: y_bytes} (FHIR canonical_json); P: policy.Policy (W,M,b);
    rho: (RID, sd); pp: Setup output (commitment G/D plus pol_ver/B_max);
    cert_s: the signer certificate issued by the RA (Aux, §3.1). SK must be
    the key bound to cert_s.pk at issuance time.
    """
    rid, sd = rho
    return _Q.signing(pp, SK, cert_s, rid, S, P, rng=rng,
                      schema_digest=sd, sig_rng=sig_rng)


def Redact(S, sigma, S_prime, P_prime, ID_R, role_R, vk_R, sk_R, rho,
           *, pp=None, ts: int = 0, legacy=False, sig_rng=None):
    """Redact(S,σ,S',P',ID_R,role_R,vk_R,sk_R;ρ) → σ_S' ∣ ⊥.

    S_prime: retained index set I'_S; P_prime: updated policy; ID_R/role_R/vk_R
    are authenticated through cert_R=(μ,τ) (the vk_R argument *is* the cert_R
    object — the key self-certifies). Raises RedactRefused on ⊥.
    """
    return _Q.redact(pp, sigma, S_prime, P_prime, vk_R, sk_R, ts,
                     legacy=legacy, sig_rng=sig_rng)


def Verify(PK, S, sigma, mode: str, rho, *, cfg=None, ra=None, nonce=None,
           revsnap=None, **kw):
    """Verify(PK,S,σ,mode;ρ) → {accept, ⊥}; mode ∈ {hist, fresh}.

    Returns "accept_historical"/"accept_fresh"; raises VerifyReject(step)
    (= ⊥) on any failed check. cfg must contain pk_ra (administrator vk).
    """
    if cfg is None:
        cfg = {"pk_ra": PK}
    return _Q.verify(cfg, sigma, mode, ra=ra, nonce=nonce, revsnap=revsnap, **kw)
