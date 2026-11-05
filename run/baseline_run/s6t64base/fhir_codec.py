r"""HL7 FHIR field canonical encoding.

Layering:
- the fixed 32 B synthetic-field tests are the security regression layer and
  stay;
- this module is the real encoding layer: extract the sub-object from a FHIR
  document by path, normalize it to deterministic bytes with canonical_json,
  and feed those as y_j into Signing/Verify — signing and verification use
  exactly the same byte representation;
- data: hand-written compliant FHIR R4 examples (no real PHI anywhere) plus
  a Synthea synthetic bundle for the formal experiments (fully synthetic
  patients, no PHI; introducing real/de-identified datasets would need a
  fresh compliance review).

The normalization is an explicitly safe subset of RFC 8785 (JCS) — not "JCS
unimplemented", but a restricted dialect proven byte-identical to JCS within
the subset:
  json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
The full list of divergence points from real JCS, and how each is handled:
  1. Key ordering: JCS sorts by UTF-16 code units, Python by code points —
     they differ only when a key contains supplementary-plane characters
     (> U+FFFF) mixed with certain BMP characters (–￿) → the subset FORBIDS
     non-BMP keys (validate_jcs_safe rejects; a test demonstrates a real
     divergence case).
  2. Numbers: JCS uses ECMAScript IEEE-754 serialization (1.0 → "1", lossy
     above 2^53); Python repr(37.0) = "37.0" → the subset FORBIDS floats;
     ints are limited to |v| ≤ 2^53−1 (JS safe integers).
  3. String escaping: both use \uXXXX/short escapes for control characters
     and pass non-ASCII through raw — identical; lone surrogates are kept
     by ECMAScript but fail Python's UTF-8 encoding → forbidden.
Inside the whitelist (str / int(≤2^53) / bool / None / list / dict + BMP
keys + no lone surrogates), canonical_json ≡ JCS byte for byte (by
elimination over the divergence list above).
"""
import json
import struct

from . import canon

# ---------- canonical extraction ----------

_INT53 = (1 << 53) - 1


def validate_jcs_safe(obj, path="$"):
    """Recursively check that obj falls inside the JCS-safe subset; raise
    ValueError (naming the path) on anything outside. Both the signing and
    the verification side must call this before extracting y_j — it is what
    makes the representation cross-language."""
    if isinstance(obj, bool) or obj is None:
        return True
    if isinstance(obj, int):
        if not (-_INT53 <= obj <= _INT53):
            raise ValueError(f"{path}: int 超出 JS 安全整数范围 |v|>2^53-1: {obj}")
        return True
    if isinstance(obj, float):
        raise ValueError(f"{path}: float 不在 JCS 安全子集（ECMAScript 数字规范形未实现）")
    if isinstance(obj, str):
        for c in obj:
            if 0xD800 <= ord(c) <= 0xDFFF:
                raise ValueError(f"{path}: 孤立代理项 U+{ord(c):04X}")
        return True
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: 键必须为 str，得到 {type(k).__name__}")
            for c in k:
                if ord(c) > 0xFFFF:
                    raise ValueError(f"{path}: 键含非 BMP 字符 U+{ord(c):X}（UTF-16 序分歧域，禁用）")
                if 0xD800 <= ord(c) <= 0xDFFF:
                    raise ValueError(f"{path}: 键含孤立代理项")
            validate_jcs_safe(v, f"{path}.{k}")
        return True
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            validate_jcs_safe(v, f"{path}[{i}]")
        return True
    raise ValueError(f"{path}: 不支持的数据类型 {type(obj).__name__}")


def canonical_json(obj) -> bytes:
    """Deterministic JSON bytes: sorted keys + tight separators + UTF-8 (no
    whitespace, no escaping ambiguity). Callers must run validate_jcs_safe
    first (field_bytes_checked below does it for you)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def path_get(obj, path):
    """path = tuple of dict keys (str) or list indices (int)."""
    for k in path:
        obj = obj[k]
    return obj


def field_bytes(doc, path) -> bytes:
    """Field bytes shared by signing and verification:
    y_j = canonical_json(doc[path]). (No validation; use field_bytes_checked
    on the real path.)"""
    return canonical_json(path_get(doc, path))


def field_bytes_checked(doc, j: int, schema) -> bytes:
    """Extract per the trusted schema table: path, declared type, then JCS
    subset validation, then canonicalize. schema = [(j, path, ftype), ...]
    — the type comes from the trusted table, NOT from the document: a value
    whose type mismatches is rejected, so an attacker cannot drift types
    document-side to smuggle a different semantic mapping."""
    ent = dict((e[0], e) for e in schema)
    if j not in ent:
        raise ValueError(f"field {j} not in schema")
    _, path, ftype = ent[j]
    v = path_get(doc, path)
    got = {str: "str", int: "int", bool: "bool", list: "list", dict: "dict",
           type(None): "null"}.get(type(v), type(v).__name__)
    if got != ftype:
        raise ValueError(f"field {j}: 文档类型 {got} ≠ schema 声明 {ftype}")
    validate_jcs_safe(v, f"field{j}")
    return canonical_json(v)


# ---------- hand-written compliant FHIR R4 example (fictional, no PHI) ----------

EXAMPLE_BUNDLE = {
    "resourceType": "Bundle",
    "id": "bundle-qr-demo-2026",
    "type": "collection",
    "entry": [
        {
            "fullUrl": "urn:uuid:0c0a7a70-7d6e-4f0e-a3dd-000000000001",
            "resource": {
                "resourceType": "Patient",
                "id": "pat-demo-001",
                "identifier": [{"system": "urn:oid:1.2.840.99999.1", "value": "D-2026-001"}],
                "active": True,
                "name": [{"family": "示范", "given": ["甲", "乙"]}],
                "gender": "female",
                "birthDate": "1970-01-01",
                "address": [{"city": "示例市", "district": "示例区", "postalCode": "000000"}],
            },
        },
        {
            "fullUrl": "urn:uuid:0c0a7a70-7d6e-4f0e-a3dd-000000000002",
            "resource": {
                "resourceType": "Observation",
                "id": "obs-demo-002",
                "status": "final",
                "code": {"coding": [{"system": "http://loinc.org", "code": "8310-5",
                                     "display": "Body temperature"}],
                         "text": "体温"},
                "subject": {"reference": "urn:uuid:0c0a7a70-7d6e-4f0e-a3dd-000000000001"},
                "effectiveDateTime": "2026-10-01T08:30:00+08:00",
                "valueQuantity": {"value": 37, "unit": "Cel", "system": "http://unitsofmeasure.org"},
                "note": [{"text": "示例注释：无临床含义"}],
            },
        },
        {
            "fullUrl": "urn:uuid:0c0a7a70-7d6e-4f0e-a3dd-000000000003",
            "resource": {
                "resourceType": "MedicationRequest",
                "id": "med-demo-003",
                "status": "active",
                "intent": "order",
                "medicationCodeableConcept": {
                    "text": "示例药物（虚构）",
                    "coding": [{"system": "urn:demo:med", "code": "DM-0001"}],
                },
                "authoredOn": "2026-10-01T09:00:00+08:00",
            },
        },
    ],
}

# ---------- trusted schema table (single source of the j→path/type map) ----------
# ftype values come from the JCS-safe whitelist; the table itself is TRUSTED
# CONFIGURATION (in a deployment it would be pinned alongside pk_RA), and its
# digest sd = canon.schema_digest(SCHEMA) goes into M_orig/M_reginit and the
# v4 serialization.

SCHEMA = [
    (1, ("entry", 0, "resource", "id"), "str"),                    # short str
    (2, ("entry", 0, "resource", "name"), "list"),                 # nested list[dict]
    (3, ("entry", 0, "resource", "birthDate"), "str"),             # date str
    (4, ("entry", 0, "resource", "address"), "list"),              # list[dict]
    (5, ("entry", 0, "resource", "active"), "bool"),               # bool
    (6, ("entry", 1, "resource", "code"), "dict"),                 # deep dict
    (7, ("entry", 1, "resource", "effectiveDateTime"), "str"),     # timestamp str
    (8, ("entry", 1, "resource", "valueQuantity"), "dict"),        # quantity dict
    (9, ("entry", 1, "resource", "note"), "list"),                 # list[dict] notes
    (10, ("entry", 2, "resource", "medicationCodeableConcept"), "dict"),   # concept dict
    (11, ("entry", 2, "resource", "authoredOn"), "str"),           # str
    (12, ("resourceType",), "str"),                                # top-level str
]

# legacy view (j → path), kept for the older test surface
FIELD_PATHS = {j: p for (j, p, _) in SCHEMA}


def example_field_bytes(j: int) -> bytes:
    return field_bytes_checked(EXAMPLE_BUNDLE, j, SCHEMA)


# ---------- Synthea synthetic FHIR (real-format data layer of the experiments) ----------

def synthea_schema(bundle, n: int) -> list:
    """Build an n-field trusted schema from a Synthea bundle:
    j → ("entry", i, "resource", key). Keys rotate over
    ("resourceType", "status", "id") (naturally varying lengths); only
    JCS-safe scalar str fields are taken, missing ones are skipped; the
    declared type is "str" (the trusted table decides the type), and every
    extraction goes through field_bytes_checked, so document-side type
    drift is rejected on the spot."""
    ent = []
    j = 1
    keys = ("resourceType", "status", "id")
    for i, e in enumerate(bundle.get("entry", [])):
        if j > n:
            break
        res = e.get("resource", {})
        key = keys[(j - 1) % len(keys)]
        if key in res and isinstance(res[key], str):
            ent.append((j, ("entry", i, "resource", key), "str"))
            j += 1
    if len(ent) < n:
        raise ValueError(f"bundle 仅能构造 {len(ent)} 个安全字段 < n={n}")
    return ent[:n]
