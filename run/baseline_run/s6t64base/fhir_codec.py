r"""HL7 FHIR 字段规范编码（2B-2 任务四 → 17号 最终补丁）。

分层声明：
- 固定 32 B 合成字段测试（test_all/test_2b1/test_2b2）= **安全回归层**，继续保留；
- 本模块 = **真实编码层**：从 FHIR 文档按路径提取子对象，canonical_json 规范化为
  确定性字节串，作为 y_j 进入 Signing/Verify——签名与验证使用完全相同的字节表示；
- 数据：手写合规 FHIR R4 示例（无任何真实 PHI）+ Synthea 合成 bundle（正式实验，
  全合成患者、无 PHI；真实/脱敏数据集若引入须重走合规审查）。

规范化 = RFC 8785 (JCS) 的**显式安全子集**（17号 §3）：不是"未实现 JCS"，
而是经证明在本子集内与 JCS 逐字节一致的受限方言：
  json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
与完整 JCS 的全部差异点（及本实现的处置）：
  1. 键排序：JCS 按 UTF-16 码元序，Python 按码点序——仅当键含增补平面字符
     （>U+FFFF）与某些 BMP 字符（–￿）共存时分歧 → 子集**禁止非 BMP 键**
     （validate_jcs_safe 拒绝；测试演示真实分歧例）。
  2. 数字：JCS=ECMAScript IEEE-754 序列化（1.0→"1"，>2^53 失真）；
     Python repr(37.0)="37.0" → 子集**禁止 float**；int 限 |v| ≤ 2^53−1（JS 安全整数）。
  3. 字符串转义：两者对控制字符均用 \uXXXX/短转义、非 ASCII 原文输出——一致；
     孤立代理项（lone surrogate）ECMAScript 保留、Python UTF-8 编码失败 → 子集禁止。
  白名单内（str/int(≤2^53)/bool/None/list/dict + BMP 键 + 无孤立代理），
  canonical_json ≡ JCS（逐字节；按上述逐条差异的排除法论证，17号 §3.2）。
"""
import json
import struct

from . import canon

# ---------- 规范化提取 ----------

_INT53 = (1 << 53) - 1


def validate_jcs_safe(obj, path="$"):
    """递归校验对象落在 JCS 安全子集内；越界抛 ValueError（指明路径）。
    签名/验证两侧提取 y_j 前都必须调用——保证跨语言语义（17号 任务一(3)）。"""
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
    """确定性 JSON 字节串：排序键 + 紧凑分隔 + UTF-8（无空白/无转义差异）。
    调用方须先 validate_jcs_safe（本模块 field_bytes_checked 已内置）。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def path_get(obj, path):
    """path = 元组，元素为 dict 键（str）或 list 下标（int）。"""
    for k in path:
        obj = obj[k]
    return obj


def field_bytes(doc, path) -> bytes:
    """签名/验证共用的字段字节：y_j = canonical_json(doc[path])。
    （不校验；正式路径用 field_bytes_checked。）"""
    return canonical_json(path_get(doc, path))


def field_bytes_checked(doc, j: int, schema) -> bytes:
    """按可信 schema 表提取：路径、声明类型、JCS 子集三重校验后规范化。
    schema = [(j, path, ftype), ...]（17号 §2：类型取自可信表而非文档——
    文档值类型错配即拒，防止攻击者用文档侧类型漂移绕过语义映射）。"""
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


# ---------- 手写合规 FHIR R4 示例（全虚构，无 PHI） ----------

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

# ---------- 可信 schema 表（17号 §2：j→path/type 映射的单一来源） ----------
# ftype 取自 JCS 安全白名单；表本身是**可信配置**（部署：与 pk_RA 同级钉扎），
# 其摘要 sd=canon.schema_digest(SCHEMA) 入 M_orig/M_reginit/序列化 v4。

SCHEMA = [
    (1, ("entry", 0, "resource", "id"), "str"),                    # str 短
    (2, ("entry", 0, "resource", "name"), "list"),                 # 嵌套 list[dict]
    (3, ("entry", 0, "resource", "birthDate"), "str"),             # str 日期
    (4, ("entry", 0, "resource", "address"), "list"),              # list[dict]
    (5, ("entry", 0, "resource", "active"), "bool"),               # bool
    (6, ("entry", 1, "resource", "code"), "dict"),                 # dict 深层
    (7, ("entry", 1, "resource", "effectiveDateTime"), "str"),     # str 时间戳
    (8, ("entry", 1, "resource", "valueQuantity"), "dict"),        # dict 数量
    (9, ("entry", 1, "resource", "note"), "list"),                 # list[dict] 注释
    (10, ("entry", 2, "resource", "medicationCodeableConcept"), "dict"),   # dict 概念
    (11, ("entry", 2, "resource", "authoredOn"), "str"),           # str
    (12, ("resourceType",), "str"),                                # 顶层 str
]

# 兼容 2B-2 T4 的旧视图（j → path）
FIELD_PATHS = {j: p for (j, p, _) in SCHEMA}


def example_field_bytes(j: int) -> bytes:
    return field_bytes_checked(EXAMPLE_BUNDLE, j, SCHEMA)


# ---------- Synthea 合成 FHIR（正式实验的真实格式数据层，17号 §5） ----------

def synthea_schema(bundle, n: int) -> list:
    """从 Synthea bundle 构造 n 字段可信 schema：j→("entry",i,"resource",key)。
    键在 ("resourceType", "status", "id") 间轮转（长度天然可变）；
    只收 JCS 安全的标量 str 字段，缺失即跳过；类型声明 str（可信表定类型），
    提取时逐字段 field_bytes_checked 复核（文档侧类型漂移即拒）。"""
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
