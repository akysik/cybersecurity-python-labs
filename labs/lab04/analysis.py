"""Перевірка відповіді NVD і застосування правила варіанта.

Функції модуля не читають файлів і змінних середовища, не виконують
HTTP-запитів, нічого не друкують і не змінюють переданий ``payload``.
"""

from __future__ import annotations

import math
from typing import Any

# Номер варіанта -> (поріг T, поле cvssData, очікуване значення)
VARIANT_RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

# Допустимі значення полів cvssData (розділ 2.2 методички)
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}

REJECTED_STATUS = "Rejected"


class NVDDataError(ValueError):
    """Відповідь NVD порушує очікуваний контракт даних."""


def _optional_nonempty_str(
    container: dict[str, Any], key: str, where: str
) -> str | None:
    """Повертає None, якщо ключа немає; інакше вимагає непорожній рядок."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise NVDDataError(f"{where}.{key} має бути непорожнім рядком")
    return value


def _pick_description(cve: dict[str, Any]) -> str | None:
    """Перевіряє descriptions і повертає перший непорожній англійський опис."""
    if "descriptions" not in cve:
        raise NVDDataError("Відсутнє обов'язкове поле cve.descriptions")
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise NVDDataError("cve.descriptions має бути списком")
    for item in descriptions:
        if not isinstance(item, dict):
            raise NVDDataError("Елементи cve.descriptions мають бути об'єктами")
        lang, value = item.get("lang"), item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise NVDDataError("Поля lang і value в descriptions мають бути рядками")
    for item in descriptions:
        if item["lang"] == "en" and item["value"].strip():
            return item["value"]
    return None


def _check_score(value: Any) -> float:
    """baseScore: скінченне число 0–10, не bool і не рядок."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NVDDataError("cvssData.baseScore має бути числом")
    if not math.isfinite(value) or not 0 <= value <= 10:
        raise NVDDataError("cvssData.baseScore має бути скінченним числом від 0 до 10")
    return value


def _pick_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибирає оцінку CVSS v3.1 і повертає її у внутрішньому форматі або None."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise NVDDataError("cve.metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    entries = metrics["cvssMetricV31"]
    if not isinstance(entries, list):
        raise NVDDataError("metrics.cvssMetricV31 має бути списком")
    if not entries:
        return None
    if not all(isinstance(entry, dict) for entry in entries):
        raise NVDDataError("Елементи cvssMetricV31 мають бути об'єктами")

    chosen = next(
        (entry for entry in entries if entry.get("type") == "Primary"), entries[0]
    )

    cvss_data = chosen.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise NVDDataError("cvssData вибраної оцінки має бути об'єктом")
    if "baseScore" not in cvss_data:
        raise NVDDataError("У вибраній оцінці відсутній cvssData.baseScore")
    score = _check_score(cvss_data["baseScore"])

    version = _optional_nonempty_str(cvss_data, "version", "cvssData")
    if version is not None and version != "3.1":
        raise NVDDataError('cvssData.version має дорівнювати "3.1"')

    return {
        "score": score,
        "source": _optional_nonempty_str(chosen, "source", "cvssMetricV31[]"),
        "version": version,
        "vector": _optional_nonempty_str(cvss_data, "vectorString", "cvssData"),
        "cvss_data": dict(cvss_data),
    }


def extract_record(payload: object, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None.

    None означає, що запис не знайдено (порожній ``vulnerabilities``).
    Формат запису::

        {
            "cve_id": str,               # ідентифікатор із відповіді
            "vuln_status": str | None,   # vulnStatus або None, якщо поля немає
            "description": str | None,   # перший непорожній опис "en"
            "metric": None | {           # вибрана оцінка CVSS v3.1
                "score": float,          # перевірений baseScore
                "source": str | None,
                "version": "3.1" | None,
                "vector": str | None,
                "cvss_data": dict,       # копія cvssData для правила варіанта
            },
        }

    Для статусу ``Rejected`` або відсутнього статусу оцінки не аналізуються,
    і ``metric`` дорівнює None. За порушення контракту піднімає ValueError.
    """
    if not isinstance(payload, dict):
        raise NVDDataError("Відповідь має бути JSON-об'єктом")
    if "vulnerabilities" not in payload:
        raise NVDDataError("У відповіді відсутнє поле vulnerabilities")
    vulnerabilities = payload["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise NVDDataError("vulnerabilities має бути списком")
    if not vulnerabilities:
        return None
    if len(vulnerabilities) > 1:
        raise NVDDataError(
            "Для одного ідентифікатора очікується не більше одного запису"
        )

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise NVDDataError("Елемент vulnerabilities має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise NVDDataError("cve.id не збігається із запитаним ідентифікатором")

    status = _optional_nonempty_str(cve, "vulnStatus", "cve")
    description = _pick_description(cve)

    metric = None
    if status is not None and status != REJECTED_STATUS:
        metric = _pick_metric(cve)

    return {
        "cve_id": cve_id,
        "vuln_status": status,
        "description": description,
        "metric": metric,
    }


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосовує правило варіанта і повертає словник звіту.

    Рішення: ``not_found``, ``rejected``, ``insufficient_data``, ``review``
    (score >= T і cvssData[field] == expected в одній оцінці) або ``other``.
    Наявне, але некоректне поле варіанта (null, не рядок, недопустиме
    значення) піднімає ValueError.
    """
    if isinstance(variant, bool) or not isinstance(variant, int):
        raise NVDDataError("Номер варіанта має бути цілим числом")
    if variant not in VARIANT_RULES:
        raise NVDDataError("Номер варіанта має бути від 1 до 15")
    threshold, field, expected = VARIANT_RULES[variant]

    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report
    if not isinstance(record, dict):
        raise NVDDataError("Внутрішній запис має бути словником або None")

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]

    if record["vuln_status"] == REJECTED_STATUS:
        report["decision"] = "rejected"
        return report
    metric = record["metric"]
    if record["vuln_status"] is None or metric is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = metric["version"]
    report["score"] = metric["score"]
    report["score_source"] = metric["source"]
    report["vector"] = metric["vector"]

    cvss_data = metric["cvss_data"]
    if field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report
    observed = cvss_data[field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise NVDDataError(f"Недопустиме значення cvssData.{field}")

    report["observed"] = observed
    if metric["score"] >= threshold and observed == expected:
        report["decision"] = "review"
    else:
        report["decision"] = "other"
    return report
