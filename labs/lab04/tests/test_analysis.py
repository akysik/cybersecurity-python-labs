"""Модульні тести перевірки даних і правила варіанта 6.

Варіант 6: score >= 7.0 і cvssData.integrityImpact == "HIGH" -> review.
"""

import copy
import math

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"
VARIANT = 6


def cvss_entry(payload: dict) -> dict:
    """Перший елемент cvssMetricV31 у копії синтетичної відповіді."""
    return payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]


def cve_of(payload: dict) -> dict:
    return payload["vulnerabilities"][0]["cve"]


def run(payload: dict) -> dict:
    return build_report(extract_record(payload, CVE_ID), CVE_ID, VARIANT)


# --- Синтетичний файл повністю -------------------------------------------------


def test_sample_file_gives_review(sample_payload):
    assert run(sample_payload) == {
        "cve_id": "CVE-2099-10001",
        "variant": 6,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 7.0, "field": "integrityImpact", "expected": "HIGH"},
        "observed": "HIGH",
        "decision": "review",
    }


def test_payload_is_not_modified(sample_payload):
    before = copy.deepcopy(sample_payload)
    run(sample_payload)
    assert sample_payload == before


# --- Межа порогу та ознака -------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "integrity", "expected"),
    [
        (6.9, "HIGH", "other"),  # нижче порога
        (7.0, "HIGH", "review"),  # рівно на порозі
        (7.1, "HIGH", "review"),  # вище порога
        (10, "HIGH", "review"),  # верхня межа, int
        (9.8, "LOW", "other"),  # висока оцінка, невідповідна ознака
        (9.8, "NONE", "other"),
        (0, "HIGH", "other"),  # нижня межа
    ],
)
def test_threshold_and_field(sample_payload, score, integrity, expected):
    data = cvss_entry(sample_payload)["cvssData"]
    data["baseScore"] = score
    data["integrityImpact"] = integrity
    report = run(sample_payload)
    assert report["decision"] == expected
    assert report["observed"] == integrity
    assert report["score"] == score


# --- not_found, rejected, insufficient_data --------------------------------------


def test_not_found_has_null_data_fields():
    payload = {"totalResults": 0, "vulnerabilities": []}
    record = extract_record(payload, CVE_ID)
    assert record is None
    report = build_report(record, CVE_ID, VARIANT)
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE_ID
    assert report["variant"] == 6
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "integrityImpact",
        "expected": "HIGH",
    }
    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[key] is None


def test_rejected_ignores_high_score(sample_payload):
    cve_of(sample_payload)["vulnStatus"] = "Rejected"
    report = run(sample_payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None
    assert report["vector"] is None


def test_rejected_does_not_validate_broken_metrics(sample_payload):
    cve_of(sample_payload)["vulnStatus"] = "Rejected"
    cve_of(sample_payload)["metrics"] = None
    assert run(sample_payload)["decision"] == "rejected"


def test_missing_status_gives_insufficient_data(sample_payload):
    del cve_of(sample_payload)["vulnStatus"]
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None
    assert report["observed"] is None


@pytest.mark.parametrize(
    "drop",
    ["metrics", "cvssMetricV31", "empty_list"],
)
def test_missing_cvss31_gives_insufficient_data(sample_payload, drop):
    cve = cve_of(sample_payload)
    if drop == "metrics":
        del cve["metrics"]
    elif drop == "cvssMetricV31":
        cve["metrics"] = {"cvssMetricV2": []}
    else:
        cve["metrics"]["cvssMetricV31"] = []
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None


def test_missing_variant_field_gives_insufficient_data(sample_payload):
    del cvss_entry(sample_payload)["cvssData"]["integrityImpact"]
    report = run(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None
    assert report["score"] == 9.8


# --- Некоректне поле варіанта ----------------------------------------------------


@pytest.mark.parametrize("bad_value", [None, "high", "MEDIUM", 1, True, ""])
def test_invalid_variant_field_raises(sample_payload, bad_value):
    cvss_entry(sample_payload)["cvssData"]["integrityImpact"] = bad_value
    with pytest.raises(ValueError):
        run(sample_payload)


# --- Некоректна оцінка ----------------------------------------------------------


@pytest.mark.parametrize(
    "bad_score",
    ["9.8", True, False, None, math.nan, math.inf, -math.inf, -0.1, 10.1, [9.8]],
)
def test_invalid_base_score_raises(sample_payload, bad_score):
    cvss_entry(sample_payload)["cvssData"]["baseScore"] = bad_score
    with pytest.raises(ValueError):
        run(sample_payload)


def test_missing_base_score_raises(sample_payload):
    del cvss_entry(sample_payload)["cvssData"]["baseScore"]
    with pytest.raises(ValueError):
        run(sample_payload)


# --- Вибір оцінки: Primary має пріоритет -----------------------------------------


def make_entry(source: str, kind: str, score: float, integrity: str) -> dict:
    return {
        "source": source,
        "type": kind,
        "cvssData": {
            "version": "3.1",
            "vectorString": f"CVSS:3.1/I:{integrity[0]}",
            "baseScore": score,
            "integrityImpact": integrity,
        },
    }


def test_primary_wins_over_earlier_secondary(sample_payload):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        make_entry("secondary@example.invalid", "Secondary", 9.9, "LOW"),
        make_entry("nvd@nist.gov", "Primary", 7.5, "HIGH"),
    ]
    report = run(sample_payload)
    assert report["score_source"] == "nvd@nist.gov"
    assert report["score"] == 7.5
    assert report["decision"] == "review"


def test_score_and_field_come_from_same_metric(sample_payload):
    # Висока оцінка Secondary + HIGH у Primary з низькою оцінкою -> other
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        make_entry("secondary@example.invalid", "Secondary", 9.9, "HIGH"),
        make_entry("nvd@nist.gov", "Primary", 5.0, "HIGH"),
    ]
    report = run(sample_payload)
    assert report["score"] == 5.0
    assert report["decision"] == "other"


def test_first_metric_chosen_without_primary(sample_payload):
    cve_of(sample_payload)["metrics"]["cvssMetricV31"] = [
        make_entry("first@example.invalid", "Secondary", 8.0, "HIGH"),
        make_entry("second@example.invalid", "Secondary", 3.0, "LOW"),
    ]
    report = run(sample_payload)
    assert report["score_source"] == "first@example.invalid"
    assert report["decision"] == "review"


# --- Поля звіту version / vectorString / source -----------------------------------


def test_optional_report_fields_missing_become_none(sample_payload):
    entry = cvss_entry(sample_payload)
    del entry["source"]
    del entry["cvssData"]["version"]
    del entry["cvssData"]["vectorString"]
    report = run(sample_payload)
    assert report["score_source"] is None
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["decision"] == "review"


@pytest.mark.parametrize(
    ("where", "key", "value"),
    [
        ("cvssData", "version", "3.0"),
        ("cvssData", "version", 3.1),
        ("cvssData", "vectorString", ""),
        ("entry", "source", None),
    ],
)
def test_invalid_report_fields_raise(sample_payload, where, key, value):
    entry = cvss_entry(sample_payload)
    target = entry["cvssData"] if where == "cvssData" else entry
    target[key] = value
    with pytest.raises(ValueError):
        run(sample_payload)


# --- Структура відповіді ---------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": [{"cve": {}}, {"cve": {}}]},
        {"vulnerabilities": ["text"]},
        {"vulnerabilities": [{"no_cve": {}}]},
    ],
)
def test_invalid_payload_structure_raises(payload):
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_cve_id_mismatch_raises(sample_payload):
    with pytest.raises(ValueError):
        extract_record(sample_payload, "CVE-2021-44228")


@pytest.mark.parametrize("status", ["", "   ", None, 5])
def test_invalid_status_raises(sample_payload, status):
    cve_of(sample_payload)["vulnStatus"] = status
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE_ID)


@pytest.mark.parametrize(
    ("metrics_value", "list_value"),
    [(None, None), ([], None), ({"cvssMetricV31": None}, None), (None, ["x"])],
)
def test_invalid_metrics_structure_raises(sample_payload, metrics_value, list_value):
    cve = cve_of(sample_payload)
    if list_value is None:
        cve["metrics"] = metrics_value
    else:
        cve["metrics"]["cvssMetricV31"] = list_value
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE_ID)


def test_cvss_data_must_be_dict(sample_payload):
    cvss_entry(sample_payload)["cvssData"] = "CVSS:3.1/AV:N"
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE_ID)


# --- Опис -----------------------------------------------------------------------


def test_description_first_nonempty_english(sample_payload):
    cve_of(sample_payload)["descriptions"] = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "First English text"},
        {"lang": "en", "value": "Second English text"},
    ]
    assert run(sample_payload)["description"] == "First English text"


def test_description_none_without_english(sample_payload):
    cve_of(sample_payload)["descriptions"] = [{"lang": "uk", "value": "Опис"}]
    assert run(sample_payload)["description"] is None


@pytest.mark.parametrize(
    "descriptions",
    ["missing", None, "text", [{"lang": "en"}], [{"lang": "en", "value": 1}], ["x"]],
)
def test_invalid_descriptions_raise(sample_payload, descriptions):
    cve = cve_of(sample_payload)
    if descriptions == "missing":
        del cve["descriptions"]
    else:
        cve["descriptions"] = descriptions
    with pytest.raises(ValueError):
        extract_record(sample_payload, CVE_ID)


# --- Номер варіанта -------------------------------------------------------------


@pytest.mark.parametrize("variant", [0, 16, -1, True, "6", 6.0, None])
def test_build_report_rejects_invalid_variant(variant):
    with pytest.raises(ValueError):
        build_report(None, CVE_ID, variant)
