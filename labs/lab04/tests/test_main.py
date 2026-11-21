"""Тести командного інтерфейсу (інтеграція модулів, без мережі)."""

import json
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import main as cli

SAMPLE_CVE = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def variant_six(monkeypatch):
    """Тести CLI фіксують номер варіанта 6 незалежно від shared/student.py."""
    monkeypatch.setattr(cli, "VARIANT_NUMBER", 6)


@pytest.fixture
def no_network(monkeypatch):
    """Будь-яка спроба отримати дані з мережі провалює тест."""
    fake = Mock(side_effect=AssertionError("мережевий запит у локальному режимі"))
    monkeypatch.setattr(cli.api_client, "fetch_response", fake)
    return fake


def write_json(tmp_path, data) -> str:
    path = tmp_path / "response.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


# --- Локальний режим ---------------------------------------------------------------


def test_local_sample_prints_single_json_report(capsys, sample_path, no_network):
    code = cli.main(["--cve", SAMPLE_CVE, "--input", str(sample_path)])
    out, err = capsys.readouterr()

    assert code == 0
    assert err == ""
    report = json.loads(out)  # stdout містить рівно один JSON-об'єкт
    assert report["decision"] == "review"
    assert report["variant"] == 6
    assert report["observed"] == "HIGH"
    no_network.assert_not_called()


def test_local_not_found_exits_zero(capsys, tmp_path, no_network):
    path = write_json(tmp_path, {"totalResults": 0, "vulnerabilities": []})
    code = cli.main(["--cve", SAMPLE_CVE, "--input", path])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "not_found"


def test_local_insufficient_data_exits_zero(
    capsys, tmp_path, sample_payload, no_network
):
    del sample_payload["vulnerabilities"][0]["cve"]["metrics"]
    code = cli.main(
        ["--cve", SAMPLE_CVE, "--input", write_json(tmp_path, sample_payload)]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "insufficient_data"


def test_invalid_json_file_exits_one(capsys, tmp_path, no_network):
    path = tmp_path / "broken.json"
    path.write_text("{ not json", encoding="utf-8")
    code = cli.main(["--cve", SAMPLE_CVE, "--input", str(path)])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "JSON" in err
    assert "Traceback" not in err


def test_missing_file_exits_one(capsys, tmp_path, no_network):
    code = cli.main(["--cve", SAMPLE_CVE, "--input", str(tmp_path / "absent.json")])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "прочитати" in err


def test_non_utf8_file_exits_one(capsys, tmp_path, no_network):
    path = tmp_path / "cp1251.json"
    path.write_bytes('{"a": "Опис"}'.encode("cp1251"))
    code = cli.main(["--cve", SAMPLE_CVE, "--input", str(path)])
    assert code == 1
    assert "UTF-8" in capsys.readouterr().err


def test_data_error_exits_one(capsys, sample_path, no_network):
    # Файл містить інший ідентифікатор, ніж запитаний
    code = cli.main(["--cve", "CVE-2021-44228", "--input", str(sample_path)])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "структура" in err


def test_json_null_file_is_data_error(capsys, tmp_path, no_network):
    code = cli.main(["--cve", SAMPLE_CVE, "--input", write_json(tmp_path, None)])
    assert code == 1
    assert capsys.readouterr().out == ""


# --- Мережевий режим (підміна функції клієнта) --------------------------------------


def test_network_mode_uses_client(capsys, monkeypatch, sample_payload):
    fake = Mock(return_value=sample_payload)
    monkeypatch.setattr(cli.api_client, "fetch_response", fake)

    assert cli.main(["--cve", SAMPLE_CVE]) == 0
    fake.assert_called_once_with(SAMPLE_CVE)
    assert json.loads(capsys.readouterr().out)["decision"] == "review"


def make_http_error(status: int) -> requests.HTTPError:
    response = Mock(spec=requests.Response)
    response.status_code = status
    return requests.HTTPError(f"{status} Client Error", response=response)


@pytest.mark.parametrize(
    ("error", "fragment"),
    [
        (requests.exceptions.ReadTimeout("read timed out"), "час очікування"),
        (requests.exceptions.ConnectionError("refused"), "з'єднатися"),
        (make_http_error(404), "404"),
        (make_http_error(503), "503"),
        (requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1), "JSON"),
        (cli.api_client.UnexpectedStatusError(204), "204"),
        (requests.exceptions.TooManyRedirects("loop"), "запит"),
    ],
)
def test_network_errors_exit_one(capsys, monkeypatch, error, fragment):
    monkeypatch.setenv("NVD_API_KEY", "fake-secret-key")
    monkeypatch.setattr(cli.api_client, "fetch_response", Mock(side_effect=error))

    code = cli.main(["--cve", SAMPLE_CVE])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert fragment in err
    assert "fake-secret-key" not in err
    assert "Traceback" not in err


# --- Помилки аргументів і варіанта ------------------------------------------------


@pytest.mark.parametrize(
    "cve",
    [
        "cve-2021-44228",
        "CVE-21-44228",
        "CVE-2021-123",
        "CVE-2021-44228 ",
        " CVE-2021-44228",
        "CVE-2021-44228x",
        "CVE_2021_44228",
        "",
    ],
)
def test_invalid_cve_format_exits_two(capsys, cve, no_network):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--cve", cve])
    assert exc_info.value.code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("cve", ["CVE-2021-4422", "CVE-2099-10001", "CVE-1999-1234567"])
def test_valid_cve_formats_accepted(cve, monkeypatch):
    payload = {"vulnerabilities": []}
    monkeypatch.setattr(cli.api_client, "fetch_response", Mock(return_value=payload))
    assert cli.main(["--cve", cve]) == 0


def test_missing_cve_argument_exits_two(no_network):
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, True, "6", None, 6.0])
def test_invalid_variant_exits_two(capsys, monkeypatch, sample_path, variant):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", variant)
    code = cli.main(["--cve", SAMPLE_CVE, "--input", str(sample_path)])
    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert "VARIANT_NUMBER" in err


def test_load_response_reads_utf8_json(sample_path):
    data = cli.load_response(sample_path)
    assert data["vulnerabilities"][0]["cve"]["id"] == SAMPLE_CVE
