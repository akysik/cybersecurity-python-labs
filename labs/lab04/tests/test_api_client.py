"""Тести HTTP-клієнта: підміняється requests.get, а не сама функція клієнта."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE_ID = "CVE-2099-10001"
EMPTY_PAYLOAD = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}


def make_response(status_code: int = 200, payload: object = None) -> Mock:
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def install_get(
    monkeypatch, response: Mock | None = None, error: Exception | None = None
):
    fake_get = Mock(return_value=response, side_effect=error)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


# --- build_headers ----------------------------------------------------------------


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_fake_key_is_stripped(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key-123  ")
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_headers_blank_key_ignored(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


# --- fetch_response: успіх --------------------------------------------------------


def test_fetch_uses_expected_request(monkeypatch):
    response = make_response(payload=EMPTY_PAYLOAD)
    fake_get = install_get(monkeypatch, response)

    assert api_client.fetch_response(CVE_ID) == EMPTY_PAYLOAD
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": CVE_ID},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_key_in_header_not_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fake-key-123")
    fake_get = install_get(monkeypatch, make_response(payload=EMPTY_PAYLOAD))

    api_client.fetch_response(CVE_ID)
    _, kwargs = fake_get.call_args
    assert kwargs["headers"]["apiKey"] == "fake-key-123"
    assert kwargs["params"] == {"cveId": CVE_ID}
    assert "fake-key-123" not in fake_get.call_args.args[0]


# --- fetch_response: помилки --------------------------------------------------------


@pytest.mark.parametrize("status", [404, 403, 500, 503])
def test_fetch_http_error_propagates(monkeypatch, status):
    response = make_response(status_code=status)
    response.raise_for_status.side_effect = requests.HTTPError(
        f"{status} error", response=response
    )
    install_get(monkeypatch, response)

    with pytest.raises(requests.HTTPError) as exc_info:
        api_client.fetch_response(CVE_ID)
    assert exc_info.value.response.status_code == status
    response.json.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("connect timeout"),
        requests.exceptions.ReadTimeout("read timeout"),
        requests.exceptions.ConnectionError("no route"),
    ],
)
def test_fetch_network_errors_propagate(monkeypatch, error):
    install_get(monkeypatch, error=error)
    with pytest.raises(type(error)):
        api_client.fetch_response(CVE_ID)


def test_fetch_invalid_json_propagates(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    install_get(monkeypatch, response)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response(CVE_ID)


@pytest.mark.parametrize("status", [204, 301, 302])
def test_fetch_unexpected_status_raises(monkeypatch, status):
    # raise_for_status() не піднімає винятку для 2xx/3xx, але потрібен саме 200
    response = make_response(status_code=status)
    install_get(monkeypatch, response)

    with pytest.raises(api_client.UnexpectedStatusError):
        api_client.fetch_response(CVE_ID)
    response.json.assert_not_called()
