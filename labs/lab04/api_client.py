"""Клієнт NVD CVE API 2.0: заголовки та один GET-запит."""

from __future__ import annotations

import os

import requests

NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT: tuple[float, float] = (3.05, 10)
API_KEY_ENV: str = "NVD_API_KEY"


class UnexpectedStatusError(Exception):
    """Сервер повернув статус без помилки, але не 200 (наприклад, 204 або 3xx)."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"Неочікуваний HTTP-статус: {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає HTTP-заголовки запиту.

    Завжди містить ``Accept: application/json``. Якщо змінна середовища
    ``NVD_API_KEY`` містить непорожнє значення, додає заголовок ``apiKey``
    з ключем без крайніх пробілів. Змінна читається під час виклику.
    """
    headers = {"Accept": "application/json"}
    api_key = os.getenv(API_KEY_ENV)
    if api_key is not None and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> object:
    """Виконує один GET-запит до NVD для ``cve_id`` і повертає декодований JSON.

    Винятки Requests (таймаут, помилка з'єднання, ``HTTPError``,
    ``JSONDecodeError``) не перехоплюються і передаються викликачу.
    Якщо статус не 4xx/5xx, але й не 200, піднімається
    ``UnexpectedStatusError``. Семантична перевірка даних тут не виконується.
    """
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
