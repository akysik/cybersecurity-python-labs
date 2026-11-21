"""CLI для перегляду запису CVE з NVD і формування JSON-звіту.

Запуск з кореня репозиторію (приклади команд див. у README.md):
    python -m labs.lab04.main --cve CVE-2021-44228
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import requests

from labs.lab04 import api_client
from labs.lab04.analysis import build_report, extract_record
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")

EXIT_OK = 0
EXIT_DATA_ERROR = 1
EXIT_USAGE_ERROR = 2

# Позначка невдалого отримання даних (JSON null — це теж значення)
_FAILED = object()


def load_response(path: Path) -> object:
    """Читає локальну відповідь NVD з UTF-8 JSON-файла.

    Винятки читання (OSError, UnicodeDecodeError) і json.JSONDecodeError
    передаються викликачу.
    """
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Перегляд запису CVE з NVD та звіт за правилом варіанта.",
    )
    parser.add_argument(
        "--cve", required=True, help="Ідентифікатор, напр. CVE-2021-44228"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Локальна відповідь NVD (JSON); мережеві запити тоді не виконуються",
    )
    return parser


def _error(message: str) -> None:
    print(f"Помилка: {message}", file=sys.stderr)


def _fetch(cve_id: str) -> object:
    """Отримує відповідь з NVD; у разі помилки друкує пояснення і повертає _FAILED."""
    try:
        return api_client.fetch_response(cve_id)
    except requests.exceptions.Timeout:
        _error("перевищено час очікування відповіді від NVD.")
    except requests.exceptions.ConnectionError:
        _error("не вдалося з'єднатися з NVD.")
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "невідомий"
        _error(f"NVD повернув HTTP-помилку, код статусу {status}.")
    except api_client.UnexpectedStatusError as exc:
        _error(f"NVD повернув неочікуваний статус {exc.status_code}.")
    except requests.exceptions.JSONDecodeError:
        _error("відповідь NVD не є коректним JSON.")
    except requests.exceptions.RequestException:
        _error("не вдалося виконати запит до NVD.")
    return _FAILED


def _load(path: Path) -> object:
    """Читає локальний файл; у разі помилки друкує пояснення і повертає _FAILED."""
    try:
        return load_response(path)
    except json.JSONDecodeError:
        _error(f"файл {path} не містить коректного JSON.")
    except UnicodeDecodeError:
        _error(f"файл {path} не є текстом у кодуванні UTF-8.")
    except OSError:
        _error(f"не вдалося прочитати файл {path}.")
    return _FAILED


def main(argv: list[str] | None = None) -> int:
    """Точка входу CLI. Повертає код завершення 0, 1 або 2."""
    variant = VARIANT_NUMBER
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or not 1 <= variant <= 15
    ):
        _error("VARIANT_NUMBER у shared/student.py має бути цілим числом від 1 до 15.")
        return EXIT_USAGE_ERROR

    parser = build_parser()
    args = parser.parse_args(argv)
    if CVE_PATTERN.fullmatch(args.cve) is None:
        parser.error(
            "--cve має відповідати формату CVE-РРРР-NNNN (напр. CVE-2021-44228)"
        )

    payload = _load(args.input) if args.input is not None else _fetch(args.cve)
    if payload is _FAILED:
        return EXIT_DATA_ERROR

    try:
        record = extract_record(payload, args.cve)
        report = build_report(record, args.cve, variant)
    except ValueError as exc:
        _error(f"некоректна структура даних NVD: {exc}")
        return EXIT_DATA_ERROR

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
