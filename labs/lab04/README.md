# Лабораторна робота №4 — NVD CVE API та pytest

Консольна утиліта шукає запис CVE у National Vulnerability Database (NVD CVE API 2.0),
перевіряє відповідь, вибирає оцінку CVSS v3.1 і застосовує правило варіанта.
Результат — один JSON-об'єкт у `stdout`.

## Варіант

Номер варіанта береться з `shared/student.py` (`VARIANT_NUMBER = 6`).

**Варіант 6 — високий вплив на цілісність:**
`decision = "review"`, якщо `baseScore >= 7.0` **і** `cvssData.integrityImpact == "HIGH"`
в одній і тій самій вибраній оцінці CVSS v3.1.

## Встановлення

З кореня репозиторію, у віртуальному середовищі з Python 3.12+:

```bash
pip install -r requirements.txt
```

## Запуск

Локальний режим (без мережі, синтетична відповідь):

```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Запит до NVD (один ручний запит):

```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

Необов'язковий ключ API передається лише через змінну середовища `NVD_API_KEY`
(у заголовку `apiKey`, не в URL). Ключ не зберігається у файлах проєкту.

## Формат звіту

Ключі: `cve_id`, `variant`, `description`, `vuln_status`, `cvss_version`, `score`,
`score_source`, `vector`, `rule` (`threshold`, `field`, `expected`), `observed`,
`decision`. Відсутні значення — `null`.

Можливі `decision`: `not_found`, `rejected`, `insufficient_data`, `review`, `other`.
Стани `other` та `insufficient_data` **не** означають, що вразливість безпечна.

## Коди завершення

| Код | Значення |
|-----|----------|
| 0 | Звіт сформовано (зокрема `not_found` чи `insufficient_data`) |
| 1 | Помилка отримання, читання файла або перевірки даних |
| 2 | Неправильні аргументи або номер варіанта |

## Перевірка

```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Тести не звертаються до мережі: `tests/conftest.py` забороняє справжні запити Requests
і видаляє `NVD_API_KEY` перед кожним тестом.
