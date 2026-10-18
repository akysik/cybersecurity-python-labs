import csv
import hashlib
import json
import os
from datetime import datetime
from functools import wraps

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 9
SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = os.path.join("labs", "lab01", "data")
USERS_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or password == "":
        raise ValueError("Пароль не може бути порожнім")

    if salt is None or salt == "":
        raise ValueError("Сіль не може бути порожньою")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль повинен містити щонайменше {MIN_PASSWORD_LENGTH} символів"
        )

    value = (password + salt).encode("utf-8")
    return hashlib.blake2s(value).hexdigest()


users_to_register = (
    ("artur", "CyberPass1!"),
    ("admin", "AdminPass123!"),
    ("student", "Student123!"),
    ("analyst", "Analysis2026!"),
    ("security", "Security#123"),
    ("developer", "Developer1!"),
    ("operator", "Operator#2026"),
    ("manager", "Manager123!"),
    ("tester", "Testing#123"),
    ("expert", "ExpertPass1!"),
)


def create_user(username, password):
    password_hash = generate_hash(password, SALT)
    return username, password_hash


def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)

    with open(USERS_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password_hash"])

        for username, password in users_list:
            writer.writerow(create_user(username, password))


def read_users():
    users_db = []

    with open(USERS_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        users_db = list(reader)

    return users_db


def save_log(event):
    os.makedirs(DATA_DIR, exist_ok=True)

    logs = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as file:
                logs = json.load(file)

                if not isinstance(logs, list):
                    logs = []
        except (OSError, json.JSONDecodeError):
            logs = []

    logs.append(event)

    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(logs, file, ensure_ascii=False, indent=4)


def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "")

        try:
            result = func(*args, **kwargs)

            event = {
                "event": "login",
                "user": username,
                "result": "success" if result else "failure",
                "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {},
            }

            save_log(event)
            return result

        except Exception:
            event = {
                "event": "login",
                "user": username,
                "result": "failure",
                "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {},
            }

            save_log(event)
            raise

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    if username is None or username == "":
        raise ValueError("Логін не може бути порожнім")

    if password is None or password == "":
        raise ValueError("Пароль не може бути порожнім")

    users_db = read_users()
    entered_hash = generate_hash(password, SALT)

    for user in users_db:
        if user["username"] == username and user["password_hash"] == entered_hash:
            return True

    return False


def main():
    try:
        print(f"Студент: {STUDENT_NAME}")
        print(f"Група: {GROUP_NAME}")
        print(f"Варіант: {VARIANT_NUMBER}")
        print("Алгоритм хешування: blake2s")
        print(f"Персональна сіль: {SALT}")
        print()

        create_users(users_to_register)

        users_db = read_users()

        print("=== БАЗА КОРИСТУВАЧІВ ===")
        print(f"{'Логін':<15} {'Хеш пароля'}")
        print("-" * 80)

        for user in users_db:
            print(f"{user['username']:<15} {user['password_hash']}")

        print()
        print("=== ПЕРЕВІРКА ВХОДУ ===")

        tests = (
            ("artur", "CyberPass1!"),
            ("admin", "WrongPassword1!"),
            ("student", "Student123!"),
        )

        for username, password in tests:
            result = login(username, password)

            if result:
                print(f"{username}: вхід успішний")
            else:
                print(f"{username}: помилка входу")

    except FileNotFoundError as error:
        print("Файл не знайдено:", error)

    except PermissionError as error:
        print("Немає дозволу на роботу з файлом:", error)

    except ValidationError as error:
        print("Помилка перевірки:", error)

    except ValueError as error:
        print("Помилка значення:", error)

    except OSError as error:
        print("Помилка роботи з файлом:", error)


if __name__ == "__main__":
    main()
