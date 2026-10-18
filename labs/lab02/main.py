import sys

from labs.lab02.task1 import Admin, User, UserAccount
from labs.lab02.task2 import run_cli


def run_demo():
    print("=== Демонстрація Завдання 1 (ООП) ===")

    user = User("j_doe", "j_doe@example.com")
    user.set_password("SecureP@ss123")
    print(f"Створено користувача: {user}")
    print(f"Перевірка правильного пароля: {user.check_password('SecureP@ss123')}")
    print(f"Перевірка неправильного пароля: {user.check_password('WrongPass')}")

    try:
        user.email = "bad_email_format"
    except ValueError as e:
        print(f"Перехоплено очікувану помилку валідації email: {e}")

    admin = Admin("admin_alex", "alex@company.org")
    admin.grant_permission("READ_LOGS")
    print(f"Адміністратор: {admin}")

    account = UserAccount(user)
    login_success = account.login("j_doe", "SecureP@ss123", "192.168.1.10")
    print(f"Успішний вхід: {login_success}")
    print(f"Сесія активна та автентифікована?: {account.is_authenticated()}")

    account.logout()
    print(f"Після logout() сесія активна?: {account.is_authenticated()}")

    print("\n=== Логи аудиту (AuditLog) ===")
    for record in account.audit_log.show_all():
        print(
            f"[{record.timestamp.strftime('%H:%M:%S')}] {record.username} -> {record.action}"
        )


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo()
    elif len(sys.argv) > 1 and sys.argv[1] == "analyze":
        sys.argv.pop(1)
        run_cli()
    else:
        print("Використання:")
        print("  python -m labs.lab02.main demo")
        print(
            "  python -m labs.lab02.main analyze --wordlist labs/lab02/data/passwords.txt [додаткові прапорці]"
        )


if __name__ == "__main__":
    main()
