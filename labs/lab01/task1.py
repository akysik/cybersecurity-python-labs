import random
import string

from shared.student import STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "InfoS3c@2023",
    "simple123",
    "Def3ns3@Key",
    "public",
    "Encrypt3d#Pass",
    "basic123",
    "Secur3@Analysis",
    "temp123",
    "Pr0t3ct@Data",
    "default",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {"simple123", "public", "basic123", "temp123", "default", "guest"}


random_indexes = random.sample(range(len(passwords)), 3)

for index in random_indexes:
    passwords.append(passwords[index])


def check_password(password):
    # Заборонений пароль
    if password in forbidden_passwords or len(password) < criteria["min_length"]:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in string.punctuation for char in password)

    all_required = has_digit and has_upper and has_special

    # Дуже сильний
    if (
        all_required
        and len(password) >= criteria["min_length"] + 4
        and passwords.count(password) == 1
    ):
        return "Дуже сильний"

    # Сильний
    if all_required and len(password) < criteria["min_length"] + 4:
        return "Сильний"

    passed = sum([has_digit, has_upper, has_special, has_lower])

    # Середній
    if passed > 1:
        return "Середній"

    # Слабкий
    if passed >= 1:
        return "Слабкий"

    return "Слабкий"


def main():
    print(f"Студент: {STUDENT_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print()

    print(f"{'Пароль':<22} {'Надійність'}")
    print("-" * 40)

    for password in passwords:
        print(f"{password:<22} {check_password(password)}")


if __name__ == "__main__":
    main()
