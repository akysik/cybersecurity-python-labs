from labs.lab01.task1 import main as task1_main
from labs.lab01.task2 import main as task2_main
from labs.lab01.task3 import main as task3_main


def main():
    while True:
        print("\n=== ЛАБОРАТОРНА РОБОТА №1 ===")
        print("1 - Завдання 1")
        print("2 - Завдання 2")
        print("3 - Завдання 3")
        print("0 - Вихід")

        choice = input("\nОберіть завдання: ")

        if choice == "1":
            print("\n=== ЗАВДАННЯ 1 ===")
            task1_main()

        elif choice == "2":
            print("\n=== ЗАВДАННЯ 2 ===")
            task2_main()

        elif choice == "3":
            print("\n=== ЗАВДАННЯ 3 ===")
            task3_main()

        elif choice == "0":
            print("Роботу завершено.")
            break

        else:
            print("Невірний вибір. Введіть 0, 1, 2 або 3.")


if __name__ == "__main__":
    main()
