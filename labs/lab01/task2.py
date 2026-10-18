from shared.student import STUDENT_NAME, VARIANT_NUMBER

users = {
    "red_team_lead": {
        "role": "red_team",
        "clearance": 4,
        "department": "Red Team",
        "active": True,
    },
    "blue_team_analyst": {
        "role": "blue_team",
        "clearance": 3,
        "department": "Blue Team",
        "active": True,
    },
    "purple_team_coord": {
        "role": "purple_team",
        "clearance": 3,
        "department": "Purple Team",
        "active": True,
    },
    "student_intern": {
        "role": "student",
        "clearance": 1,
        "department": "Academia",
        "active": True,
    },
    "retired_expert": {
        "role": "retired",
        "clearance": 2,
        "department": "Emeritus",
        "active": False,
    },
}


resources = {
    "attack_scenarios": 4,
    "defense_playbooks": 3,
    "exercise_plans": 3,
    "research_papers": 1,
    "exploit_tools": 4,
    "student_resources": 1,
    "simulation_results": 3,
    "red_team_tools": 4,
    "blue_team_reports": 3,
    "public_research": 1,
}


security_levels = ("Academic", "Operational", "Tactical", "Strategic")


blocked_users = {"retired_expert", "academic_violator", "leaked_account"}


def check_access(username, resource):
    if username not in users:
        return "Відмовлено: користувача не знайдено"

    if resource not in resources:
        return "Відмовлено: ресурс не знайдено"

    user = users[username]

    if username in blocked_users:
        return "Відмовлено: користувач заблокований"

    if not user["active"]:
        return "Відмовлено: обліковий запис неактивний"

    required_clearance = resources[resource]

    if user["clearance"] >= required_clearance:
        return "Доступ дозволено"

    return "Доступ заборонено: недостатній рівень допуску"


def main():
    print(f"Студент: {STUDENT_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print()

    print("=== СИСТЕМА КОНТРОЛЮ ДОСТУПУ ===")
    print()

    for username in users:
        print(f"Користувач: {username}")

        for resource in resources:
            result = check_access(username, resource)
            print(f"  {resource:<22} -> {result}")

        print()


if __name__ == "__main__":
    main()
