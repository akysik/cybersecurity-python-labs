
import json
import logging
import sqlite3

from labs.lab03.database import BASE_DIR, get_connection, initialize_database

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SEED_FILE = BASE_DIR / "data" / "seed.json"


def seed_data() -> None:
    initialize_database()
    if not SEED_FILE.exists():
        logger.error("Файл початкових даних не знайдено: %s", SEED_FILE)
        return

    data = json.loads(SEED_FILE.read_text(encoding="utf-8"))

    with get_connection() as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] > 0:
            logger.info("База вже містить дані. Заповнення скасовано.")
            return

        try:
            for cat in data["categories"]:
                conn.execute(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    (cat["id"], cat["name"]),
                )

            for rec in data["records"]:
                conn.execute(
                    "INSERT INTO records (code, title, category_id, value, status) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        rec["code"],
                        rec["title"],
                        rec["category_id"],
                        rec["value"],
                        rec["status"],
                    ),
                )
            logger.info("Базу успішно заповнено початковими даними.")
        except sqlite3.IntegrityError as e:
            logger.error("Помилка цілісності при заповненні: %s", e)
            raise


if __name__ == "__main__":
    seed_data()