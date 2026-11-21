"""Функції доступу до бази даних (SQL-запити)."""

import sqlite3
from contextlib import closing

from labs.lab03.database import get_connection


def get_categories():
    with closing(get_connection()) as conn:
        rows = conn.execute("SELECT id, name FROM categories ORDER BY id").fetchall()
        return [dict(row) for row in rows]


def create_category(name: str):
    with closing(get_connection()) as conn:
        cursor = conn.execute("INSERT INTO categories (name) VALUES (?)", (name,))
        return {"id": cursor.lastrowid, "name": name}


def delete_category(category_id: int):
    with closing(get_connection()) as conn:
        # Перевіряємо, чи немає записів у категорії
        count = conn.execute(
            "SELECT COUNT(*) FROM records WHERE category_id = ?", (category_id,)
        ).fetchone()[0]
        if count > 0:
            raise sqlite3.IntegrityError("Category is not empty")
        cursor = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        if cursor.rowcount == 0:
            raise KeyError("Category not found")


def get_record(record_id: int):
    with closing(get_connection()) as conn:
        row = conn.execute(
            """
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name as category_name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id = ?
            """,
            (record_id,),
        ).fetchone()
        return dict(row) if row else None


def get_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
):
    query = """
        SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name as category_name
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE 1=1
    """
    params = []

    if category_id is not None:
        query += " AND r.category_id = ?"
        params.append(category_id)
    if status is not None:
        query += " AND r.status = ?"
        params.append(status)
    if min_value is not None:
        query += " AND r.value >= ?"
        params.append(min_value)
    if q is not None:
        query += " AND r.title LIKE ?"
        params.append(f"%{q}%")

    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(row) for row in rows]


def create_record(data: dict):
    with closing(get_connection()) as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                (data["code"], data["title"], data["category_id"], data["value"], data["status"]),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError as e:
            if "FOREIGN KEY" in str(e):
                raise KeyError("Category not found")
            raise
    return get_record(record_id)


def update_record(record_id: int, data: dict):
    with closing(get_connection()) as conn:
        try:
            cursor = conn.execute(
                "UPDATE records SET code=?, title=?, category_id=?, value=?, status=? WHERE id=?",
                (data["code"], data["title"], data["category_id"], data["value"], data["status"], record_id),
            )
            if cursor.rowcount == 0:
                raise KeyError("Record not found")
        except sqlite3.IntegrityError as e:
            if "FOREIGN KEY" in str(e):
                raise KeyError("Category not found")
            raise
    return get_record(record_id)


def delete_record(record_id: int):
    with closing(get_connection()) as conn:
        cursor = conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise KeyError("Record not found")


def create_records_bulk(records_data: list[dict]):
    with closing(get_connection()) as conn:
        try:
            # Контекстний менеджер with conn автоматично зробить commit, якщо не буде помилок,
            # і rollback, якщо буде виняток.
            created_ids = []
            for data in records_data:
                cursor = conn.execute(
                    "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                    (data["code"], data["title"], data["category_id"], data["value"], data["status"]),
                )
                created_ids.append(cursor.lastrowid)
        except sqlite3.IntegrityError as e:
            if "FOREIGN KEY" in str(e):
                raise KeyError("Category not found")
            raise  # sqlite3 автоматично скасує транзакцію (rollback)

    # Повертаємо створені записи (поза транзакцією)
    return [get_record(rid) for rid in created_ids]