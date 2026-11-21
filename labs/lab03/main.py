import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import VARIANT_NUMBER

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Mail Security Events API",
    description="Сервіс обліку подій поштової безпеки (Варіант 6). "
    "Одиниця вимірювання: кількість виявлених подій (INTEGER). "
    "Поріг: 10.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", tags=["System"])
def ping():
    return {"status": "ok"}


@app.get("/student", tags=["System"])
def get_student():
    return {
        "student_name": "Зічнук Артур Вікторович",
        "group_name": "КБ-204",
        "variant_number": VARIANT_NUMBER,
    }