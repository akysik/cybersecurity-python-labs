from fastapi import APIRouter, HTTPException, status, Query
import sqlite3

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordReplace, RecordRead, StatusType

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=list[RecordRead])
def list_records(
    category_id: int | None = Query(None, gt=0),
    status: StatusType | None = None,
    min_value: float | None = None,
    q: str | None = Query(None, min_length=1, max_length=120),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return repository.get_records(category_id, status, min_value, q, limit, offset)


@router.get("/{record_id}", response_model=RecordRead)
def get_record(record_id: int):
    record = repository.get_record(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    return record


@router.post("", response_model=RecordRead, status_code=status.HTTP_201_CREATED)
def create_record(record: RecordCreate):
    try:
        return repository.create_record(record.model_dump())
    except KeyError:
        raise HTTPException(status_code=404, detail="Category not found")
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Record code already exists")


@router.put("/{record_id}", response_model=RecordRead)
def update_record(record_id: int, record: RecordReplace):
    try:
        return repository.update_record(record_id, record.model_dump())
    except KeyError as e:
        if str(e) == "'Record not found'":
            raise HTTPException(status_code=404, detail="Record not found")
        raise HTTPException(status_code=404, detail="Category not found")
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Record code already exists")


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int):
    try:
        repository.delete_record(record_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Record not found")


@router.post("/bulk", response_model=list[RecordRead], status_code=status.HTTP_201_CREATED)
def create_records_bulk(records: list[RecordCreate]):
    if not (1 <= len(records) <= 100):
        raise HTTPException(status_code=422, detail="Bulk must contain 1 to 100 records")
    try:
        return repository.create_records_bulk([r.model_dump() for r in records])
    except KeyError:
        raise HTTPException(status_code=404, detail="Category not found in one of the records")
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Conflict: duplicate code in request or DB")