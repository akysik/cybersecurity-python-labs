from fastapi import APIRouter, HTTPException, status
import sqlite3

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Categories"])


@router.get("", response_model=list[CategoryRead])
def list_categories():
    return repository.get_categories()


@router.post("", response_model=CategoryRead, status_code=status.HTTP_201_CREATED)
def create_category(category: CategoryCreate):
    try:
        return repository.create_category(category.name)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Category name already exists")


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(category_id: int):
    try:
        repository.delete_category(category_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Category not found")
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Cannot delete non-empty category")