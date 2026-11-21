"""Pydantic-моделі для валідації даних."""

from typing import Literal
from pydantic import BaseModel, Field, ConfigDict

StatusType = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=2, max_length=40)


class CategoryRead(BaseModel):
    id: int
    name: str


class RecordCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(..., min_length=3, max_length=40)
    title: str = Field(..., min_length=3, max_length=120)
    category_id: int = Field(..., gt=0)
    value: int = Field(..., ge=0)  # Для варіанта 6 тип INTEGER
    status: StatusType


class RecordReplace(RecordCreate):
    pass


class RecordRead(BaseModel):
    id: int
    code: str
    title: str
    category_id: int
    value: int
    status: str
    category_name: str