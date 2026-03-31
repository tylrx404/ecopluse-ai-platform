from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class UserCreate(BaseModel):
    email: str
    password: str
    city: str
    state: str
    lat: float
    lon: float
    role: str = "user"

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    city: str
    state: str
    lat: float
    lon: float
    role: str
    created_at: datetime

    class Config:
        from_attributes = True

class LoginResponse(BaseModel):
    message: str
    user: dict

class DailyInputCreate(BaseModel):
    date: str
    timestamp: str
    ac_fan_hours: float
    water_usage: float
    transport_mode: str
    outdoor_exposure: str
    waste_segregation: bool

class DailyInputResponse(DailyInputCreate):
    id: int
    user_id: str

    class Config:
        from_attributes = True

class EcoScoreModel(BaseModel):
    water_credit: float = 0.0
    energy_credit: float = 0.0
    transport_credit: float = 0.0
    waste_credit: float = 0.0
    total_score: float = 0.0
    debt: float = 0.0

    class Config:
        from_attributes = True

class BadgeModel(BaseModel):
    badge_id: str
    earned: bool

    class Config:
        from_attributes = True

class WasteDecisionModel(BaseModel):
    item_name: str
    chosen_bin: str
    correct_bin: str
    timestamp: str

    class Config:
        from_attributes = True

class DailyGreenIndexModel(BaseModel):
    date: str
    score: float
    trend: str = "stable"

    class Config:
        from_attributes = True
