import logging
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth import (ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token,
                  get_current_user, get_password_hash, verify_password)
from database import get_db
from models import EcoScore as DBEcoScore
from models import User as DBUser
from schemas import LoginResponse, UserCreate, UserLogin, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=UserResponse)
def signup(user: UserCreate, response: Response, db: Session = Depends(get_db)):
    # ── Step 1: Check if email already exists ──────────────────────────────
    logger.info(f"🔍 Checking if email exists: {user.email}")
    try:
        existing_user = db.query(DBUser).filter(DBUser.email == user.email).first()
    except Exception as e:
        logger.error(f"❌ DB error during email check for {user.email}: {e}")
        raise HTTPException(status_code=500, detail="Database error during registration")

    if existing_user:
        logger.warning(f"⚠️  Email already registered: {user.email}")
        raise HTTPException(status_code=400, detail="Email already registered")

    # ── Step 2: Create the new user ────────────────────────────────────────
    try:
        hashed_password = get_password_hash(user.password)
        user_id = str(uuid.uuid4())

        assigned_role = "user"
        if user.role == "admin" and "admin" in user.email.lower():
            assigned_role = "admin"

        new_user = DBUser(
            id=user_id,
            email=user.email,
            hashed_password=hashed_password,
            city=user.city,
            state=user.state,
            lat=user.lat,
            lon=user.lon,
            role=assigned_role,
        )
        db.add(new_user)

        # Initialize eco score record for the new user
        eco_score = DBEcoScore(
            user_id=user_id,
            score=0,   # or whatever default fields exist
        )
        db.add(eco_score)

        db.commit()
        db.refresh(new_user)
        logger.info(f"✅ User created successfully: {user.email}")

    except IntegrityError as e:
        db.rollback()
        logger.error(f"❌ IntegrityError (duplicate email) for {user.email}: {e}")
        raise HTTPException(status_code=400, detail="Email already registered")

    except Exception as e:
        db.rollback()
        logger.error(f"❌ REAL ERROR during signup for {user.email}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    # ── Step 3: Auto-login — set cookie ───────────────────────────────────
    access_token = create_access_token(
        data={"sub": new_user.id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False,
    )

    return new_user


@router.post("/login", response_model=LoginResponse)
def login(user_credentials: UserLogin, response: Response, db: Session = Depends(get_db)):
    logger.info(f"🔍 Login attempt for: {user_credentials.email}")
    try:
        user = db.query(DBUser).filter(DBUser.email == user_credentials.email).first()
    except Exception as e:
        logger.error(f"❌ DB error during login for {user_credentials.email}: {e}")
        raise HTTPException(status_code=500, detail="Database error during login")

    if not user or not verify_password(user_credentials.password, user.hashed_password):
        logger.warning(f"⚠️  Invalid credentials for: {user_credentials.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    access_token = create_access_token(
        data={"sub": user.id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False,
    )
    logger.info(f"✅ Login successful for: {user_credentials.email}")
    return {
        "message": "Logged in successfully",
        "user": {
            "id": user.id,
            "email": user.email,
            "city": user.city,
            "role": getattr(user, "role", "user"),
        },
    }


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: DBUser = Depends(get_current_user)):
    return current_user
