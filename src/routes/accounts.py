from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from dotenv import load_dotenv
from jwt import InvalidTokenError, ExpiredSignatureError as TokenExpiredError

from config import get_jwt_auth_manager
from database import (
    get_db,
    RefreshTokenModel,
)
from security.interfaces import JWTAuthManagerInterface

from app import schemas, crud


load_dotenv()

router = APIRouter()


@router.post(
    "/register/",
    response_model=schemas.UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: schemas.UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud.get_user_by_email(db=db, email=user.email)

    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Користувач з email {user.email} вже існує.",
        )

    try:
        new_user = await crud.create_user(db=db, user=user)
        await crud.create_activation_token(db=db, user_id=new_user.id)
        await db.commit()
        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Помилка під час створення користувача.",
        )


@router.post("/activate/", response_model=schemas.MessageResponseSchema)
async def activation_account(
    activation_message: schemas.UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud.get_user_by_email(db=db, email=activation_message.email)
    db_token = await crud.get_activation_token(db=db, token=activation_message.token)

    if not db_user or not db_token or db_token.user_id != db_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Невірний або прострочений токен.",
        )

    expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Токен прострочений.",
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Акаунт уже активований.",
        )

    try:
        db_user.is_active = True
        await crud.delete_activation_token(db=db, user_id=db_user.id)
        await db.commit()
        return {"message": "Акаунт успішно активовано."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Помилка під час активації акаунта.",
        )


@router.post("/password-reset/request/", response_model=schemas.MessageResponseSchema)
async def password_reset_request(
    email: schemas.PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud.get_user_by_email(db=db, email=email.email)

    if not db_user or not db_user.is_active:
        return {
            "message": "Якщо користувач існує, ви отримаєте інструкції на email."
        }

    try:
        await crud.delete_reset_password_tokens(db=db, user_id=db_user.id)
        await crud.create_reset_password_token(db=db, user_id=db_user.id)
        await db.commit()

        return {
            "message": "Якщо користувач існує, ви отримаєте інструкції на email."
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Помилка запиту на відновлення пароля.",
        )


@router.post("/reset-password/complete/", response_model=schemas.MessageResponseSchema)
async def reset_password_complete(
    reset_complete_request: schemas.PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud.get_user_by_email(db=db, email=reset_complete_request.email)
    db_token = await crud.get_reset_password_token(
        db=db, token=reset_complete_request.token
    )

    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Невірний email або токен.",
        )

    if not db_token or db_user.id != db_token.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Невірний email або токен.",
        )

    expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        await crud.delete_reset_password_tokens(db=db, user_id=db_user.id)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Токен прострочений.",
        )

    try:
        db_user.set_password(reset_complete_request.password)
        await crud.delete_reset_password_tokens(db=db, user_id=db_user.id)
        await db.commit()
        return {"message": "Пароль успішно змінено."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Помилка зміни пароля.",
        )


@router.post(
    "/login/",
    response_model=schemas.UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def user_login(
    login_data: schemas.UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    db_user = await crud.get_user_by_email(db=db, email=login_data.email)

    if not db_user or not db_user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невірний email або пароль.",
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Акаунт не активований.",
        )

    try:
        access_token = jwt_manager.create_access_token(
            data={"email": db_user.email, "user_id": db_user.id}
        )

        refresh_token = jwt_manager.create_refresh_token(
            data={"email": db_user.email, "user_id": db_user.id}
        )

        payload_refresh_token = jwt_manager.decode_refresh_token(refresh_token)

        db_refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            token=refresh_token,
            days_valid=payload_refresh_token["exp"] // (60 * 24),
        )

        db.add(db_refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Помилка входу в систему.",
        )


@router.post("/refresh/", response_model=schemas.TokenRefreshResponseSchema)
async def refresh_access_token(
    refresh_token: schemas.TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except (InvalidTokenError, TokenExpiredError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Токен недійсний або прострочений.",
        )

    db_refresh_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token.refresh_token
        )
    )

    if not db_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh-токен не знайдено.",
        )

    db_user = await crud.get_user_by_id(db=db, user_id=payload["user_id"])

    if not db_user or db_user.id != db_refresh_token.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Користувач не знайдений.",
        )

    access_token = jwt_manager.create_access_token(
        data={"email": db_user.email, "user_id": db_user.id}
    )

    return {"access_token": access_token}
