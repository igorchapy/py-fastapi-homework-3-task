from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

# Write your code here
load_dotenv()


@router.post(
    "/register/",
    response_model=schemas.UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: schemas.UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await crud.get_user_by_email(db=db, email=user.email)

    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists.",
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
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=schemas.MessageResponseSchema)
async def activation_account(
    activation_message: schemas.UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await crud.get_user_by_email(db=db, email=activation_message.email)
    db_token = await crud.get_activation_token(db=db, token=activation_message.token)

    if db_token:
        expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)

    if (
        not db_user
        or not db_token
        or db_token.user_id != db_user.id
        or datetime.now(timezone.utc) > expires_at
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    elif db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    try:
        db_user.is_active = True

        await crud.delete_activation_token(db=db, user_id=db_user.id)
        await db.commit()

        return {"message": "User account activated successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during activation.",
        )


@router.post("/password-reset/request/", response_model=schemas.MessageResponseSchema)
async def password_reset_request(
    email: schemas.PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await crud.get_user_by_email(db=db, email=email.email)

    if not db_user or not db_user.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }
    try:
        await crud.delete_reset_password_tokens(db=db, user_id=db_user.id)
        await crud.create_reset_password_token(db=db, user_id=db_user.id)
        await db.commit()

        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password reset request.",
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
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    if db_token:
        expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)

    if (
        not db_token
        or db_user.id != db_token.user_id
        or expires_at <= datetime.now(timezone.utc)
    ):
        await crud.delete_reset_password_tokens(db=db, user_id=db_user.id)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        db_user.password = reset_complete_request.password
        await crud.delete_reset_password_tokens(db=db, user_id=db_user.id)
        await db.commit()
        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=schemas.UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
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
            detail="Invalid email or password.",
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
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
            detail="An error occurred while processing the request.",
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
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    db_refresh_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token.refresh_token
        )
    )

    if not db_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    db_user = await crud.get_user_by_id(db=db, user_id=payload["user_id"])

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )
    elif db_user.id != db_refresh_token.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    access_token = jwt_manager.create_access_token(
        data={"email": db_user.email, "user_id": db_user.id}
    )

    return {"access_token": access_token}
