from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, email: EmailStr):
        return accounts_validators.validate_email(str(email))

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str):
        return accounts_validators.validate_password_strength(password)


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class BaseMessageSchema(BaseModel):
    message: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseMessageSchema):
    pass


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, email: EmailStr):
        return accounts_validators.validate_email(str(email))


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, email: EmailStr):
        return accounts_validators.validate_email(str(email))

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str):
        return accounts_validators.validate_password_strength(password)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
