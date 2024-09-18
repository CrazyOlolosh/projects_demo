import datetime
import time
import uuid
from typing import Annotated

from dependencies import role_checker
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.security import OAuth2PasswordRequestForm
from project_lib_api.routers.auth.auth import Auth, TokenManager
from project_lib_utils.exceptions.auth import (
    BaseUserException,
    UserNotFoundException,
    WrongPasswordException,
)
from project_lib_utils.helpers.base_auth import PasswordManager
from project_lib_utils.helpers.ldap_auth import LDAPAuth
from project_lib_utils.services_layer.events import EventServices
from project_lib_utils.settings.config import settings
from project_lib_utils.transport_data_types import User
from routers.auth import schemas
from routers.auth.exceptions import (
    CredentialException,
    EmailExistException,
    IncorrectUsernameException,
    InvalidSymbolException,
    OftenPasswordChangeException,
    OldPasswordException,
    UserExistException,
    WeakPasswordException,
)
from routers.auth.services import UserServices
from routers.sessions import schemas as session_schemas
from routers.sessions.services import SessionServices

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    responses={
        401: {"description": "Unauthorized"},
    },
)


@router.post(
    "/create",
    summary="Create an user",
    response_model=dict[str, str],
)
def create_user(
    name: Annotated[str, Query(..., description="User full name")],
    role: Annotated[schemas.Roles, Query(..., description="User role")],
    username: Annotated[
        str,
        Query(
            min_length=3,
            description="User login, minimum 3 characters, starts with "
            "letters, can contain digits and underscores",
        ),
    ],
    email: Annotated[str, Query(..., description="User email")],
    request: Request,
    password: Annotated[
        str | None,
        Query(
            min_length=settings.PASSWORD_MIN_LENGTH,
            description=f"User password(minimum {settings.PASSWORD_MIN_LENGTH} characters,"
            f" {settings.PASSWORD_LOWERCASE} lowercase,"
            f" {settings.PASSWORD_UPPERCASE} uppercase,"
            f" {settings.PASSWORD_DIGIT} number,"
            f" {settings.PASSWORD_SPECIAL} special({settings.PASSWORD_VALID_SPECIAL})",
        ),
    ] = None,
    _: bool = Depends(role_checker(required_roles={"admin"})),
):
    is_exist_user = UserServices.get_user_from_db(username=username, email=email)

    if is_exist_user:
        EventServices.user_creation(
            user_id=None,
            result="failure",
            ip_address=request.client.host if request.client else None,
            additional_info=UserExistException().detail,
        )
        raise UserExistException

    if not Auth.validate_username(username):
        EventServices.user_creation(
            user_id=None,
            result="failure",
            ip_address=request.client.host if request.client else None,
            additional_info=IncorrectUsernameException().detail,
        )
        raise IncorrectUsernameException

    if password and not PasswordManager.validate_password(password):
        if any(s in settings.PASSWORD_INVALID_SPECIAL for s in password):
            EventServices.user_creation(
                user_id=None,
                result="failure",
                ip_address=request.client.host if request.client else None,
                additional_info=InvalidSymbolException(
                    exception_reason="password",
                ).detail,
            )
            raise InvalidSymbolException(exception_reason="password")
        EventServices.user_creation(
            user_id=None,
            result="failure",
            ip_address=request.client.host if request.client else None,
            additional_info=WeakPasswordException().detail,
        )
        raise WeakPasswordException

    user_password = password if password else PasswordManager.generate_password()

    new_user = User(
        user_id=uuid.uuid4(),
        name=name,
        role=role,
        username=username,
        email=email,
        password=PasswordManager.hash_password(user_password),
        password_update=int(time.time()),
        is_locked=False,
        failed_logins=0,
        is_generated_password=True,
        is_disabled=False,
        last_login=int(time.time()),
    )
    UserServices.create_new_user(user=new_user)
    EventServices.user_creation(
        user_id=new_user.user_id,
        result="success",
        ip_address=request.client.host if request.client else None,
    )
    UserServices.add_password_history(
        schemas.PasswordHistory(
            passwords_history_id=uuid.uuid4(),
            username=new_user.username,
            password=new_user.password,
            password_update=new_user.password_update,
        ),
    )

    return {"username": username, "password": user_password}


@router.post(
    "/login",
    summary="Login",
    response_model=schemas.Tokens,
)
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], request: Request):
    try:
        user = Auth.is_authenticate_user(
            form_data.username,
            form_data.password,
            request.client.host if request.client else None,
        )

        if not user:
            raise CredentialException
        tokens = TokenManager.create_tokens_for_login(
            username=form_data.username,
            auth_type=schemas.TokenAuthTypes.base,
            user_role=user.role,
        )

        data = session_schemas.BaseSessionInfo(
            session_id=uuid.uuid4(),
            username=user.username,
            token=tokens.refresh_token,
        )

        SessionServices.create_user_session(session_info=data)

        return tokens
    except BaseUserException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.post(
    "/ldap_login",
    summary="Login by LDAP",
    response_model=schemas.Tokens,
)
def ldap_login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    try:
        if user := LDAPAuth.connect_to_ldap(
            form_data.username,
            form_data.password,
        ):
            tokens = TokenManager.create_tokens_for_login(
                username=user.username,
                auth_type=schemas.TokenAuthTypes.ldap,
                user_role=user.role,
            )

            data = session_schemas.BaseSessionInfo(
                session_id=uuid.uuid4(),
                username=user.username,
                token=tokens.refresh_token,
            )

            SessionServices.create_user_session(session_info=data)

            return tokens
    except BaseUserException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.get("/user")
def get_all_users(
    _: bool = Depends(role_checker(required_roles={"admin", "auditor"})),  # noqa
):
    try:
        return UserServices.get_all_users()

    except BaseUserException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.get("/user/{username}")
def get_user_by_username(
    username: Annotated[
        str,
        Path(
            min_length=3,
            description="Username, minimum 3 characters, starts with "
            "letters, can contain digits and underscores",
        ),
    ],
    _: bool = Depends(role_checker(required_roles={"admin", "auditor"})),
):
    try:
        return UserServices.get_user_by_ref(reference={"username": username})

    except UserNotFoundException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.post(
    "/refresh",
    summary="Refresh token",
    response_model=schemas.AccessToken,
)
def token_refresh(refresh_token: Annotated[str, Query(...)]):
    token_data = TokenManager.decode_token(refresh_token)
    if token_data.type != schemas.TokenTypes.refresh:
        raise CredentialException

    return TokenManager.update_access_token(username=token_data.username)


@router.post("/change_password", summary="Change password for a logged user")
def change_password(
    old_password: Annotated[str, Query(...)],
    new_password: Annotated[str, Query(...)],
    current_user: Annotated[User, Depends(Auth.get_current_user_from_token)],
    request: Request,
):
    try:
        if not PasswordManager.verify_password(old_password, current_user.password):
            EventServices.password_change(
                user_id=current_user.user_id,
                result="failure",
                ip_address=request.client.host if request.client else None,
                additional_info=WrongPasswordException.detail,
            )
            # TODO: тут точно 401 ошибка при вводе неверного старого пароля, не 404?
            raise WrongPasswordException

        if not current_user.is_generated_password:
            if datetime.datetime.now() - datetime.datetime.fromtimestamp(
                current_user.password_update,
            ) < datetime.timedelta(days=settings.MIN_PASSWORD_LIFETIME):
                EventServices.password_change(
                    user_id=current_user.user_id,
                    result="failure",
                    ip_address=request.client.host if request.client else None,
                    additional_info=OftenPasswordChangeException(
                        min_password_lifetime=settings.MIN_PASSWORD_LIFETIME,
                    ).detail,
                )
                raise OftenPasswordChangeException(
                    min_password_lifetime=settings.MIN_PASSWORD_LIFETIME,
                )

        if not PasswordManager.validate_password(new_password):
            EventServices.password_change(
                user_id=current_user.user_id,
                result="failure",
                ip_address=request.client.host if request.client else None,
                additional_info=WeakPasswordException().detail,
            )
            raise WeakPasswordException

        for old_hashed_password in UserServices.get_passwords_history(
            current_user.username,
        ):
            if PasswordManager.verify_password(new_password, old_hashed_password):
                EventServices.password_change(
                    user_id=current_user.user_id,
                    result="failure",
                    ip_address=request.client.host if request.client else None,
                    additional_info=OldPasswordException().detail,
                )
                raise OldPasswordException

        hashed_password = PasswordManager.hash_password(new_password)

        UserServices.change_user_password(
            current_user.user_id,
            hashed_password,
            is_generated_password=False,
        )
        UserServices.add_password_history(
            schemas.PasswordHistory(
                passwords_history_id=uuid.uuid4(),
                username=current_user.username,
                password=hashed_password,
                password_update=int(time.time()),
            ),
        )

        EventServices.password_change(
            user_id=current_user.user_id,
            result="success",
            ip_address=request.client.host if request.client else None,
        )

        return {"200": "Password changed"}

    except BaseUserException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.post("/reset_password", summary="Reset password without login in")
def reset_password(
    username: Annotated[str, Query(...)],
    request: Request,
    _: bool = Depends(role_checker(required_roles={"admin"})),
):
    try:
        user = UserServices.get_user_by_ref(reference={"username": username})

        if user is None:
            EventServices.password_change(
                user_id=None,
                result="failure",
                ip_address=request.client.host if request.client else None,
                additional_info=UserNotFoundException.detail
                + f" Username: {username}.",
            )
            raise UserNotFoundException

        new_password = PasswordManager.generate_password()

        UserServices.change_user_password(
            user.user_id,
            PasswordManager.hash_password(new_password),
            is_generated_password=True,
        )

        EventServices.password_change(
            user_id=user.user_id,
            result="success",
            ip_address=request.client.host if request.client else None,
        )

        return new_password

    except BaseUserException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.post("/lock_user", summary="User locking/unlocking by admin")
def lock_user(
    username: Annotated[str, Query(...)],
    is_locked: Annotated[bool, Query(...)],
    request: Request,
    _: bool = Depends(role_checker(required_roles={"admin"})),
):
    try:
        user = UserServices.get_user_by_ref(reference={"username": username})

        if user is None:
            EventServices.account_lock(
                user_id=None,
                result="failure",
                ip_address=request.client.host if request.client else None,
                additional_info=UserNotFoundException.detail
                + f" Username: {username}.",
            )
            raise UserNotFoundException

        Auth.lock_user(user.user_id, is_locked)
        EventServices.account_lock(
            user_id=user.user_id,
            result="success",
            ip_address=request.client.host if request.client else None,
        )
        return f"Lock is {is_locked} for user {username}"
    except BaseUserException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.post("/change_email", summary="Change user email by username")
def change_email(
    username: Annotated[str, Query(...)],
    new_email: Annotated[str, Query(...)],
    request: Request,
    _: bool = Depends(role_checker(required_roles={"admin"})),
):
    try:
        user = UserServices.get_user_by_ref(reference={"username": username})

        if user is None:
            EventServices.account_change(
                user_id=None,
                result="failure",
                ip_address=request.client.host if request.client else None,
                additional_info=UserNotFoundException.detail
                + f" Username: {username}.",
            )
            raise UserNotFoundException

        email_user = UserServices.get_user_by_ref(reference={"email": new_email})

        if email_user is not None:
            EventServices.account_change(
                user_id=None,
                result="failure",
                ip_address=request.client.host if request.client else None,
                additional_info=EmailExistException().detail + f" Email: {new_email}.",
            )
            raise EmailExistException

        old_email = user.email
        UserServices.update_email(user.user_id, new_email)
        EventServices.account_change(
            user_id=user.user_id,
            result="success",
            ip_address=request.client.host if request.client else None,
        )
        return f"Email for user {username} changed from {old_email} to {new_email}."

    except BaseUserException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.post("/change_role/{username}", summary="Change user role")
def change_role(
    username: Annotated[str, Path(description="Username")],
    role: Annotated[schemas.Roles, Query(..., description="New role")],
    request: Request,
    _: bool = Depends(role_checker(required_roles={"admin"})),
):  # TODO: нужно что-то возвращать типо ОК или еще что-то
    try:
        user = UserServices.get_user_by_ref(reference={"username": username})

        if user is None:
            EventServices.account_role_change(
                user_id=None,
                result="failure",
                ip_address=request.client.host if request.client else None,
                additional_info=UserNotFoundException.detail
                + f" Username: {username}.",
            )
            raise UserNotFoundException

        UserServices.change_user_role(user.user_id, role)
        EventServices.account_role_change(
            user_id=user.user_id,
            result="success",
            ip_address=request.client.host if request.client else None,
        )

    except BaseUserException as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.detail,
        )


@router.delete(
    "/user",
    summary="User deactivation",
    description="User activation/deactivation by admin",
)
def deactivate_user(
    username: Annotated[str, Query(...)],
    is_disabled: Annotated[bool, Query(...)],
    request: Request,
    _: bool = Depends(role_checker(required_roles={"admin"})),
):
    user = UserServices.get_user_by_ref(reference={"username": username})

    if user is None:
        EventServices.account_deactivation(
            user_id=None,
            result="failure",
            ip_address=request.client.host if request.client else None,
            additional_info=UserNotFoundException().detail + f" Username: {username}.",
        )
        raise UserNotFoundException

    Auth.disable_user(user.user_id, is_disabled)
    EventServices.account_deactivation(
        user_id=user.user_id,
        result="success",
        ip_address=request.client.host if request.client else None,
    )
