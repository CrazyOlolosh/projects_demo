from datetime import timedelta
from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from project_lib_utils.helpers.base_auth import (
    BaseAuth,
    BaseRoleChecker,
    BaseTokenManager,
)
from project_lib_utils.settings.config import settings
from project_lib_utils.transport_data_types import User
from routers.auth import schemas
from routers.auth.exceptions import (
    CredentialException,
    GeneratedPasswordException,
    RoleException,
    SessionNotFoundException,
)
from routers.auth.services import UserServices
from routers.sessions.services import SessionServices


def _get_oauth2_scheme() -> OAuth2PasswordBearer:
    if settings.LDAP_SERVER:
        return OAuth2PasswordBearer(tokenUrl="/auth/ldap_login")
    return OAuth2PasswordBearer(tokenUrl="/auth/login")


oauth2_scheme: OAuth2PasswordBearer = _get_oauth2_scheme()


class Auth(BaseAuth):
    """
    Authentication-related utilities for handling user validation and token-based authentication.

    This class extends `BaseAuth` and provides functionality to retrieve the current
    user based on authentication tokens. It supports different authentication methods,
    such as base authentication and LDAP, and integrates token validation and session
    management.
    """

    @staticmethod
    def get_current_user_from_token(
        token: Annotated[str, Depends(oauth2_scheme)],
    ) -> User | schemas.UserLDAP:
        """
        Retrieve the current user from the provided token.

        This method decodes the provided JWT token and extracts user data such as
        authentication type and username. It checks if the token is of type `access`
        and identifies the user either through base authentication or LDAP. After
        verifying the user's session, it returns the user object.

        Args:
            token (str): The JWT token containing user information.

        Returns:
            user (User | UserLDAP): The user object (either a base `User` or an LDAP user).

        Raises:
            CredentialException: If the token type is invalid or if the user is not found.
            SessionNotFoundException: If no active session for the user is found.
        """
        token_data = TokenManager.decode_token(token)
        token_type = token_data.type

        if token_type != schemas.TokenTypes.access:
            raise CredentialException

        auth_type = token_data.auth_type
        username: str = token_data.username

        if auth_type == schemas.TokenAuthTypes.base:
            user = UserServices.get_user_by_ref(reference={"username": username})

            if user is None or user.username != username:
                raise CredentialException
        elif auth_type == schemas.TokenAuthTypes.ldap:
            user = schemas.UserLDAP(
                username=username,
                role=token_data.role,
            )
        else:
            raise CredentialException

        session_info = SessionServices.get_user_sessions_by_filter(
            reference={"username": user.username},
        )

        if not session_info:
            raise SessionNotFoundException

        if user is None:
            raise CredentialException

        return user


class TokenManager(BaseTokenManager):
    """
    TokenManager is responsible for handling operations related to JWT tokens.

    This class extends the BaseTokenManager and provides methods to manage
    and decode JSON Web Tokens (JWT), such as extracting token data and
    validating token structures.

    Inherited from:
        BaseTokenManager
    """

    @staticmethod
    def decode_token(token: str) -> schemas.TokenData:
        """
        Decode a JWT token and extract user information.

        This method decodes a given JWT token using the configured secret key
        and algorithm, extracting relevant data such as the username, token type,
        authentication type, and user role. If any of these fields are missing or
        the token is invalid, a `CredentialException` is raised.

        Args:
            token (str): The JWT token to be decoded.

        Returns:
            TokenData: A dataclass containing the decoded token information
                               (username, token type, authentication type, and role).

        Raises:
            CredentialException: If the token is invalid or any required data is missing.
        """
        token_data: schemas.TokenData
        try:
            raw_token_data = jwt.decode(
                token,
                settings.SECRET_KEY,
                settings.ALGORITHM,
            )
            token_sub = raw_token_data.get("sub")
            token_type = raw_token_data.get("type")
            token_auth_type = raw_token_data.get("auth_type")
            token_role = raw_token_data.get("role")
            if (
                token_sub is None
                or token_type is None
                or token_auth_type is None
                or token_role is None
            ):
                raise CredentialException
            token_data = schemas.TokenData(
                username=token_sub,
                type=token_type,
                auth_type=token_auth_type,
                role=token_role,
            )
        except JWTError:
            raise CredentialException
        return token_data

    @classmethod
    def create_tokens_for_login(
        cls,
        username: str,
        user_role: str,
        auth_type: str,
    ) -> schemas.Tokens:
        """
        Create access and refresh tokens for a user upon login.

        This method generates an access token and a refresh token for a user
        based on their username, role, and authentication type. The tokens
        include user-specific data, token type, authentication type, and role.
        The expiration time for both tokens is determined by the application
        settings.

        Args:
            username (str): The username of the user.
            user_role (str): The role of the user (e.g., admin, user).
            auth_type (str): The type of authentication (e.g., base, ldap).

        Returns:
            Tokens: A dataclass containing the generated access and refresh tokens.
        """
        access_token = cls._create_token(
            data={
                "sub": username,
                "type": schemas.TokenTypes.access,
                "auth_type": auth_type,
                "role": user_role,
            },
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRES),
        )
        refresh_token = cls._create_token(
            data={
                "sub": username,
                "type": schemas.TokenTypes.refresh,
                "auth_type": auth_type,
                "role": user_role,
            },
            expires_delta=timedelta(minutes=settings.REFRESH_TOKEN_EXPIRES),
        )

        return schemas.Tokens(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    @classmethod
    def update_access_token(cls, username: str) -> schemas.AccessToken:
        """
        Update and generate a new access token for a user.

        This method retrieves the user by their username and generates a new
        access token with updated expiration time. The token includes user-specific
        data such as username, token type, authentication type, and user role.
        The expiration time is set according to the application settings.

        Args:
            username (str): The username of the user.

        Returns:
            AccessToken: A dataclass containing the new access token.
        """
        user = UserServices.get_user_by_ref(reference={"username": username})

        if user is None:
            raise CredentialException

        new_access_token = cls._create_token(
            data={
                "sub": username,
                "type": schemas.TokenTypes.access,
                "auth_type": schemas.TokenAuthTypes.base,
                "role": user.role,
            },
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRES),
        )

        return schemas.AccessToken(access_token=new_access_token)


class RoleChecker(BaseRoleChecker):
    """
    A role validation utility that checks if the current user has the required role(s).

    This class inherits from `BaseRoleChecker` and is responsible for verifying if the user,
    either a regular `User` or `UserLDAP`, has the necessary role to access a specific resource.
    If the user has a generated password or does not meet the role requirements,
    exceptions will be raised.

    Raises:
        GeneratedPasswordException: If the user is using a generated password.
        RoleException: If the user does not have the required role(s).
    """

    def __call__(
        self,
        user: User | schemas.UserLDAP = Depends(Auth.get_current_user_from_token),
    ) -> bool:
        """
        Perform the role check for the given user.

        This method checks if the user has the necessary role(s) to proceed. It raises an exception
        if the user is using a generated password (for `User` objects) or if the user's role is not
        in the required roles.

        Args:
            user (User | UserLDAP): The user object, either `User` or `UserLDAP`,
                                            retrieved from the authentication token.

        Returns:
            bool: True if the user passes the role check.

        Raises:
            GeneratedPasswordException: If the user is using a generated password (for `User`).
            RoleException: If the user does not have the required role(s).
        """
        if isinstance(user, User) and user.is_generated_password:
            raise GeneratedPasswordException

        if user.role not in self.required_roles:
            raise RoleException

        return True
