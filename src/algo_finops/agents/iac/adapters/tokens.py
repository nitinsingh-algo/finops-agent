from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from algo_finops.agents.iac.domain import GitHubEvent, TokenResolutionError
from algo_finops.config import Settings
from algo_finops.persistence.models import Installation

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"


class FernetCipher:
    def __init__(self, key: str) -> None:
        if not key:
            raise TokenResolutionError("IAC_TOKEN_ENCRYPTION_KEY is not configured")
        self._fernet = Fernet(key.encode("utf-8") if isinstance(key, str) else key)

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise TokenResolutionError("Stored installation token cannot be decrypted") from exc


class GithubTokenStore:
    """Resolves a clone token without putting it in LangGraph state.

    Order: GitHub App installation token → stored installation secret → IAC_GITHUB_TOKEN.
    """

    def __init__(
        self,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
        cipher: FernetCipher | None = None,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings
        self._sessions = session_factory
        self._cipher = cipher
        self._http = http
        self._cache: dict[str, str] = {}

    async def resolve(self, event: GitHubEvent) -> str:
        cache_key = str(event.installation_id or event.repo_full_name)
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        token = await self._resolve(event)
        self._cache[cache_key] = token
        return token

    async def _resolve(self, event: GitHubEvent) -> str:
        if self._settings.github_app_id and self._settings.github_app_private_key:
            if event.installation_id is None:
                raise TokenResolutionError("GitHub App is configured but the event has no installation id")
            return await self._mint_installation_token(event.installation_id)

        stored = await self._load_stored_token(event.installation_id)
        if stored:
            return stored

        if self._settings.github_token:
            logger.debug("Using development GITHUB_TOKEN for %s", event.repo_full_name)
            return self._settings.github_token

        raise TokenResolutionError(
            "No GitHub credential available. Configure a GitHub App, store an installation token, or set IAC_GITHUB_TOKEN."
        )

    async def upsert(self, installation_id: int, token: str, *, account_login: str = "", expires_at: datetime | None = None) -> None:
        cipher = self._require_cipher()
        async with self._sessions() as session:
            row = await session.get(Installation, installation_id)
            if row is None:
                session.add(
                    Installation(
                        installation_id=installation_id,
                        account_login=account_login,
                        encrypted_token=cipher.encrypt(token),
                        token_expires_at=expires_at,
                    )
                )
            else:
                row.account_login = account_login or row.account_login
                row.encrypted_token = cipher.encrypt(token)
                row.token_expires_at = expires_at
            await session.commit()

    async def _load_stored_token(self, installation_id: int | None) -> str | None:
        if installation_id is None or self._cipher is None:
            return None
        async with self._sessions() as session:
            row = await session.get(Installation, installation_id)
            if row is None:
                return None
            if row.token_expires_at and row.token_expires_at <= datetime.now(timezone.utc):
                return None
            return self._cipher.decrypt(row.encrypted_token)

    async def _mint_installation_token(self, installation_id: int) -> str:
        jwt_token = self._app_jwt()
        client = self._http or httpx.AsyncClient(timeout=20.0)
        owns_client = self._http is None
        try:
            response = await client.post(
                f"{_GITHUB_API}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {jwt_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if response.status_code >= 400:
                raise TokenResolutionError(f"GitHub App token mint failed ({response.status_code})")
            payload: dict[str, Any] = response.json()
        finally:
            if owns_client:
                await client.aclose()

        token = payload.get("token")
        if not token:
            raise TokenResolutionError("GitHub App token response did not include a token")
        expires_at = _parse_github_expiry(payload.get("expires_at"))
        if self._cipher is not None:
            await self.upsert(installation_id, token, expires_at=expires_at)
        return token

    def _app_jwt(self) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "iat": int(now.timestamp()) - 60,
            "exp": int((now + timedelta(minutes=9)).timestamp()),
            "iss": self._settings.github_app_id,
        }
        return jwt.encode(payload, self._settings.github_app_private_key, algorithm="RS256")

    def _require_cipher(self) -> FernetCipher:
        if self._cipher is None:
            raise TokenResolutionError("IAC_TOKEN_ENCRYPTION_KEY is not configured")
        return self._cipher


def _parse_github_expiry(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


async def load_installation(session: AsyncSession, installation_id: int) -> Installation | None:
    result = await session.execute(select(Installation).where(Installation.installation_id == installation_id))
    return result.scalar_one_or_none()
