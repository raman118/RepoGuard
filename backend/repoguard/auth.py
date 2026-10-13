from collections.abc import Iterator
from dataclasses import dataclass
from hashlib import sha256
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from repoguard.models import Credential

bearer = HTTPBearer(auto_error=False)


def token_digest(token: str) -> str:
    return sha256(token.encode()).hexdigest()


def session(request: Request) -> Iterator[Session]:
    with request.app.state.sessions() as db:
        yield db


DB = Annotated[Session, Depends(session)]


@dataclass(frozen=True)
class Identity:
    tenant_id: str
    actor: str


def authenticate(
    db: DB,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Identity:
    if credentials is None or len(credentials.credentials) > 256:
        raise HTTPException(401, "authentication required")
    credential = db.get(Credential, token_digest(credentials.credentials))
    if credential is None or not credential.active:
        raise HTTPException(401, "invalid credential")
    return Identity(credential.tenant_id, credential.actor)


Actor = Annotated[Identity, Depends(authenticate)]
