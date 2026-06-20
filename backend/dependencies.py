# backend/dependencies.py
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import jwt  # PyJWT

from . import config

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

_revoked_user_ids: set = set()

def revoke_user(uid: str):
    _revoked_user_ids.add(uid)

def create_access_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes or config.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        uid = payload.get("sub"); username = payload.get("username"); role = payload.get("role")
        if not (uid and username and role):
            raise HTTPException(status_code=401, detail="Invalid token payload")
        if uid in _revoked_user_ids:
            raise HTTPException(status_code=401, detail="Token has been revoked")
        return {"id": uid, "username": username, "role": role}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

def get_current_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if str(current_user.get("role","")).lower() != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user
