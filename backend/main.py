import base64
import binascii
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
import psycopg
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, Field

DB_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
if len(JWT_SECRET.encode()) < 32:
    raise RuntimeError("JWT_SECRET doit contenir au moins 32 octets")

hasher = PasswordHasher()
dummy_hash = hasher.hash(os.urandom(32))
bearer = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    with psycopg.connect(DB_URL) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS vaults (
                user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                salt BYTEA NOT NULL,
                payload BYTEA NOT NULL,
                version BIGINT NOT NULL DEFAULT 1
            )
        """)
    yield


app = FastAPI(title="Password Vault", lifespan=lifespan)


class Credentials(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,64}$")
    password: str = Field(min_length=12, max_length=256)


class Register(Credentials):
    salt: str = Field(max_length=24)
    payload: str = Field(max_length=1_400_000)


class SaveVault(BaseModel):
    version: int = Field(ge=1)
    payload: str = Field(max_length=1_400_000)


def decode(value: str, minimum: int, maximum: int) -> bytes:
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise HTTPException(422, "Base64 invalide")
    if not minimum <= len(data) <= maximum:
        raise HTTPException(422, "Taille invalide")
    return data


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def user_id(
    auth: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> int:
    try:
        if auth is None:
            raise ValueError()
        claims = jwt.decode(
            auth.credentials, JWT_SECRET, algorithms=["HS256"],
            options={"require": ["sub", "exp"]},
        )
        return int(claims["sub"])
    except (ValueError, jwt.InvalidTokenError):
        raise HTTPException(401, "Session absente ou expirée")


UserId = Annotated[int, Depends(user_id)]


@app.middleware("http")
async def no_cache(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/register", status_code=201)
def register(body: Register):
    salt = decode(body.salt, 16, 16)
    payload = decode(body.payload, 40, 1_048_576)
    password_hash = hasher.hash(body.password)
    try:
        with psycopg.connect(DB_URL) as db:
            uid = db.execute(
                "INSERT INTO users(username,password_hash) VALUES (%s,%s) RETURNING id",
                (body.username.lower(), password_hash),
            ).fetchone()[0]
            db.execute(
                "INSERT INTO vaults(user_id,salt,payload) VALUES (%s,%s,%s)",
                (uid, salt, payload),
            )
    except UniqueViolation:
        raise HTTPException(409, "Nom de compte indisponible")
    return {"created": True}


@app.post("/api/login")
def login(body: Credentials):
    with psycopg.connect(DB_URL) as db:
        row = db.execute(
            "SELECT id,password_hash FROM users WHERE username=%s",
            (body.username.lower(),),
        ).fetchone()
    try:
        hasher.verify(row[1] if row else dummy_hash, body.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Identifiants incorrects")
    if not row:
        raise HTTPException(401, "Identifiants incorrects")
    token = jwt.encode(
        {"sub": str(row[0]), "exp": datetime.now(timezone.utc) + timedelta(minutes=30)},
        JWT_SECRET, algorithm="HS256",
    )
    return {"token": token}


@app.get("/api/vault")
def read_vault(uid: UserId):
    with psycopg.connect(DB_URL) as db:
        row = db.execute(
            "SELECT salt,payload,version FROM vaults WHERE user_id=%s", (uid,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Coffre introuvable")
    return {"salt": encode(row[0]), "payload": encode(row[1]), "version": row[2]}


@app.put("/api/vault")
def save_vault(body: SaveVault, uid: UserId):
    payload = decode(body.payload, 40, 1_048_576)
    with psycopg.connect(DB_URL) as db:
        row = db.execute(
            """UPDATE vaults SET payload=%s, version=version+1
               WHERE user_id=%s AND version=%s RETURNING version""",
            (payload, uid, body.version),
        ).fetchone()
    if not row:
        raise HTTPException(409, "Coffre modifié ailleurs. Recharge-le avant de réessayer.")
    return {"version": row[0]}