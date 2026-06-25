# app/routers/__init__.py
from app.routers import auth
from app.routers import users
from app.routers import storage
from app.routers import tasks
from app.routers import debug
from app.routers import webauthn
from app.routers import backup
from app.routers import sessions  # ✅ DEBE ESTAR PRESENTE

__all__ = [
    "auth",
    "users",
    "storage",
    "tasks",
    "debug",
    "webauthn",
    "backup",
    "sessions",  # ✅ DEBE ESTAR PRESENTE
]