# app/routers/__init__.py
"""
Paquete de routers de la API
"""

from app.routers import auth
from app.routers import users
from app.routers import storage
from app.routers import tasks
from app.routers import debug
from app.routers import webauthn  # <-- Agregar esto

__all__ = [
    "auth",
    "users",
    "storage",
    "tasks",
    "debug",
    "webauthn",  # <-- Agregar esto
]