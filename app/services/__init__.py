# app/services/__init__.py
"""
Paquete de servicios para la API
"""

from app.services.email_service import EmailService, email_service
from app.services.supabase_auth_service import SupabaseAuthService, supabase_auth
from app.services.supabase_service import SupabaseStorageService, supabase_storage

__all__ = [
    "EmailService",
    "email_service",
    "SupabaseAuthService",
    "supabase_auth",
    "SupabaseStorageService",
    "supabase_storage",
]