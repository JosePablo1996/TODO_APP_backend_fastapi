# app/config.py
import os
import json
import socket
from typing import Optional, List
from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from pydantic import ConfigDict, field_validator
import logging

# Cargar variables de entorno desde .env
load_dotenv()

# Configurar logging
logger = logging.getLogger(__name__)


def get_local_ip():
    """Obtiene la IP local de la máquina automáticamente"""
    try:
        # Conectar a un servidor externo para obtener la IP real
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip
    except Exception:
        return '127.0.0.1'


class Settings(BaseSettings):
    """Configuración de la aplicación usando Pydantic Settings"""
    
    # ============================================
    # SUPABASE AUTH CONFIGURATION (PRINCIPAL)
    # ============================================
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_SERVICE_KEY: str = os.getenv("SUPABASE_SERVICE_KEY", "")
    SUPABASE_ANON_KEY: str = os.getenv("SUPABASE_ANON_KEY", "")

    # ============================================
    # KEYCLOAK (DEPRECATED - Se mantiene solo por compatibilidad)
    # ============================================
    KEYCLOAK_URL: Optional[str] = os.getenv("KEYCLOAK_URL")
    KEYCLOAK_ADMIN_USERNAME: Optional[str] = os.getenv("KEYCLOAK_ADMIN_USERNAME")
    KEYCLOAK_ADMIN_PASSWORD: Optional[str] = os.getenv("KEYCLOAK_ADMIN_PASSWORD")
    REALM: Optional[str] = os.getenv("REALM")
    KEYCLOAK_CLIENT_ID: Optional[str] = os.getenv("KEYCLOAK_CLIENT_ID")
    KEYCLOAK_CLIENT_SECRET: Optional[str] = os.getenv("KEYCLOAK_CLIENT_SECRET")

    # ============================================
    # SMTP EMAIL CONFIGURATION
    # ============================================
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: Optional[str] = os.getenv("SMTP_USER")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD")
    SMTP_FROM: Optional[str] = os.getenv("SMTP_FROM")
    
    # Email notification settings
    SEND_PASSWORD_CHANGE_NOTIFICATIONS: bool = os.getenv("SEND_PASSWORD_CHANGE_NOTIFICATIONS", "true").lower() == "true"
    SEND_WELCOME_EMAILS: bool = os.getenv("SEND_WELCOME_EMAILS", "true").lower() == "true"
    SEND_SECURITY_ALERTS: bool = os.getenv("SEND_SECURITY_ALERTS", "true").lower() == "true"
    SEND_PASSWORD_EXPIRY_WARNINGS: bool = os.getenv("SEND_PASSWORD_EXPIRY_WARNINGS", "true").lower() == "true"

    # ============================================
    # FRONTEND CONFIGURATION
    # ============================================
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173")

    # ============================================
    # TOKEN CONFIGURATION
    # ============================================
    TOKEN_EXPIRE_HOURS: int = int(os.getenv("TOKEN_EXPIRE_HOURS", "1"))

    # ============================================
    # PASSWORD HISTORY CONFIGURATION
    # ============================================
    PASSWORD_HISTORY_LIMIT: int = int(os.getenv("PASSWORD_HISTORY_LIMIT", "10"))
    PREVENT_PASSWORD_REUSE: bool = os.getenv("PREVENT_PASSWORD_REUSE", "true").lower() == "true"

    # ============================================
    # SEGURIDAD AVANZADA (FASE 1)
    # ============================================
    PASSWORD_MAX_AGE_DAYS: int = int(os.getenv("PASSWORD_MAX_AGE_DAYS", "90"))
    PASSWORD_PREVENT_REUSE_COUNT: int = int(os.getenv("PASSWORD_PREVENT_REUSE_COUNT", "5"))
    PASSWORD_MIN_LENGTH: int = int(os.getenv("PASSWORD_MIN_LENGTH", "8"))
    PASSWORD_REQUIRE_UPPERCASE: bool = os.getenv("PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true"
    PASSWORD_REQUIRE_LOWERCASE: bool = os.getenv("PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true"
    PASSWORD_REQUIRE_NUMBERS: bool = os.getenv("PASSWORD_REQUIRE_NUMBERS", "true").lower() == "true"
    PASSWORD_REQUIRE_SPECIAL_CHARS: bool = os.getenv("PASSWORD_REQUIRE_SPECIAL_CHARS", "true").lower() == "true"

    # ============================================
    # RATE LIMITING (FASE 2)
    # ============================================
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOGIN_LOCKOUT_MINUTES: int = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
    SESSION_TIMEOUT_HOURS: int = int(os.getenv("SESSION_TIMEOUT_HOURS", "24"))
    MAX_2FA_ATTEMPTS: int = int(os.getenv("MAX_2FA_ATTEMPTS", "3"))

    # ============================================
    # API CONFIGURATION
    # ============================================
    API_VERSION: str = "2.6.0"  # ✅ Actualizado: Fases 1, 2 y 3 completadas
    API_TITLE: str = "Todo App Manager API"
    API_DESCRIPTION: str = (
        "API para la aplicación de tareas con Supabase Auth. "
        "Soporta autenticación con email/contraseña, Passkeys (WebAuthn), "
        "OTP por email, 2FA (TOTP), Expiración de contraseñas, "
        "Historial de contraseñas, Prevención de reutilización, "
        "Rate limiting, Bloqueo de cuenta y Backup en la nube."
    )

    # ============================================
    # SECURITY CONFIGURATION
    # ============================================
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-super-secret-key-change-in-production-2026")

    # ============================================
    # CORS CONFIGURATION - CONFIGURACIÓN DINÁMICA
    # ============================================
    ALLOWED_ORIGINS_ENV: Optional[str] = os.getenv("ALLOWED_ORIGINS")
    
    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        """Genera dinámicamente los orígenes CORS permitidos"""
        if self.ALLOWED_ORIGINS_ENV:
            try:
                return json.loads(self.ALLOWED_ORIGINS_ENV)
            except json.JSONDecodeError:
                return [origin.strip() for origin in self.ALLOWED_ORIGINS_ENV.split(",")]
        
        local_ip = get_local_ip()
        origins = [
            "http://localhost:5173",
            "http://localhost:8000",
            f"http://{local_ip}:5173",
            f"http://{local_ip}:8000"
        ]
        
        if os.getenv("ENVIRONMENT", "development") == "development":
            origins.append("*")
        
        return origins

    # ============================================
    # LOGGING CONFIGURATION
    # ============================================
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ============================================
    # ENVIRONMENT CONFIGURATION
    # ============================================
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production")

    # ============================================
    # STORAGE CONFIGURATION
    # ============================================
    SUPABASE_BUCKET_AVATARS: str = os.getenv("SUPABASE_BUCKET_AVATARS", "avatars")
    SUPABASE_BUCKET_BANNERS: str = os.getenv("SUPABASE_BUCKET_BANNERS", "banners")
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "10"))
    ALLOWED_IMAGE_TYPES: List[str] = [
        "image/jpeg", 
        "image/jpg", 
        "image/png", 
        "image/gif", 
        "image/webp"
    ]

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    @field_validator("ALLOWED_IMAGE_TYPES", mode="before")
    @classmethod
    def parse_allowed_image_types(cls, v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return [img_type.strip() for img_type in v.split(",") if img_type.strip()]
        return v

    # ============================================
    # MÉTODOS DE VALIDACIÓN
    # ============================================

    def is_supabase_configured(self) -> bool:
        return bool(self.SUPABASE_URL and self.SUPABASE_SERVICE_KEY)

    def validate_smtp_config(self) -> bool:
        required = [self.SMTP_HOST, self.SMTP_PORT, self.SMTP_USER, self.SMTP_PASSWORD, self.SMTP_FROM]
        return all(required)

    def validate_supabase_config(self) -> bool:
        return self.is_supabase_configured()

    @property
    def max_file_size_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024

    @property
    def reset_password_url(self) -> str:
        base = self.FRONTEND_URL.rstrip('/')
        return f"{base}/reset-password"

    @property
    def use_supabase_auth(self) -> bool:
        return self.is_supabase_configured()

    @property
    def should_send_email_notifications(self) -> bool:
        return self.validate_smtp_config() and self.SEND_PASSWORD_CHANGE_NOTIFICATIONS

    @property
    def should_prevent_password_reuse(self) -> bool:
        return self.PREVENT_PASSWORD_REUSE and self.PASSWORD_HISTORY_LIMIT > 0

    @property
    def should_send_password_expiry_warnings(self) -> bool:
        return self.validate_smtp_config() and self.SEND_PASSWORD_EXPIRY_WARNINGS

    @property
    def password_policy(self) -> dict:
        return {
            "max_age_days": self.PASSWORD_MAX_AGE_DAYS,
            "prevent_reuse_count": self.PASSWORD_PREVENT_REUSE_COUNT,
            "min_length": self.PASSWORD_MIN_LENGTH,
            "require_uppercase": self.PASSWORD_REQUIRE_UPPERCASE,
            "require_lowercase": self.PASSWORD_REQUIRE_LOWERCASE,
            "require_numbers": self.PASSWORD_REQUIRE_NUMBERS,
            "require_special_chars": self.PASSWORD_REQUIRE_SPECIAL_CHARS
        }

    @property
    def rate_limit_config(self) -> dict:
        return {
            "max_login_attempts": self.MAX_LOGIN_ATTEMPTS,
            "lockout_minutes": self.LOGIN_LOCKOUT_MINUTES,
            "session_timeout_hours": self.SESSION_TIMEOUT_HOURS,
            "max_2fa_attempts": self.MAX_2FA_ATTEMPTS
        }


# Instancia global de configuración
settings = Settings()

# Mostrar configuración al inicio
print("=" * 60)
print("📋 CONFIGURACIÓN DE LA API")
print(f"📌 API Version: {settings.API_VERSION}")
print(f"🌐 Frontend URL: {settings.FRONTEND_URL}")
print(f"🔗 Reset Password URL: {settings.reset_password_url}")
print(f"🌍 CORS Origins: {settings.ALLOWED_ORIGINS}")
print("-" * 60)

# Mostrar estado de Supabase
if settings.is_supabase_configured():
    print(f"✅ Supabase Auth: CONFIGURADO")
    print(f"   URL: {settings.SUPABASE_URL}")
    print(f"   Storage Buckets: {settings.SUPABASE_BUCKET_AVATARS}, {settings.SUPABASE_BUCKET_BANNERS}")
else:
    print("❌ Supabase Auth: NO CONFIGURADO")

# Mostrar estado de SMTP
if settings.validate_smtp_config():
    print(f"✅ SMTP: CONFIGURADO ({settings.SMTP_HOST}:{settings.SMTP_PORT})")
else:
    print("⚠️ SMTP: NO CONFIGURADO")

# Mostrar configuración de seguridad
print("-" * 60)
print("🔐 CONFIGURACIÓN DE SEGURIDAD")
print(f"   Prevenir reutilización: {'✅' if settings.should_prevent_password_reuse else '❌'}")
print(f"   Envío de notificaciones: {'✅' if settings.should_send_email_notifications else '❌'}")
print(f"   Advertencias de expiración: {'✅' if settings.should_send_password_expiry_warnings else '❌'}")
print(f"   2FA (TOTP): ✅ ACTIVADO")
print(f"   OTP por email: ✅ ACTIVADO")
print(f"   Cloud Backup: ✅ ACTIVADO (límite 20)")

# Mostrar política de contraseñas
print("-" * 60)
print("📋 POLÍTICA DE CONTRASEÑAS")
policy = settings.password_policy
print(f"   Máx edad: {policy['max_age_days']} días")
print(f"   Prevenir reutilización: últimas {policy['prevent_reuse_count']} veces")
print(f"   Longitud mínima: {policy['min_length']} caracteres")
print(f"   Requiere mayúsculas: {'✅' if policy['require_uppercase'] else '❌'}")
print(f"   Requiere minúsculas: {'✅' if policy['require_lowercase'] else '❌'}")
print(f"   Requiere números: {'✅' if policy['require_numbers'] else '❌'}")
print(f"   Requiere caracteres especiales: {'✅' if policy['require_special_chars'] else '❌'}")

# Mostrar configuración de rate limiting
print("-" * 60)
print("🚦 RATE LIMITING")
rate = settings.rate_limit_config
print(f"   Máx intentos login: {rate['max_login_attempts']}")
print(f"   Duración bloqueo: {rate['lockout_minutes']} minutos")
print(f"   Timeout sesión: {rate['session_timeout_hours']} horas")
print(f"   Máx intentos 2FA: {rate['max_2fa_attempts']}")
print("=" * 60)