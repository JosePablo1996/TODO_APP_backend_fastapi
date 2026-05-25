# app/routers/auth.py
from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any, List
from app.services.supabase_auth_service import supabase_auth
from app.services.email_service import email_service
from app.services.two_factor_service import two_factor_service, two_factor_setup_cache
from app.services.security_service import security_service, SecurityEventType
from app.config import settings
from app.dependencies import get_current_user, get_auth_token
import logging
import httpx
import hashlib
import base64
import random
import string
from datetime import datetime, timedelta
from collections import defaultdict

# ============================================
# IMPORTAR MODELOS DESDE APP.MODELS
# ============================================
from app.models import (
    # Modelos de autenticación existentes
    RegisterRequest,
    RegisterResponse,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    LogoutResponse,
    ChangePasswordRequest,
    ChangePasswordResponse,
    DebugCheckResponse,
    # Modelos OTP
    OtpSendRequest,
    OtpSendResponse,
    OtpVerifyRequest,
    OtpVerifyResponse,
    # Modelos 2FA
    TwoFactorSetupRequest,
    TwoFactorSetupResponse,
    TwoFactorEnableRequest,
    TwoFactorEnableResponse,
    TwoFactorVerifyRequest,
    TwoFactorVerifyResponse,
    TwoFactorDisableRequest,
    TwoFactorStatusResponse,
    # Reset de contraseña por código OTP
    ResetPasswordOtpRequest,
    ResetPasswordOtpVerifyRequest,
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])
logger = logging.getLogger(__name__)

# Variable para detectar reinicio del servidor
LAST_RESTART = datetime.now()

# ============================================
# CONSTANTES PARA DEEP LINKS
# ============================================

WEB_RESET_PASSWORD_URL = f"{settings.FRONTEND_URL}/reset-password"
MOBILE_RESET_PASSWORD_URL = "todoappmanager://reset-password"

# ============================================
# ALMACENAMIENTO TEMPORAL OTP
# ============================================

otp_storage: Dict[str, dict] = {}
otp_rate_limit: Dict[str, list] = defaultdict(list)
reset_otp_storage: Dict[str, dict] = {}


def generate_otp_code() -> str:
    """Genera un código OTP de 6 dígitos"""
    return ''.join(random.choices(string.digits, k=6))


def clean_expired_otps():
    """Limpia códigos OTP expirados"""
    now = datetime.now()
    expired = [email for email, data in otp_storage.items() if data["expires_at"] < now]
    for email in expired:
        del otp_storage[email]


def clean_rate_limit():
    """Limpia rate limiting antiguo (más de 1 hora)"""
    now = datetime.now()
    for email in list(otp_rate_limit.keys()):
        otp_rate_limit[email] = [ts for ts in otp_rate_limit[email] if now - ts < timedelta(hours=1)]
        if not otp_rate_limit[email]:
            del otp_rate_limit[email]


def detect_platform(request: Request) -> str:
    """
    Detecta si la solicitud viene de la app móvil o web.
    
    Returns:
        'mobile' o 'web'
    """
    platform_header = request.headers.get('X-Platform', '').lower()
    if platform_header == 'mobile':
        logger.info("📱 Plataforma detectada por header: mobile")
        return 'mobile'
    if platform_header == 'web':
        logger.info("🌐 Plataforma detectada por header: web")
        return 'web'
    
    user_agent = request.headers.get('User-Agent', '').lower()
    mobile_patterns = ['flutter', 'dart', 'android', 'iphone', 'ipad', 'ios', 'mobile', 'okhttp', 'dio', 'cfnetwork', 'darwin']
    
    for pattern in mobile_patterns:
        if pattern in user_agent:
            logger.info(f"📱 Plataforma detectada por User-Agent: mobile")
            return 'mobile'
    
    logger.info(f"🌐 Plataforma no detectada, usando default: web")
    return 'web'


async def send_otp_email(to_email: str, code: str) -> bool:
    """Envía el código OTP por email usando el servicio de email existente."""
    try:
        user_name = to_email.split('@')[0]
        
        try:
            admin_client = supabase_auth.get_admin_client()
            users_response = admin_client.auth.admin.list_users()
            if users_response and hasattr(users_response, 'users') and users_response.users:
                for user in users_response.users:
                    if user.email == to_email:
                        user_metadata = user.user_metadata or {}
                        user_name = user_metadata.get("full_name") or user_metadata.get("username") or to_email.split('@')[0]
                        break
        except Exception:
            pass
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Código de acceso - TodoApp</title>
            <style>
                @media only screen and (max-width: 600px){{
                    .otp-code {{
                        font-size: 28px !important;
                        letter-spacing: 8px !important;
                        padding: 16px !important;
                    }}
                }}
            </style>
        </head>
        <body style="margin:0; padding:20px; background:linear-gradient(135deg, #f0f2f5, #e6e9f0); font-family:'Segoe UI', -apple-system, BlinkMacSystemFont, 'Roboto', Arial, Helvetica, sans-serif;">
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:600px; width:100%;">
                <tr>
                    <td align="center" style="padding:20px 10px;">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#ffffff; border-radius:28px; box-shadow:0 20px 40px rgba(0,0,0,0.12); overflow:hidden;">
                            <tr>
                                <td align="center" style="background:linear-gradient(135deg, #10B981, #059669); padding:48px 20px;">
                                    <div style="font-size:64px; margin-bottom:16px;">🔐</div>
                                    <h1 style="margin:0; color:white; font-size:34px; font-weight:700;">¡Hola {user_name}!</h1>
                                    <p style="margin:12px 0 0; color:rgba(255,255,255,0.95); font-size:16px;">Tu código de acceso seguro</p>
                                </td>
                            </tr>
                            <tr>
                                <td align="left" style="padding:48px 40px;">
                                    <h2 style="color:#1f2937; font-size:24px; margin:0 0 12px;">¡Bienvenido! 👋</h2>
                                    <p style="color:#4b5563; line-height:1.6; margin:0 0 24px; font-size:16px;">
                                        Has solicitado iniciar sesión en <strong style="color:#10B981;">TodoApp</strong>.
                                        Usa el siguiente código para completar tu acceso.
                                    </p>
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background:linear-gradient(135deg, #f0fdf4, #ecfdf5); border-radius:20px; padding:32px 28px; margin:32px 0;">
                                        <tr>
                                            <td align="center">
                                                <div class="otp-code" style="background:#ffffff; border-radius:16px; padding:20px 24px; border:2px solid #10B981;">
                                                    <span style="font-size:36px; font-weight:800; letter-spacing:12px; color:#059669; font-family:'Courier New', monospace;">{code}</span>
                                                </div>
                                                <p style="color:#374151; font-size:15px; margin:20px 0 0;">
                                                    Ingresa este código en la pantalla de verificación
                                                </p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>
                            <tr>
                                <td align="center" style="background-color:#f9fafb; padding:32px 24px; border-top:1px solid #e5e7eb;">
                                    <h3 style="font-size:26px; font-weight:700; color:#10B981; margin:0 0 12px;">TodoApp</h3>
                                    <p style="color:#9ca3af; font-size:12px;">Organiza tu día, alcanza tus metas</p>
                                    <p style="color:#9ca3af; font-size:11px; margin:16px 0 0;">© 2026 TodoApp. Todos los derechos reservados.</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        
        email_sent = await email_service.send_email(
            to_email=to_email,
            subject="🔐 Tu código de acceso a TodoApp",
            body=f"Tu código de verificación es: {code}\n\nEste código expirará en 15 minutos.\n\nSi no solicitaste este código, ignora este mensaje.",
            html_body=html_content
        )
        
        if email_sent:
            logger.info(f"📧 Código OTP enviado exitosamente a {to_email}")
            return True
        else:
            logger.error(f"❌ Error enviando email OTP a {to_email}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error enviando email OTP: {e}")
        return False


# ============================================
# ✅ NUEVO FASE 2: ENDPOINT PARA VERIFICAR ESTADO DE BLOQUEO
# ============================================

@router.get("/login-attempts/status")
async def get_login_attempts_status(email: str, request: Request):
    """
    Verifica el estado de los intentos de login para un email/IP.
    Útil para mostrar al usuario cuántos intentos le quedan.
    """
    ip_address = request.client.host if request.client else "unknown"
    
    try:
        info = await security_service.get_failed_attempts_info(email, ip_address)
        
        return {
            "success": True,
            "email": email,
            "ip_address": ip_address,
            **info
        }
    except Exception as e:
        logger.error(f"Error obteniendo estado de bloqueo: {e}")
        return {
            "success": False,
            "error": "Error al obtener información"
        }


# ============================================
# ✅ NUEVO FASE 2: ENDPOINT PARA ENVÍO DE ADVERTENCIAS DE EXPIRACIÓN
# (Para ser llamado por un cron job diario)
# ============================================

@router.post("/cron/send-password-expiry-warnings")
async def send_password_expiry_warnings_cron(request: Request):
    """
    Endpoint interno para enviar advertencias de expiración de contraseña.
    Debe ser llamado por un cron job diario.
    Solo accesible con service_role.
    """
    # Verificar que la solicitud viene de un origen confiable
    auth_header = request.headers.get("Authorization", "")
    expected_key = f"Bearer {settings.SUPABASE_SERVICE_KEY}"
    
    if auth_header != expected_key:
        logger.warning("⚠️ Intento no autorizado de acceder al endpoint de advertencias")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="No autorizado"
        )
    
    logger.info("📧 Enviando advertencias de expiración de contraseña...")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # Obtener todos los usuarios
        users_response = admin_client.auth.admin.list_users()
        users = users_response.users if hasattr(users_response, 'users') else []
        
        warnings_sent = 0
        warnings_skipped = 0
        
        for user in users:
            user_id = user.id
            user_email = user.email
            user_metadata = user.user_metadata or {}
            user_name = user_metadata.get("full_name") or user_metadata.get("username") or user_email.split('@')[0]
            
            # Verificar expiración
            is_expired, days_remaining = await security_service.is_password_expired(user_id)
            
            if not is_expired and days_remaining is not None and days_remaining > 0:
                # Verificar si debe enviar advertencia
                last_notified = user_metadata.get("last_expiry_notification_days")
                
                if security_service.should_notify_expiry(days_remaining, last_notified):
                    if settings.should_send_password_expiry_warnings:
                        await email_service.send_password_expiry_warning(user_email, user_name, days_remaining)
                        warnings_sent += 1
                        
                        # Actualizar metadata del usuario en profiles
                        try:
                            await security_service.update_user_metadata(user_id, {
                                "last_expiry_notification_days": days_remaining,
                                "last_expiry_notification_at": datetime.now().isoformat()
                            })
                        except Exception as meta_error:
                            logger.warning(f"⚠️ No se pudo actualizar metadata para {user_id}: {meta_error}")
                    else:
                        warnings_skipped += 1
                else:
                    warnings_skipped += 1
        
        logger.info(f"✅ Advertencias enviadas: {warnings_sent}, omitidas: {warnings_skipped}")
        
        return {
            "success": True,
            "warnings_sent": warnings_sent,
            "warnings_skipped": warnings_skipped,
            "total_users": len(users)
        }
        
    except Exception as e:
        logger.error(f"❌ Error enviando advertencias: {e}")
        return {
            "success": False,
            "error": str(e)
        }


# ============================================
# ENDPOINTS DE AUTENTICACIÓN EXISTENTES
# ============================================

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: RegisterRequest):
    """Registra un nuevo usuario usando Supabase Auth"""
    logger.info(f"📝 Intentando registrar usuario: {user_data.username} ({user_data.email})")
    
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible"
        )
    
    try:
        user = await supabase_auth.create_user(
            email=user_data.email,
            password=user_data.password,
            username=user_data.username,
            full_name=user_data.full_name
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error al crear usuario. El email puede estar ya registrado."
            )
        
        logger.info(f"✅ Usuario registrado exitosamente: {user['user_id']}")
        
        try:
            await email_service.send_welcome_email(
                to_email=user_data.email,
                nombre=user_data.full_name or user_data.username
            )
        except Exception as e:
            logger.warning(f"⚠️ Error enviando email de bienvenida (no crítico): {e}")
        
        return RegisterResponse(
            success=True,
            message="Usuario registrado exitosamente. Revisa tu email para confirmar tu cuenta.",
            user_id=user["user_id"],
            email=user["email"],
            username=user["username"],
            requires_email_verification=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en registro: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al registrar usuario: {str(e)}"
        )


@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, req: Request = None):
    """Inicia sesión usando Supabase Auth"""
    logger.info(f"📝 Intentando login para: {credentials.email}")
    
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible"
        )
    
    # ✅ Obtener IP del cliente
    ip_address = req.client.host if req else "unknown"
    
    # ✅ Verificar si la cuenta está bloqueada (RATE LIMITING FASE 2)
    is_locked, locked_until, remaining_attempts = await security_service.is_account_locked(
        credentials.email, ip_address
    )
    
    if is_locked:
        seconds_remaining = int((locked_until - datetime.now()).total_seconds()) if locked_until else 0
        minutes_remaining = (seconds_remaining + 59) // 60
        
        logger.warning(f"⚠️ Intento de login a cuenta bloqueada: {credentials.email} (IP: {ip_address})")
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "ACCOUNT_LOCKED",
                "message": f"Demasiados intentos fallidos. Tu cuenta está bloqueada temporalmente.",
                "minutes_remaining": minutes_remaining,
                "seconds_remaining": seconds_remaining,
                "unlock_time": locked_until.isoformat() if locked_until else None
            }
        )
    
    try:
        client = supabase_auth.anon_client
        
        if not client:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cliente de autenticación no disponible"
            )
        
        response = client.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })
        
        if not response or not response.user:
            # ✅ Registrar intento fallido con rate limiting (FASE 2)
            await security_service.record_failed_login(
                email=credentials.email,
                ip_address=ip_address,
                user_id=None
            )
            
            # Obtener información actualizada
            attempt_info = await security_service.get_failed_attempts_info(credentials.email, ip_address)
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": "INVALID_CREDENTIALS",
                    "message": "Email o contraseña incorrectos",
                    "attempts_remaining": attempt_info.get("remaining_attempts", 4),
                    "max_attempts": security_service.max_login_attempts
                }
            )
        
        if not response.user.email_confirmed_at:
            logger.warning(f"⚠️ Intento de login con email no verificado: {credentials.email}")
            await security_service.log_security_event(
                user_id=response.user.id,
                event_type=SecurityEventType.LOGIN_FAILED,
                ip_address=ip_address,
                user_agent=req.headers.get("User-Agent"),
                details={"email": credentials.email, "reason": "email_not_confirmed"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Por favor verifica tu email antes de iniciar sesión. Revisa tu bandeja de entrada."
            )
        
        user_id = response.user.id
        
        # ✅ Verificar expiración de contraseña
        is_expired, days_remaining = await security_service.is_password_expired(user_id)
        
        if is_expired:
            logger.warning(f"⚠️ Intento de login con contraseña expirada: {credentials.email}")
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.PASSWORD_EXPIRED,
                ip_address=ip_address,
                user_agent=req.headers.get("User-Agent"),
                details={"email": credentials.email, "days_remaining": 0}
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "PASSWORD_EXPIRED",
                    "message": "Tu contraseña ha expirado. Debes cambiarla para continuar.",
                    "requires_password_change": True
                }
            )
        
        # Verificar si el usuario tiene 2FA activado
        admin_client = supabase_auth.get_admin_client()
        requires_2fa = False
        
        try:
            result = admin_client.table("user_two_factor").select("enabled").eq("user_id", user_id).execute()
            if result.data and len(result.data) > 0:
                requires_2fa = result.data[0].get("enabled", False)
        except Exception as e:
            logger.warning(f"⚠️ Error verificando 2FA: {e}")
        
        # ✅ Registrar evento de seguridad: login exitoso
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.LOGIN_SUCCESS,
            ip_address=ip_address,
            user_agent=req.headers.get("User-Agent"),
            details={"email": credentials.email, "requires_2fa": requires_2fa}
        )
        
        # ✅ Limpiar intentos fallidos después de login exitoso (FASE 2)
        await security_service.reset_failed_logins(credentials.email, ip_address)
        
        # Si tiene 2FA activado, devolver respuesta especial
        if requires_2fa:
            logger.info(f"🔐 Usuario {credentials.email} requiere 2FA")
            user_metadata = response.user.user_metadata or {}
            
            return LoginResponse(
                requires_2fa=True,
                message="Se requiere código de verificación 2FA",
                user_id=user_id,
                user={
                    "id": user_id,
                    "email": credentials.email,
                    "username": user_metadata.get("username") or credentials.email.split("@")[0],
                    "full_name": user_metadata.get("full_name"),
                    "avatar": user_metadata.get("avatar")
                }
            )
        
        # Login exitoso sin 2FA
        logger.info(f"✅ Login exitoso para: {credentials.email}")
        
        user_metadata = response.user.user_metadata or {}
        
        user_data = {
            "id": response.user.id,
            "email": response.user.email,
            "username": user_metadata.get("username") or credentials.email.split("@")[0],
            "full_name": user_metadata.get("full_name"),
            "avatar": user_metadata.get("avatar"),
            "email_verified": True
        }
        
        return LoginResponse(
            access_token=response.session.access_token,
            refresh_token=response.session.refresh_token,
            expires_in=response.session.expires_in,
            user=user_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ Error en login: {error_msg}")
        
        if "Invalid login credentials" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email o contraseña incorrectos"
            )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al iniciar sesión: {error_msg}"
        )


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_token(request: RefreshTokenRequest):
    """Renueva el access token usando el refresh token"""
    logger.info("🔄 Renovando token")
    
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible"
        )
    
    try:
        client = supabase_auth.anon_client
        
        if not client:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cliente de autenticación no disponible"
            )
        
        response = client.auth.refresh_session(request.refresh_token)
        
        if not response or not response.session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token inválido o expirado"
            )
        
        logger.info("✅ Token renovado exitosamente")
        
        return RefreshTokenResponse(
            access_token=response.session.access_token,
            refresh_token=response.session.refresh_token,
            expires_in=response.session.expires_in
        )
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ Error refrescando token: {error_msg}")
        
        if "Invalid Refresh" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token inválido o expirado"
            )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al renovar token: {error_msg}"
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout(request: RefreshTokenRequest, req: Request = None):
    """Cierra la sesión del usuario"""
    logger.info("👋 Cerrando sesión")
    
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible"
        )
    
    try:
        client = supabase_auth.anon_client
        
        if client:
            client.auth.sign_out()
        
        logger.info("✅ Sesión cerrada exitosamente")
        
        return LogoutResponse(
            message="Sesión cerrada exitosamente"
        )
        
    except Exception as e:
        logger.error(f"❌ Error en logout: {str(e)}")
        return LogoutResponse(
            message="Sesión cerrada"
        )


# ============================================
# ✅ ENDPOINT FORGOT-PASSWORD
# ============================================

@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(request: Request, body: ForgotPasswordRequest):
    """Solicita recuperación de contraseña."""
    logger.info(f"📧 Solicitud de recuperación para: {body.email}")
    
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible"
        )
    
    try:
        client = supabase_auth.anon_client
        
        if not client:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cliente de autenticación no disponible"
            )
        
        client.auth.reset_password_for_email(body.email)
        
        logger.info(f"✅ Email de recuperación enviado a: {body.email}")
        
        return ForgotPasswordResponse(
            message="Si el email existe en nuestro sistema, recibirás instrucciones para restablecer tu contraseña."
        )
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ Error en forgot-password: {error_msg}")
        
        return ForgotPasswordResponse(
            message="Si el email existe en nuestro sistema, recibirás instrucciones para restablecer tu contraseña."
        )


# ============================================
# ✅ RESET DE CONTRASEÑA POR CÓDIGO OTP
# ============================================

@router.post("/forgot-password-otp", response_model=ForgotPasswordResponse)
async def forgot_password_otp(request: ForgotPasswordRequest):
    """Envía un código OTP de 6 dígitos para reset de contraseña."""
    logger.info(f"📧 Solicitando código OTP para reset: {request.email}")
    
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible"
        )
    
    user_exists = False
    user_name = request.email.split('@')[0]
    target_email = request.email.lower().strip()
    
    try:
        admin_client = supabase_auth.get_admin_client()
        users_response = admin_client.auth.admin.list_users()
        
        users_list = []
        if users_response is not None:
            if hasattr(users_response, 'users') and users_response.users:
                users_list = users_response.users
            elif isinstance(users_response, list):
                users_list = users_response
        
        logger.info(f"📋 Buscando entre {len(users_list)} usuarios: {target_email}")
        
        for user in users_list:
            user_email = getattr(user, 'email', '')
            if user_email.lower().strip() == target_email:
                user_exists = True
                user_metadata = getattr(user, 'user_metadata', {}) or {}
                user_name = user_metadata.get("full_name") or user_metadata.get("username") or target_email.split('@')[0]
                logger.info(f"✅ Usuario encontrado: {target_email}")
                break
        
        if not user_exists:
            logger.warning(f"❌ Usuario NO encontrado: {target_email}")
            return ForgotPasswordResponse(
                message="Si el email existe en nuestro sistema, recibirás un código de verificación."
            )
    
    except Exception as e:
        logger.error(f"❌ Error buscando usuario: {e}")
    
    if not user_exists:
        return ForgotPasswordResponse(
            message="Si el email existe en nuestro sistema, recibirás un código de verificación."
        )
    
    code = ''.join(random.choices(string.digits, k=6))
    
    reset_otp_storage[request.email] = {
        "code": code,
        "expires_at": datetime.now() + timedelta(minutes=15),
        "attempts": 0
    }
    
    logger.info(f"🔢 Código generado para {request.email}: {code}")
    
    try:
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5;">
            <div style="max-width: 500px; margin: auto; background: white; border-radius: 16px; padding: 32px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 24px;">
                    <h1 style="color: #10B981; margin: 0;">🔐 TodoApp</h1>
                </div>
                <h2 style="color: #1f2937;">Recuperación de contraseña</h2>
                <p style="color: #4b5563;">Hola <strong>{user_name}</strong>,</p>
                <p style="color: #4b5563;">Has solicitado restablecer tu contraseña. Usa el siguiente código en la app:</p>
                <div style="background: #f0fdf4; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0; border: 2px dashed #10B981;">
                    <span style="font-size: 40px; font-weight: bold; letter-spacing: 10px; color: #059669; font-family: 'Courier New', monospace;">{code}</span>
                </div>
                <p style="color: #6b7280; font-size: 14px;">⏰ Este código expira en <strong>15 minutos</strong>.</p>
                <p style="color: #6b7280; font-size: 14px;">🔒 Si no solicitaste este cambio, ignora este mensaje.</p>
                <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 24px 0;">
                <p style="color: #9ca3af; font-size: 12px; text-align: center;">© 2026 TodoApp. Todos los derechos reservados.</p>
            </div>
        </body>
        </html>
        """
        
        email_sent = await email_service.send_email(
            to_email=request.email,
            subject="🔐 Código de recuperación - TodoApp",
            body=f"Hola {user_name},\n\nTu código de recuperación es: {code}\n\nEste código expira en 15 minutos.\n\nSi no solicitaste este cambio, ignora este mensaje.",
            html_body=html_content
        )
        
        if email_sent:
            logger.info(f"✅ Código OTP enviado a {request.email}")
        else:
            logger.error(f"❌ Email service retornó False para {request.email}")
            reset_otp_storage.pop(request.email, None)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al enviar el código. Intenta nuevamente."
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error enviando email OTP: {e}")
        reset_otp_storage.pop(request.email, None)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al enviar el código. Intenta nuevamente."
        )
    
    return ForgotPasswordResponse(
        message="Si el email existe en nuestro sistema, recibirás un código de verificación."
    )


@router.post("/reset-password-otp", response_model=ResetPasswordResponse)
async def reset_password_otp(request: ResetPasswordOtpVerifyRequest, req: Request = None):
    """
    ✅ NUEVO: Verifica código OTP y cambia la contraseña.
    Incluye validación de fortaleza, historial y expiración.
    """
    logger.info(f"🔐 Verificando código OTP para reset: {request.email}")
    
    # Verificar código
    stored = reset_otp_storage.get(request.email)
    
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se encontró una solicitud de código. Solicita uno nuevo."
        )
    
    if datetime.now() > stored["expires_at"]:
        del reset_otp_storage[request.email]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El código ha expirado. Solicita uno nuevo."
        )
    
    if stored["attempts"] >= 5:
        del reset_otp_storage[request.email]
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Solicita un nuevo código."
        )
    
    if stored["code"] != request.code:
        stored["attempts"] += 1
        remaining = 5 - stored["attempts"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Código incorrecto. Te quedan {remaining} intentos."
        )
    
    # Código correcto - limpiar
    del reset_otp_storage[request.email]
    
    # ✅ Validar fortaleza de la nueva contraseña
    policy = await security_service.get_password_policy()
    is_valid, errors = security_service.validate_password_strength(request.new_password, policy)
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors, "message": "La contraseña no cumple los requisitos de seguridad"}
        )
    
    # Buscar usuario
    try:
        admin_client = supabase_auth.get_admin_client()
        user_id = None
        target_email = request.email.lower().strip()
        
        users_response = admin_client.auth.admin.list_users()
        
        users_list = []
        if users_response is not None:
            if hasattr(users_response, 'users') and users_response.users:
                users_list = users_response.users
            elif isinstance(users_response, list):
                users_list = users_response
        
        for user in users_list:
            user_email = getattr(user, 'email', '')
            if user_email.lower().strip() == target_email:
                user_id = getattr(user, 'id', None)
                logger.info(f"✅ Usuario encontrado: {target_email} (ID: {user_id})")
                break
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado."
            )
        
        # ✅ Verificar reutilización de contraseña
        new_password_hash = security_service.hash_password_for_history(request.new_password)
        can_reuse, times_used = await security_service.check_password_reuse(user_id, new_password_hash)
        
        if not can_reuse:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"No puedes usar una contraseña que hayas utilizado en las últimas {policy.get('prevent_reuse_count', 5)} veces"
            )
        
        # Actualizar contraseña
        admin_client.auth.admin.update_user_by_id(
            user_id,
            {"password": request.new_password}
        )
        
        logger.info(f"✅ Contraseña actualizada para usuario: {user_id}")
        
        # ✅ Registrar en historial de contraseñas
        await security_service.record_password_history(user_id, new_password_hash)
        await security_service.cleanup_old_password_history(user_id, 20)
        
        # ✅ Actualizar fecha de expiración
        await security_service.update_password_expiry(user_id)
        
        # ✅ Invalidar todas las sesiones
        await security_service.invalidate_all_sessions(user_id)
        
        # ✅ Registrar evento de seguridad
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.PASSWORD_RESET_VIA_OTP,
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={"method": "otp_reset"}
        )
        
        return ResetPasswordResponse(
            message="Contraseña actualizada exitosamente. Todas tus sesiones han sido cerradas por seguridad."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error cambiando contraseña: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al cambiar contraseña: {str(e)}"
        )


# ============================================
# ENDPOINT RESET-PASSWORD
# ============================================

@router.post("/reset-password", response_model=ResetPasswordResponse)
async def reset_password(request: ResetPasswordRequest, req: Request = None):
    """
    Restablece la contraseña usando el token recibido por email.
    ✅ INCLUYE: validación de fortaleza, historial, expiración
    """
    logger.info("🔐 Intentando restablecer contraseña")
    
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible"
        )
    
    try:
        supabase_url = settings.SUPABASE_URL
        url = f"{supabase_url}/auth/v1/user"
        
        headers = {
            "Authorization": f"Bearer {request.token}",
            "Content-Type": "application/json",
            "apikey": settings.SUPABASE_ANON_KEY
        }
        
        async with httpx.AsyncClient() as client:
            get_response = await client.get(url, headers=headers)
            
            if get_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token inválido o expirado"
                )
            
            user_data = get_response.json()
            user_id = user_data.get("id")
            user_email = user_data.get("email")
            user_metadata = user_data.get("user_metadata", {})
            user_name = user_metadata.get("full_name") or user_metadata.get("username") or user_email.split('@')[0]
            
            if not user_id or not user_email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No se pudo identificar al usuario"
                )
            
            # ✅ Validar fortaleza de la nueva contraseña
            policy = await security_service.get_password_policy()
            is_valid, errors = security_service.validate_password_strength(request.new_password, policy)
            
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"errors": errors, "message": "La contraseña no cumple los requisitos de seguridad"}
                )
            
            # ✅ Verificar reutilización de contraseña
            new_password_hash = security_service.hash_password_for_history(request.new_password)
            can_reuse, times_used = await security_service.check_password_reuse(user_id, new_password_hash)
            
            if not can_reuse:
                logger.warning(f"⚠️ Intento de reutilizar contraseña anterior para usuario: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"No puedes usar una contraseña que hayas utilizado en las últimas {policy.get('prevent_reuse_count', 5)} veces"
                )
            
            payload = {"password": request.new_password}
            put_response = await client.put(url, headers=headers, json=payload)
            
            if put_response.status_code != 200:
                error_detail = put_response.json() if put_response.text else {}
                error_msg = error_detail.get('msg', error_detail.get('message', 'Error desconocido'))
                logger.error(f"❌ Supabase error: {put_response.status_code} - {error_msg}")
                
                if put_response.status_code == 401:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="El enlace de recuperación ha expirado o es inválido. Solicita uno nuevo."
                    )
                elif put_response.status_code == 422:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="La contraseña no cumple con los requisitos de seguridad."
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Error al actualizar contraseña: {error_msg}"
                    )
            
            # ✅ Registrar en historial
            await security_service.record_password_history(user_id, new_password_hash)
            await security_service.cleanup_old_password_history(user_id, 20)
            
            # ✅ Actualizar fecha de expiración
            await security_service.update_password_expiry(user_id)
            
            # ✅ Invalidar todas las sesiones
            await security_service.invalidate_all_sessions(user_id)
            
            # ✅ Registrar evento de seguridad
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.PASSWORD_CHANGED,
                ip_address=req.client.host if req else None,
                user_agent=req.headers.get("User-Agent"),
                details={"method": "email_reset"}
            )
            
            logger.info(f"✅ Contraseña actualizada exitosamente para usuario ID: {user_id}")
            
            try:
                detalles = {
                    "dispositivo": "Navegador web",
                    "ubicacion": "Ubicación desconocida",
                    "ip": req.client.host if req else "IP no registrada",
                    "metodo": "restablecimiento por email"
                }
                
                await email_service.send_password_changed_notification(
                    to_email=user_email,
                    nombre=user_name,
                    detalles=detalles
                )
                logger.info(f"📧 Notificación de cambio de contraseña enviada a: {user_email}")
            except Exception as email_error:
                logger.warning(f"⚠️ No se pudo enviar notificación por email: {email_error}")
        
        return ResetPasswordResponse(
            message="Contraseña actualizada exitosamente. Todas tus sesiones han sido cerradas por seguridad."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ Error en reset-password: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al restablecer contraseña: {error_msg}"
        )


# ============================================
# ✅ ENDPOINT CHANGE-PASSWORD ACTUALIZADO
# ============================================

@router.post("/change-password", response_model=ChangePasswordResponse)
async def change_password(
    request: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
    token: str = Depends(get_auth_token),
    req: Request = None
):
    """
    Cambia la contraseña del usuario autenticado.
    ✅ INCLUYE: validación de fortaleza, historial, expiración, eventos
    """
    user_id = current_user.get("sub")
    user_email = current_user.get("email")
    user_name = current_user.get("name") or current_user.get("username") or user_email.split('@')[0]
    
    logger.info(f"🔐 Intentando cambiar contraseña para usuario: {user_id}")
    
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de autenticación no disponible"
        )
    
    try:
        client = supabase_auth.anon_client
        if not client:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cliente de autenticación no disponible"
            )
        
        # Verificar contraseña actual
        try:
            verification = client.auth.sign_in_with_password({
                "email": user_email,
                "password": request.current_password
            })
            
            if not verification or not verification.user:
                # ✅ Registrar intento fallido
                await security_service.log_security_event(
                    user_id=user_id,
                    event_type=SecurityEventType.PASSWORD_CHANGE_FAILED,
                    ip_address=req.client.host if req else None,
                    user_agent=req.headers.get("User-Agent"),
                    details={"reason": "current_password_incorrect"}
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="La contraseña actual es incorrecta"
                )
        except Exception as e:
            error_msg = str(e)
            if "Invalid login credentials" in error_msg:
                await security_service.log_security_event(
                    user_id=user_id,
                    event_type=SecurityEventType.PASSWORD_CHANGE_FAILED,
                    ip_address=req.client.host if req else None,
                    user_agent=req.headers.get("User-Agent"),
                    details={"reason": "current_password_incorrect"}
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="La contraseña actual es incorrecta"
                )
            raise
        
        # Verificar que nueva contraseña sea diferente
        if request.current_password == request.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La nueva contraseña debe ser diferente a la actual"
            )
        
        # ✅ Validar fortaleza de la nueva contraseña
        policy = await security_service.get_password_policy()
        is_valid, errors = security_service.validate_password_strength(request.new_password, policy)
        
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": errors, "message": "La contraseña no cumple los requisitos de seguridad"}
            )
        
        # ✅ Verificar reutilización de contraseña
        new_password_hash = security_service.hash_password_for_history(request.new_password)
        can_reuse, times_used = await security_service.check_password_reuse(user_id, new_password_hash)
        
        if not can_reuse:
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.PASSWORD_REUSE_ATTEMPT,
                ip_address=req.client.host if req else None,
                user_agent=req.headers.get("User-Agent"),
                details={"times_used": times_used}
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"No puedes usar una contraseña que hayas utilizado en las últimas {policy.get('prevent_reuse_count', 5)} veces"
            )
        
        # Actualizar contraseña en Supabase
        supabase_url = settings.SUPABASE_URL
        url = f"{supabase_url}/auth/v1/user"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "apikey": settings.SUPABASE_ANON_KEY
        }
        
        payload = {"password": request.new_password}
        
        async with httpx.AsyncClient() as http_client:
            put_response = await http_client.put(url, headers=headers, json=payload)
            
            if put_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Error al actualizar contraseña"
                )
        
        # ✅ Registrar en historial de contraseñas
        await security_service.record_password_history(user_id, new_password_hash)
        await security_service.cleanup_old_password_history(user_id, 20)
        
        # ✅ Actualizar fecha de expiración
        await security_service.update_password_expiry(user_id)
        
        # ✅ Invalidar todas las sesiones
        await security_service.invalidate_all_sessions(user_id)
        
        # ✅ Registrar evento de seguridad
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.PASSWORD_CHANGED,
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={"reason": "user_initiated", "force_logout": True}
        )
        
        # Enviar notificación por email
        if settings.should_send_email_notifications:
            try:
                detalles = {
                    "dispositivo": req.headers.get("User-Agent", "Dispositivo actual")[:100],
                    "ubicacion": "Ubicación desconocida",
                    "ip": req.client.host if req else "IP no registrada",
                    "metodo": "cambio de contraseña desde perfil"
                }
                
                await email_service.send_password_changed_notification(
                    to_email=user_email,
                    nombre=user_name,
                    detalles=detalles
                )
            except Exception as email_error:
                logger.warning(f"⚠️ No se pudo enviar notificación por email: {email_error}")
        
        return ChangePasswordResponse(
            message="Contraseña actualizada exitosamente. Todas tus sesiones han sido cerradas por seguridad.",
            sessions_closed=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error cambiando contraseña: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al cambiar contraseña: {str(e)}"
        )


# ============================================
# ✅ ENDPOINT: POLÍTICA DE CONTRASEÑAS (FASE 1)
# ============================================

@router.get("/password-policy")
async def get_password_policy_endpoint():
    """Obtiene la política actual de contraseñas."""
    try:
        policy = await security_service.get_password_policy()
        return policy
    except Exception as e:
        logger.error(f"Error obteniendo política: {e}")
        return {
            "max_age_days": 90,
            "prevent_reuse_count": 5,
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special_chars": True
        }


# ============================================
# ✅ ENDPOINT: VERIFICAR EXPIRACIÓN DE CONTRASEÑA
# ============================================

@router.get("/check-password-expiry")
async def check_password_expiry(current_user: dict = Depends(get_current_user)):
    """Verifica si la contraseña del usuario ha expirado."""
    user_id = current_user.get("sub")
    
    try:
        is_expired, days_remaining = await security_service.is_password_expired(user_id)
        
        return {
            "success": True,
            "is_expired": is_expired,
            "days_remaining": days_remaining,
            "requires_change": is_expired or (days_remaining is not None and days_remaining <= 7)
        }
    except Exception as e:
        logger.error(f"Error verificando expiración: {e}")
        return {
            "success": False,
            "is_expired": False,
            "days_remaining": None,
            "requires_change": False
        }


# ============================================
# ENDPOINTS OTP PARA LOGIN NORMAL
# ============================================

@router.post("/otp/send", response_model=OtpSendResponse)
async def send_otp_code(request: OtpSendRequest):
    """Envía un código OTP de 6 dígitos al email del usuario."""
    logger.info(f"📧 Solicitando código OTP para: {request.email}")
    
    clean_expired_otps()
    clean_rate_limit()
    
    time_since_restart = (datetime.now() - LAST_RESTART).total_seconds()
    if time_since_restart < 120:
        logger.info(f"🔄 Servidor recién iniciado (hace {time_since_restart:.0f}s), limpiando rate limits")
        otp_rate_limit.clear()
    
    if request.email in otp_storage:
        del otp_storage[request.email]
        logger.info(f"🗑️ Código anterior eliminado para {request.email}")
    
    if len(otp_rate_limit[request.email]) >= 3:
        oldest = min(otp_rate_limit[request.email])
        time_left = 3600 - (datetime.now() - oldest).seconds
        if time_left > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Has solicitado demasiados códigos. Espera {time_left // 60} minutos."
            )
    
    code = generate_otp_code()
    logger.info(f"🔢 Código generado: {code}")
    
    if not settings.validate_smtp_config():
        is_dev = "localhost" in settings.FRONTEND_URL or "127.0.0.1" in settings.FRONTEND_URL
        
        if is_dev or settings.ENVIRONMENT == "development":
            logger.warning(f"🔧 MODO DESARROLLO: Código OTP = {code}")
            otp_storage[request.email] = {
                "code": code,
                "expires_at": datetime.now() + timedelta(minutes=15),
                "attempts": 0
            }
            otp_rate_limit[request.email].append(datetime.now())
            
            return OtpSendResponse(
                message=f"🔧 [DEV] Código: {code} - Úsalo para probar",
                expires_in=900
            )
        else:
            logger.error("❌ Servicio de email no configurado en producción")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="El servicio de envío de correos no está disponible."
            )
    
    try:
        email_sent = await send_otp_email(request.email, code)
        
        if not email_sent:
            is_dev = "localhost" in settings.FRONTEND_URL or "127.0.0.1" in settings.FRONTEND_URL
            
            if is_dev or settings.ENVIRONMENT == "development":
                logger.warning(f"🔧 [DEV] Código OTP = {code} (email falló)")
                otp_storage[request.email] = {
                    "code": code,
                    "expires_at": datetime.now() + timedelta(minutes=15),
                    "attempts": 0
                }
                otp_rate_limit[request.email].append(datetime.now())
                return OtpSendResponse(
                    message=f"🔧 [DEV] Código: {code}",
                    expires_in=900
                )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No se pudo enviar el código de verificación. Verifica tu dirección de email o intenta más tarde."
            )
        
        otp_storage[request.email] = {
            "code": code,
            "expires_at": datetime.now() + timedelta(minutes=15),
            "attempts": 0
        }
        otp_rate_limit[request.email].append(datetime.now())
        
        logger.info(f"✅ Código OTP enviado a {request.email} (expira en 15 min)")
        
        return OtpSendResponse(
            message="Código enviado exitosamente. Revisa tu correo electrónico.",
            expires_in=900
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error inesperado en send_otp_code: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al procesar la solicitud: {str(e)}"
        )


@router.post("/otp/verify", response_model=OtpVerifyResponse)
async def verify_otp_code(request: OtpVerifyRequest, req: Request = None):
    """Verifica el código OTP y completa el inicio de sesión."""
    logger.info(f"🔐 Verificando código OTP para: {request.email}")
    
    clean_expired_otps()
    
    stored = otp_storage.get(request.email)
    
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No se encontró una solicitud de código para este email. Solicita un nuevo código."
        )
    
    if datetime.now() > stored["expires_at"]:
        del otp_storage[request.email]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El código ha expirado. Solicita uno nuevo."
        )
    
    if stored["attempts"] >= 5:
        del otp_storage[request.email]
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos fallidos. Solicita un nuevo código."
        )
    
    if stored["code"] != request.token:
        stored["attempts"] += 1
        remaining = 5 - stored["attempts"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Código incorrecto. Te quedan {remaining} intentos."
        )
    
    del otp_storage[request.email]
    
    user_id = None
    user_metadata = {}
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        try:
            users_response = admin_client.auth.admin.list_users()
            if users_response and hasattr(users_response, 'users') and users_response.users:
                for user in users_response.users:
                    if user.email == request.email:
                        user_id = user.id
                        user_metadata = user.user_metadata or {}
                        logger.info(f"✅ Usuario encontrado en auth.users: {user_id}")
                        break
        except Exception as e:
            logger.warning(f"⚠️ Error buscando en auth.users: {e}")
        
        if not user_id:
            logger.info(f"🔍 Buscando usuario en profiles: {request.email}")
            try:
                profile_response = admin_client.table("profiles").select("*").eq("email", request.email).execute()
                if profile_response and profile_response.data and len(profile_response.data) > 0:
                    profile = profile_response.data[0]
                    user_id = profile.get("id")
                    user_metadata = {
                        "username": profile.get("username"),
                        "full_name": profile.get("full_name"),
                        "avatar": profile.get("avatar"),
                        "banner": profile.get("banner"),
                        "bio": profile.get("bio")
                    }
                    logger.info(f"✅ Usuario encontrado en profiles: {user_id}")
            except Exception as e:
                logger.warning(f"⚠️ Error buscando en profiles: {e}")
        
        if not user_id:
            logger.warning(f"❌ Usuario {request.email} no encontrado en Supabase")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No se encontró una cuenta con este email. Por favor, regístrate primero."
            )
        
        from app.services.jwt_service import create_access_token, create_refresh_token
        
        token_username = user_metadata.get("username") or request.email.split('@')[0]
        token_full_name = user_metadata.get("full_name") or token_username
        token_avatar = user_metadata.get("avatar")
        
        access_token = create_access_token(
            subject=user_id,
            additional_claims={
                "email": request.email,
                "email_verified": True,
                "username": token_username,
                "full_name": token_full_name,
                "avatar": token_avatar,
                "user_metadata": user_metadata
            }
        )
        
        refresh_token = create_refresh_token(subject=user_id)
        
        # ✅ Registrar evento de seguridad: login OTP
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.LOGIN_SUCCESS,
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={"method": "otp"}
        )
        
        logger.info(f"✅ Login OTP exitoso para: {request.email} (user_id: {user_id})")
        
        return OtpVerifyResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=3600,
            user={
                "id": user_id,
                "email": request.email,
                "username": token_username,
                "full_name": token_full_name,
                "avatar": token_avatar,
                "email_verified": True
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en verify OTP: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al procesar la verificación: {str(e)}"
        )


# ============================================
# ENDPOINTS PARA 2FA (TOTP)
# ============================================

@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(
    request: TwoFactorSetupRequest,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """Inicia la configuración de 2FA para el usuario."""
    user_id = current_user.get("sub")
    user_email = current_user.get("email")
    
    logger.info(f"🔐 Iniciando configuración 2FA para usuario: {user_id}")
    
    try:
        client = supabase_auth.anon_client
        verification = client.auth.sign_in_with_password({
            "email": user_email,
            "password": request.password
        })
        if not verification or not verification.user:
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.TWO_FACTOR_FAILED,
                ip_address=req.client.host if req else None,
                user_agent=req.headers.get("User-Agent"),
                details={"reason": "incorrect_password"}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Contraseña incorrecta"
            )
    except Exception as e:
        logger.error(f"Error verificando contraseña: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Contraseña incorrecta"
        )
    
    try:
        admin_client = supabase_auth.get_admin_client()
        result = admin_client.table("user_two_factor").select("*").eq("user_id", user_id).execute()
        
        if result.data and len(result.data) > 0 and result.data[0].get("enabled"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="2FA ya está activado"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Error verificando estado 2FA: {e}")
    
    secret, qr_base64, provisioning_uri = two_factor_service.generate_secret(user_email)
    
    two_factor_setup_cache[user_id] = {
        "secret": secret,
        "expires_at": datetime.now() + timedelta(minutes=10)
    }
    
    logger.info(f"✅ Configuración 2FA iniciada para usuario: {user_id}")
    
    return TwoFactorSetupResponse(
        secret=secret,
        qr_code=qr_base64,
        provisioning_uri=provisioning_uri
    )


@router.post("/2fa/enable", response_model=TwoFactorEnableResponse)
async def enable_2fa(
    request: TwoFactorEnableRequest,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """Confirma y activa 2FA para el usuario."""
    user_id = current_user.get("sub")
    
    logger.info(f"🔐 Activando 2FA para usuario: {user_id}")
    
    setup_data = two_factor_setup_cache.get(user_id)
    if not setup_data or setup_data["expires_at"] < datetime.now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="La configuración expiró. Inicia nuevamente."
        )
    
    if not two_factor_service.verify_code(setup_data["secret"], request.code):
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.TWO_FACTOR_FAILED,
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={"reason": "invalid_code", "action": "enable"}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Código inválido"
        )
    
    recovery_codes = two_factor_service.generate_recovery_codes(10)
    
    admin_client = supabase_auth.get_admin_client()
    
    two_factor_data = {
        "user_id": user_id,
        "secret": setup_data["secret"],
        "enabled": True,
        "recovery_codes": [rc["hash"] for rc in recovery_codes],
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    try:
        admin_client.table("user_two_factor").insert(two_factor_data).execute()
        logger.info(f"✅ 2FA activado para usuario {user_id}")
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.TWO_FACTOR_ENABLED,
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={"method": "totp"}
        )
    except Exception as e:
        logger.error(f"Error guardando 2FA en tabla: {e}")
        try:
            user_data = await supabase_auth.get_user_by_id(user_id)
            user_metadata = user_data.get("user_metadata", {})
            user_metadata["two_factor_enabled"] = True
            user_metadata["two_factor_secret"] = setup_data["secret"]
            user_metadata["two_factor_recovery_hashes"] = [rc["hash"] for rc in recovery_codes]
            
            await supabase_auth.update_user(user_id, metadata=user_metadata)
            logger.info(f"✅ 2FA activado en metadata para usuario {user_id}")
        except Exception as e2:
            logger.error(f"Error guardando 2FA en metadata: {e2}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al guardar configuración 2FA"
            )
    
    del two_factor_setup_cache[user_id]
    
    return TwoFactorEnableResponse(
        message="2FA activado exitosamente",
        recovery_codes=[rc["code"] for rc in recovery_codes]
    )


@router.post("/2fa/verify", response_model=TwoFactorVerifyResponse)
async def verify_2fa(request: TwoFactorVerifyRequest, req: Request = None):
    """Verifica el código 2FA durante el login."""
    logger.info(f"🔐 Verificando 2FA para: {request.email}")
    
    try:
        client = supabase_auth.anon_client
        response = client.auth.sign_in_with_password({
            "email": request.email,
            "password": request.password
        })
        
        if not response or not response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Credenciales inválidas"
            )
        
        user_id = response.user.id
        user_metadata = response.user.user_metadata or {}
        
    except Exception as e:
        logger.error(f"Error en login: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Credenciales inválidas"
        )
    
    admin_client = supabase_auth.get_admin_client()
    secret = None
    
    try:
        result = admin_client.table("user_two_factor").select("*").eq("user_id", user_id).execute()
        if result.data and len(result.data) > 0:
            two_factor_data = result.data[0]
            if not two_factor_data.get("enabled"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, 
                    detail="2FA no está activado"
                )
            secret = two_factor_data.get("secret")
        else:
            user_data = await supabase_auth.get_user_by_id(user_id)
            user_metadata = user_data.get("user_metadata", {})
            if not user_metadata.get("two_factor_enabled"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, 
                    detail="2FA no está activado"
                )
            secret = user_metadata.get("two_factor_secret")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo 2FA: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="2FA no está configurado"
        )
    
    if not two_factor_service.verify_code(secret, request.code):
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.TWO_FACTOR_FAILED,
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={"reason": "invalid_code"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Código 2FA inválido"
        )
    
    from app.services.jwt_service import create_access_token, create_refresh_token
    
    username = user_metadata.get("username") or request.email.split('@')[0]
    full_name = user_metadata.get("full_name") or username
    avatar = user_metadata.get("avatar")
    
    access_token = create_access_token(
        subject=user_id,
        additional_claims={
            "email": request.email,
            "email_verified": True,
            "two_factor_verified": True,
            "username": username,
            "full_name": full_name,
            "avatar": avatar
        }
    )
    
    refresh_token = create_refresh_token(subject=user_id)
    
    await security_service.log_security_event(
        user_id=user_id,
        event_type=SecurityEventType.TWO_FACTOR_VERIFIED,
        ip_address=req.client.host if req else None,
        user_agent=req.headers.get("User-Agent"),
        details={"method": "totp"}
    )
    
    logger.info(f"✅ Login con 2FA exitoso para: {request.email}")
    
    return TwoFactorVerifyResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=3600,
        user={
            "id": user_id,
            "email": request.email,
            "username": username,
            "full_name": full_name,
            "avatar": avatar,
            "email_verified": True
        }
    )


@router.post("/2fa/disable")
async def disable_2fa(
    request: TwoFactorDisableRequest,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """Desactiva 2FA para el usuario."""
    user_id = current_user.get("sub")
    user_email = current_user.get("email")
    
    logger.info(f"🔐 Desactivando 2FA para usuario: {user_id}")
    
    try:
        client = supabase_auth.anon_client
        verification = client.auth.sign_in_with_password({
            "email": user_email,
            "password": request.password
        })
        if not verification or not verification.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Contraseña incorrecta"
            )
    except Exception as e:
        logger.error(f"Error verificando contraseña: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Contraseña incorrecta"
        )
    
    admin_client = supabase_auth.get_admin_client()
    
    try:
        result = admin_client.table("user_two_factor").select("*").eq("user_id", user_id).execute()
        if result.data and len(result.data) > 0:
            secret = result.data[0].get("secret")
            if not two_factor_service.verify_code(secret, request.code):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    detail="Código 2FA inválido"
                )
            
            admin_client.table("user_two_factor").update({
                "enabled": False,
                "updated_at": datetime.now().isoformat()
            }).eq("user_id", user_id).execute()
            
            logger.info(f"✅ 2FA desactivado para usuario {user_id}")
        else:
            user_data = await supabase_auth.get_user_by_id(user_id)
            user_metadata = user_data.get("user_metadata", {})
            secret = user_metadata.get("two_factor_secret")
            
            if not two_factor_service.verify_code(secret, request.code):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    detail="Código 2FA inválido"
                )
            
            user_metadata["two_factor_enabled"] = False
            await supabase_auth.update_user(user_id, metadata=user_metadata)
            logger.info(f"✅ 2FA desactivado en metadata para usuario {user_id}")
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.TWO_FACTOR_DISABLED,
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={"reason": "user_initiated"}
        )
        
        return {"message": "2FA desactivado exitosamente"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error desactivando 2FA: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al desactivar 2FA"
        )


@router.get("/2fa/status", response_model=TwoFactorStatusResponse)
async def get_2fa_status(
    current_user: dict = Depends(get_current_user)
):
    """Obtiene el estado de 2FA del usuario actual."""
    user_id = current_user.get("sub")
    
    logger.info(f"🔐 Consultando estado 2FA para usuario: {user_id}")
    
    admin_client = supabase_auth.get_admin_client()
    
    try:
        result = admin_client.table("user_two_factor").select("*").eq("user_id", user_id).execute()
        
        if result.data and len(result.data) > 0:
            two_factor_data = result.data[0]
            enabled = two_factor_data.get("enabled", False)
            has_codes = bool(two_factor_data.get("recovery_codes"))
            return TwoFactorStatusResponse(
                enabled=enabled,
                has_recovery_codes=has_codes
            )
        else:
            user_data = await supabase_auth.get_user_by_id(user_id)
            if user_data:
                user_metadata = user_data.get("user_metadata", {})
                enabled = user_metadata.get("two_factor_enabled", False)
                has_codes = bool(user_metadata.get("two_factor_recovery_hashes"))
                return TwoFactorStatusResponse(
                    enabled=enabled,
                    has_recovery_codes=has_codes
                )
            else:
                return TwoFactorStatusResponse(enabled=False, has_recovery_codes=False)
                
    except Exception as e:
        logger.error(f"❌ Error obteniendo estado 2FA: {e}", exc_info=True)
        return TwoFactorStatusResponse(enabled=False, has_recovery_codes=False)


# ============================================
# ENDPOINTS DE DIAGNÓSTICO
# ============================================

@router.get("/debug/check", response_model=DebugCheckResponse)
async def debug_check():
    """Endpoint de diagnóstico para verificar la configuración de autenticación"""
    return DebugCheckResponse(
        supabase_configured=supabase_auth.is_available(),
        message="Supabase Auth está configurado" if supabase_auth.is_available() else "Supabase Auth NO está configurado"
    )