# app/routers/auth.py
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any, List
from app.services.supabase_auth_service import supabase_auth
from app.services.email_service import email_service
from app.services.two_factor_service import two_factor_service, two_factor_setup_cache
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
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])
logger = logging.getLogger(__name__)

# ✅ AGREGAR ESTA LÍNEA - Variable para detectar reinicio del servidor
LAST_RESTART = datetime.now()

# ============================================
# ALMACENAMIENTO TEMPORAL OTP
# ============================================

# Almacenamiento temporal de códigos OTP (en producción usar Redis o Supabase)
# Formato: { "email": {"code": "123456", "expires_at": datetime, "attempts": 0} }
otp_storage: Dict[str, dict] = {}
# Rate limiting por email (evita spam)
otp_rate_limit: Dict[str, list] = defaultdict(list)


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


async def send_otp_email(to_email: str, code: str) -> bool:
    """
    Envía el código OTP por email usando el servicio de email existente.
    ✅ CORREGIDO: Ahora retorna bool para saber si el envío fue exitoso.
    """
    try:
        # Obtener nombre del usuario si existe
        user_name = to_email.split('@')[0]
        
        # Intentar obtener nombre del usuario si ya existe en Supabase
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
        
        # Usar la plantilla HTML
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
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#f8fafc; border-radius:16px; padding:20px; margin:32px 0;">
                                        <tr>
                                            <td>
                                                <div style="margin:12px 0; display:flex; align-items:center; gap:12px;">
                                                    <span style="background:#10B981; border-radius:50%; width:28px; height:28px; display:inline-flex; align-items:center; justify-content:center; color:white;">⏰</span>
                                                    <span>Este código expirará en <strong>15 minutos</strong></span>
                                                </div>
                                                <div style="margin:12px 0; display:flex; align-items:center; gap:12px;">
                                                    <span style="background:#10B981; border-radius:50%; width:28px; height:28px; display:inline-flex; align-items:center; justify-content:center; color:white;">🔒</span>
                                                    <span>Si no solicitaste este código, ignora este mensaje</span>
                                                </div>
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
        
        # ✅ CORREGIDO: Ahora verificamos si el envío fue exitoso
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
            logger.error(f"❌ Error enviando email OTP a {to_email}: El servicio de email retornó False")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error enviando email OTP: {e}")
        return False


# ============================================
# FUNCIONES AUXILIARES EXISTENTES
# ============================================

def hash_password(password: str) -> str:
    """Genera un hash SHA-256 de la contraseña para almacenar en historial"""
    return hashlib.sha256(password.encode()).hexdigest()


async def check_password_reused(user_id: str, new_password: str) -> bool:
    """
    Verifica si la nueva contraseña ya ha sido utilizada anteriormente
    Retorna True si ya fue usada, False si es nueva
    """
    try:
        supabase_url = settings.SUPABASE_URL
        service_key = settings.SUPABASE_SERVICE_KEY
        
        url = f"{supabase_url}/rest/v1/password_history"
        
        headers = {
            "Authorization": f"Bearer {service_key}",
            "Content-Type": "application/json",
            "apikey": service_key
        }
        
        params = {
            "user_id": f"eq.{user_id}",
            "order": "created_at.desc",
            "limit": 10
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                history = response.json()
                new_hash = hash_password(new_password)
                
                for record in history:
                    if record.get("password_hash") == new_hash:
                        logger.warning(f"⚠️ Usuario {user_id} intentó reutilizar contraseña anterior")
                        return True
            
            return False
            
    except Exception as e:
        logger.warning(f"⚠️ Error verificando historial de contraseñas: {e}")
        return False


async def save_password_history(user_id: str, password: str):
    """Guarda la contraseña en el historial"""
    try:
        supabase_url = settings.SUPABASE_URL
        service_key = settings.SUPABASE_SERVICE_KEY
        
        url = f"{supabase_url}/rest/v1/password_history"
        
        headers = {
            "Authorization": f"Bearer {service_key}",
            "Content-Type": "application/json",
            "apikey": service_key,
            "Prefer": "return=minimal"
        }
        
        password_hash = hash_password(password)
        
        data = {
            "user_id": user_id,
            "password_hash": password_hash,
            "created_at": "now()"
        }
        
        async with httpx.AsyncClient() as client:
            await client.post(url, headers=headers, json=data)
            logger.debug(f"✅ Contraseña guardada en historial para usuario: {user_id}")
            
    except Exception as e:
        logger.warning(f"⚠️ Error guardando historial de contraseña: {e}")


# ============================================
# ENDPOINTS DE AUTENTICACIÓN EXISTENTES
# ============================================

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: RegisterRequest):
    """
    Registra un nuevo usuario usando Supabase Auth
    """
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
async def login(credentials: LoginRequest):
    """
    Inicia sesión usando Supabase Auth
    Soporta autenticación normal y 2FA
    """
    logger.info(f"📝 Intentando login para: {credentials.email}")
    
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
        
        response = client.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })
        
        if not response or not response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas"
            )
        
        if not response.user.email_confirmed_at:
            logger.warning(f"⚠️ Intento de login con email no verificado: {credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Por favor verifica tu email antes de iniciar sesión. Revisa tu bandeja de entrada."
            )
        
        # Verificar si el usuario tiene 2FA activado
        user_id = response.user.id
        admin_client = supabase_auth.get_admin_client()
        requires_2fa = False
        
        try:
            result = admin_client.table("user_two_factor").select("enabled").eq("user_id", user_id).execute()
            if result.data and len(result.data) > 0:
                requires_2fa = result.data[0].get("enabled", False)
        except Exception as e:
            logger.warning(f"⚠️ Error verificando 2FA: {e}")
        
        # Si tiene 2FA activado, devolver respuesta especial (no generar token aún)
        if requires_2fa:
            logger.info(f"🔐 Usuario {credentials.email} requiere 2FA")
            
            # ✅ OBTENER DATOS DEL USUARIO PARA MOSTRAR EN PANTALLA 2FA
            user_metadata = response.user.user_metadata or {}
            
            return LoginResponse(
                requires_2fa=True,
                message="Se requiere código de verificación 2FA",
                user_id=user_id,
                user={
                    "id": user_id,
                    "email": credentials.email,
                    "username": user_metadata.get("username") or credentials.email.split("@")[0],
                    "full_name": user_metadata.get("full_name"),  # ✅ INCLUIR FULL_NAME
                    "avatar": user_metadata.get("avatar")         # ✅ INCLUIR AVATAR
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
            "avatar": user_metadata.get("avatar"),  # ✅ INCLUIR AVATAR
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
async def logout(request: RefreshTokenRequest):
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


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
async def forgot_password(request: ForgotPasswordRequest):
    """Solicita recuperación de contraseña"""
    logger.info(f"📧 Solicitud de recuperación para: {request.email}")
    
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
        
        redirect_url = f"{settings.FRONTEND_URL}/reset-password"
        
        client.auth.reset_password_for_email(
            request.email,
            options={
                "redirect_to": redirect_url
            }
        )
        
        logger.info(f"✅ Email de recuperación enviado a: {request.email}")
        
        return ForgotPasswordResponse(
            message="Si el email existe en nuestro sistema, recibirás instrucciones para restablecer tu contraseña."
        )
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ Error en forgot-password: {error_msg}")
        
        return ForgotPasswordResponse(
            message="Si el email existe en nuestro sistema, recibirás instrucciones para restablecer tu contraseña."
        )


@router.post("/reset-password", response_model=ResetPasswordResponse)
async def reset_password(request: ResetPasswordRequest):
    """
    Restablece la contraseña usando el token recibido por email
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
            
            is_reused = await check_password_reused(user_id, request.new_password)
            
            if is_reused:
                logger.warning(f"⚠️ Intento de reutilizar contraseña anterior para usuario: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No puedes usar una contraseña que hayas utilizado anteriormente. Por favor, elige una contraseña nueva."
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
            
            version_incremented = await supabase_auth.increment_token_version(user_id)
            if version_incremented:
                logger.info(f"✅ Token_version incrementado para usuario {user_id}")
            else:
                logger.warning(f"⚠️ No se pudo incrementar token_version para {user_id}")
            
            await save_password_history(user_id, request.new_password)
            
            logger.info(f"✅ Contraseña actualizada exitosamente para usuario ID: {user_id}")
            
            try:
                detalles = {
                    "dispositivo": "Navegador web",
                    "ubicacion": "Ubicación desconocida",
                    "ip": "IP no registrada",
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


@router.post("/change-password", response_model=ChangePasswordResponse)
async def change_password(
    request: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
    token: str = Depends(get_auth_token)
):
    """Cambia la contraseña del usuario autenticado"""
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
        
        try:
            verification = client.auth.sign_in_with_password({
                "email": user_email,
                "password": request.current_password
            })
            
            if not verification or not verification.user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="La contraseña actual es incorrecta"
                )
        except Exception as e:
            error_msg = str(e)
            if "Invalid login credentials" in error_msg:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="La contraseña actual es incorrecta"
                )
            raise
        
        if request.current_password == request.new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La nueva contraseña debe ser diferente a la actual"
            )
        
        is_reused = await check_password_reused(user_id, request.new_password)
        
        if is_reused:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No puedes usar una contraseña que hayas utilizado anteriormente."
            )
        
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
        
        version_incremented = await supabase_auth.increment_token_version(user_id)
        if version_incremented:
            logger.info(f"✅ Token_version incrementado para usuario {user_id}")
        
        await save_password_history(user_id, request.new_password)
        
        if settings.should_send_email_notifications:
            try:
                detalles = {
                    "dispositivo": "Dispositivo actual",
                    "ubicacion": "Ubicación desconocida",
                    "ip": "IP no registrada",
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
# ✅ ENDPOINT OTP CORREGIDO - VERSIÓN FINAL
# ============================================

@router.post("/otp/send", response_model=OtpSendResponse)
async def send_otp_code(request: OtpSendRequest):
    """
    Envía un código OTP de 6 dígitos al email del usuario.
    """
    logger.info(f"📧 Solicitando código OTP para: {request.email}")
    
    # Limpiar datos expirados
    clean_expired_otps()
    clean_rate_limit()
    
    # ✅ NUEVO: Resetear rate limiting si el servidor se acaba de iniciar (menos de 2 minutos)
    time_since_restart = (datetime.now() - LAST_RESTART).total_seconds()
    if time_since_restart < 120:
        logger.info(f"🔄 Servidor recién iniciado (hace {time_since_restart:.0f}s), limpiando rate limits")
        otp_rate_limit.clear()
    
    # Limpiar cualquier código existente para este email
    if request.email in otp_storage:
        del otp_storage[request.email]
        logger.info(f"🗑️ Código anterior eliminado para {request.email}")
    
    # Rate limiting: máximo 3 solicitudes por hora
    if len(otp_rate_limit[request.email]) >= 3:
        oldest = min(otp_rate_limit[request.email])
        time_left = 3600 - (datetime.now() - oldest).seconds
        if time_left > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Has solicitado demasiados códigos. Espera {time_left // 60} minutos."
            )
    
    # ✅ PRIMERO: Generar el código (antes de cualquier validación)
    code = generate_otp_code()
    logger.info(f"🔢 Código generado: {code}")
    
    # ✅ SEGUNDO: Verificar SMTP
    if not settings.validate_smtp_config():
        logger.warning(f"⚠️ SMTP no configurado correctamente")
        logger.warning(f"   SMTP_HOST: {settings.SMTP_HOST}")
        logger.warning(f"   SMTP_PORT: {settings.SMTP_PORT}")
        logger.warning(f"   SMTP_USER: {settings.SMTP_USER}")
        logger.warning(f"   SMTP_FROM: {settings.SMTP_FROM}")
        logger.warning(f"   SMTP_PASSWORD: {'***' if settings.SMTP_PASSWORD else 'NO CONFIGURADA'}")
        
        # En desarrollo local, permitir continuar sin SMTP
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
    
    # ✅ TERCERO: SMTP configurado - Enviar email
    logger.info(f"📧 Enviando código OTP a {request.email}...")
    
    try:
        email_sent = await send_otp_email(request.email, code)
        
        if not email_sent:
            logger.error(f"❌ No se pudo enviar el email OTP a {request.email}")
            
            # En desarrollo, guardar código aunque falle el email
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
        
        # ✅ Email enviado exitosamente
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
async def verify_otp_code(request: OtpVerifyRequest):
    """
    Verifica el código OTP y completa el inicio de sesión.
    Para usuarios existentes, genera tokens JWT usando el ID real de Supabase.
    """
    logger.info(f"🔐 Verificando código OTP para: {request.email}")
    
    # Limpiar datos expirados
    clean_expired_otps()
    
    # Verificar si existe solicitud de código
    stored = otp_storage.get(request.email)
    
    if not stored:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No se encontró una solicitud de código para este email. Solicita un nuevo código."
        )
    
    # Verificar expiración
    if datetime.now() > stored["expires_at"]:
        del otp_storage[request.email]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El código ha expirado. Solicita uno nuevo."
        )
    
    # Verificar intentos
    if stored["attempts"] >= 5:
        del otp_storage[request.email]
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos fallidos. Solicita un nuevo código."
        )
    
    # Verificar código
    if stored["code"] != request.token:
        stored["attempts"] += 1
        remaining = 5 - stored["attempts"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Código incorrecto. Te quedan {remaining} intentos."
        )
    
    # Código correcto - limpiar almacenamiento
    del otp_storage[request.email]
    
    # ============================================
    # OBTENER USUARIO REAL DE LA BASE DE DATOS
    # ============================================
    user_id = None
    user_metadata = {}
    
    try:
        # Buscar el usuario en la tabla profiles usando el email
        admin_client = supabase_auth.get_admin_client()
        
        # Buscar en la tabla profiles (pública)
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
            logger.info(f"✅ Usuario encontrado en tabla profiles: {user_id}")
        
        # Si no se encontró en profiles, buscar en auth.users
        if not user_id:
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
        
        # Si aún no se encontró, crear usuario nuevo
        if not user_id:
            logger.info(f"📝 Usuario no existe, creando nuevo: {request.email}")
            
            username = request.email.split('@')[0]
            
            try:
                new_user = admin_client.auth.admin.create_user({
                    "email": request.email,
                    "email_confirm": True,
                    "user_metadata": {
                        "username": username,
                        "full_name": username,
                        "token_version": 1
                    }
                })
                
                user_id = new_user.user.id
                user_metadata = {"username": username, "full_name": username}
                logger.info(f"✅ Usuario creado: {user_id}")
                
                # Crear perfil
                try:
                    profile_data = {
                        "id": user_id,
                        "email": request.email,
                        "username": username,
                        "full_name": username,
                        "created_at": datetime.now().isoformat()
                    }
                    admin_client.table("profiles").insert(profile_data).execute()
                    logger.info(f"✅ Perfil creado")
                except Exception as e:
                    logger.warning(f"⚠️ No se pudo crear perfil: {e}")
                    
            except Exception as e:
                error_msg = str(e)
                logger.error(f"❌ Error creando usuario: {error_msg}")
                
                if "already been registered" in error_msg.lower():
                    # Último intento: consultar directamente la tabla auth.users con SQL
                    try:
                        sql_query = f"SELECT id, raw_user_meta_data FROM auth.users WHERE email = '{request.email}'"
                        result = admin_client.rpc('exec_sql', {'query': sql_query})
                        if result and result.data and len(result.data) > 0:
                            user_id = result.data[0].get("id")
                            user_metadata = result.data[0].get("raw_user_meta_data", {})
                            logger.info(f"✅ Usuario recuperado vía SQL: {user_id}")
                    except Exception as sql_error:
                        logger.error(f"❌ Error SQL: {sql_error}")
                
                if not user_id:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="No se pudo iniciar sesión. Por favor, inicia sesión con tu email y contraseña."
                    )
        
        # ============================================
        # VERIFICAR QUE TENEMOS USER_ID
        # ============================================
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se pudo identificar al usuario. Por favor, inicia sesión con tu email y contraseña."
            )
        
        # ============================================
        # GENERAR TOKENS JWT
        # ============================================
        from app.services.jwt_service import create_access_token, create_refresh_token
        
        token_username = user_metadata.get("username") or request.email.split('@')[0]
        token_full_name = user_metadata.get("full_name") or token_username
        token_avatar = user_metadata.get("avatar")  # ✅ OBTENER AVATAR
        
        access_token = create_access_token(
            subject=user_id,
            additional_claims={
                "email": request.email,
                "email_verified": True,
                "username": token_username,
                "full_name": token_full_name,
                "avatar": token_avatar,  # ✅ INCLUIR AVATAR
                "user_metadata": user_metadata
            }
        )
        
        refresh_token = create_refresh_token(subject=user_id)
        
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
                "avatar": token_avatar,  # ✅ INCLUIR AVATAR
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
    current_user: dict = Depends(get_current_user)
):
    """
    Inicia la configuración de 2FA para el usuario.
    Requiere contraseña actual para verificar identidad.
    """
    user_id = current_user.get("sub")
    user_email = current_user.get("email")
    
    logger.info(f"🔐 Iniciando configuración 2FA para usuario: {user_id}")
    
    # Verificar contraseña actual
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
    
    # Verificar si el usuario ya tiene 2FA activado
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
    
    # Generar secreto y QR
    secret, qr_base64, provisioning_uri = two_factor_service.generate_secret(user_email)
    
    # Guardar secreto temporalmente (expira en 10 minutos)
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
    current_user: dict = Depends(get_current_user)
):
    """
    Confirma y activa 2FA para el usuario.
    Verifica el código TOTP y genera códigos de respaldo.
    """
    user_id = current_user.get("sub")
    
    logger.info(f"🔐 Activando 2FA para usuario: {user_id}")
    
    # Verificar que existe una configuración pendiente
    setup_data = two_factor_setup_cache.get(user_id)
    if not setup_data or setup_data["expires_at"] < datetime.now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="La configuración expiró. Inicia nuevamente."
        )
    
    # Verificar el código
    if not two_factor_service.verify_code(setup_data["secret"], request.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Código inválido"
        )
    
    # Generar códigos de respaldo
    recovery_codes = two_factor_service.generate_recovery_codes(10)
    
    # Guardar en la base de datos
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
        # Intentar insertar en la tabla user_two_factor
        admin_client.table("user_two_factor").insert(two_factor_data).execute()
        logger.info(f"✅ 2FA activado para usuario {user_id}")
    except Exception as e:
        logger.error(f"Error guardando 2FA en tabla: {e}")
        # Fallback: guardar en user_metadata
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
    
    # Limpiar cache
    del two_factor_setup_cache[user_id]
    
    return TwoFactorEnableResponse(
        message="2FA activado exitosamente",
        recovery_codes=[rc["code"] for rc in recovery_codes]
    )


@router.post("/2fa/verify", response_model=TwoFactorVerifyResponse)
async def verify_2fa(request: TwoFactorVerifyRequest):
    """
    Verifica el código 2FA durante el login.
    Este endpoint se usa después de que el usuario ingresó sus credenciales.
    ✅ AHORA RETORNA AVATAR Y FULL_NAME DEL USUARIO
    """
    logger.info(f"🔐 Verificando 2FA para: {request.email}")
    
    # Primero, validar credenciales normales
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
    
    # Obtener secreto 2FA del usuario
    admin_client = supabase_auth.get_admin_client()
    secret = None
    
    try:
        # Intentar obtener de tabla user_two_factor
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
            # Fallback: obtener de user_metadata
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
    
    # Verificar código
    if not two_factor_service.verify_code(secret, request.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Código 2FA inválido"
        )
    
    # Login exitoso - generar tokens JWT
    from app.services.jwt_service import create_access_token, create_refresh_token
    
    # ✅ OBTENER DATOS COMPLETOS DEL USUARIO (AVATAR, FULL_NAME)
    username = user_metadata.get("username") or request.email.split('@')[0]
    full_name = user_metadata.get("full_name") or username
    avatar = user_metadata.get("avatar")  # ✅ OBTENER AVATAR
    
    logger.info(f"📸 Usuario {request.email} - Avatar: {'Sí' if avatar else 'No'}, Full Name: {full_name}")
    
    access_token = create_access_token(
        subject=user_id,
        additional_claims={
            "email": request.email,
            "email_verified": True,
            "two_factor_verified": True,
            "username": username,
            "full_name": full_name,
            "avatar": avatar  # ✅ INCLUIR AVATAR EN EL TOKEN
        }
    )
    
    refresh_token = create_refresh_token(subject=user_id)
    
    logger.info(f"✅ Login con 2FA exitoso para: {request.email}")
    
    return TwoFactorVerifyResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=3600,
        user={
            "id": user_id,
            "email": request.email,
            "username": username,
            "full_name": full_name,  # ✅ INCLUIR FULL_NAME
            "avatar": avatar,        # ✅ INCLUIR AVATAR
            "email_verified": True
        }
    )


@router.post("/2fa/disable")
async def disable_2fa(
    request: TwoFactorDisableRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Desactiva 2FA para el usuario.
    Requiere contraseña y código 2FA para confirmar.
    """
    user_id = current_user.get("sub")
    user_email = current_user.get("email")
    
    logger.info(f"🔐 Desactivando 2FA para usuario: {user_id}")
    
    # Verificar contraseña
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
    
    # Verificar código 2FA y desactivar
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
            
            # Desactivar en tabla (soft delete)
            admin_client.table("user_two_factor").update({
                "enabled": False,
                "updated_at": datetime.now().isoformat()
            }).eq("user_id", user_id).execute()
            
            logger.info(f"✅ 2FA desactivado para usuario {user_id}")
        else:
            # Fallback: usar metadata
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
    """
    Obtiene el estado de 2FA del usuario actual.
    """
    user_id = current_user.get("sub")
    
    logger.info(f"🔐 Consultando estado 2FA para usuario: {user_id}")
    
    admin_client = supabase_auth.get_admin_client()
    
    try:
        # Intentar obtener de tabla user_two_factor
        result = admin_client.table("user_two_factor").select("*").eq("user_id", user_id).execute()
        if result.data and len(result.data) > 0:
            return TwoFactorStatusResponse(
                enabled=result.data[0].get("enabled", False),
                has_recovery_codes=bool(result.data[0].get("recovery_codes"))
            )
        else:
            # Fallback: obtener de user_metadata
            user_data = await supabase_auth.get_user_by_id(user_id)
            user_metadata = user_data.get("user_metadata", {})
            return TwoFactorStatusResponse(
                enabled=user_metadata.get("two_factor_enabled", False),
                has_recovery_codes=bool(user_metadata.get("two_factor_recovery_hashes"))
            )
    except Exception as e:
        logger.error(f"Error obteniendo estado 2FA: {e}")
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