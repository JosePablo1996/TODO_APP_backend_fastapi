# app/routers/webauthn.py
"""
Router para endpoints de WebAuthn/Passkeys
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import Dict, Any, List
import logging
from datetime import datetime, timedelta
import uuid

# Importar modelos desde app.models
from app.models import (
    WebAuthnRegistrationBeginRequest,
    WebAuthnRegistrationBeginResponse,
    WebAuthnRegistrationCompleteRequest,
    WebAuthnRegistrationCompleteResponse,
    WebAuthnLoginBeginRequest,
    WebAuthnLoginBeginResponse,
    WebAuthnLoginCompleteRequest,
    WebAuthnLoginCompleteResponse,
    WebAuthnCredentialResponse,
    WebAuthnDeleteRequest
)
from app.services.webauthn_service import webauthn_service
from app.services.supabase_auth_service import supabase_auth
from app.services.session_service import session_service
from app.services.security_service import security_service, SecurityEventType
from app.dependencies import get_current_user
from app.config import settings

router = APIRouter(prefix="/api/webauthn", tags=["webauthn", "passkeys"])
logger = logging.getLogger(__name__)

# Almacenamiento temporal para challenges (en producción usar Redis)
_challenge_store = {}


# ============================================
# FUNCIONES AUXILIARES PARA PARSEAR DISPOSITIVOS
# ============================================

def _parse_browser(user_agent: str) -> str:
    """Parsea el navegador del User-Agent"""
    if not user_agent:
        return "Desconocido"
    
    ua = user_agent.lower()
    
    if "chrome" in ua and "edg" not in ua and "opr" not in ua:
        return "Chrome"
    elif "firefox" in ua:
        return "Firefox"
    elif "safari" in ua and "chrome" not in ua:
        return "Safari"
    elif "edg" in ua:
        return "Edge"
    elif "opr" in ua or "opera" in ua:
        return "Opera"
    elif "brave" in ua:
        return "Brave"
    else:
        return "Desconocido"


def _parse_os(user_agent: str) -> str:
    """Parsea el sistema operativo del User-Agent"""
    if not user_agent:
        return "Desconocido"
    
    ua = user_agent.lower()
    
    if "windows" in ua:
        return "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        return "macOS"
    elif "linux" in ua:
        return "Linux"
    elif "android" in ua:
        return "Android"
    elif "ios" in ua or "iphone" in ua or "ipad" in ua:
        return "iOS"
    else:
        return "Desconocido"


def _parse_device_info(user_agent: str, ip_address: str) -> Dict[str, Any]:
    """Parsea información completa del dispositivo"""
    ua = user_agent.lower() if user_agent else ""
    
    # Detectar tipo de dispositivo
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        device_type = "mobile"
    elif "tablet" in ua or "ipad" in ua:
        device_type = "tablet"
    elif "windows" in ua or "mac" in ua or "linux" in ua:
        device_type = "desktop"
    else:
        device_type = "web"
    
    # Detectar marca (simplificado)
    device_brand = None
    device_model = None
    
    if "apple" in ua or "iphone" in ua or "ipad" in ua or "mac" in ua:
        device_brand = "Apple"
    elif "samsung" in ua:
        device_brand = "Samsung"
    elif "xiaomi" in ua:
        device_brand = "Xiaomi"
    elif "huawei" in ua:
        device_brand = "Huawei"
    elif "google" in ua or "pixel" in ua:
        device_brand = "Google"
    elif "oneplus" in ua:
        device_brand = "OnePlus"
    elif "lenovo" in ua:
        device_brand = "Lenovo"
    elif "dell" in ua:
        device_brand = "Dell"
    elif "hp" in ua:
        device_brand = "HP"
    elif "asus" in ua:
        device_brand = "ASUS"
    
    # Detectar modelo (simplificado)
    if device_brand == "Apple":
        if "iphone" in ua:
            device_model = "iPhone"
        elif "ipad" in ua:
            device_model = "iPad"
        elif "mac" in ua:
            device_model = "Mac"
    elif device_brand == "Samsung":
        if "galaxy" in ua:
            device_model = "Galaxy"
    elif device_brand == "Google":
        if "pixel" in ua:
            device_model = "Pixel"
    
    # Detectar navegador
    browser = _parse_browser(user_agent)
    
    # Detectar SO
    os = _parse_os(user_agent)
    
    # Nombre del dispositivo
    device_name = f"{device_brand or ''} {device_model or ''}".strip() or "Dispositivo Desconocido"
    
    return {
        "device_name": device_name,
        "device_type": device_type,
        "device_brand": device_brand,
        "device_model": device_model,
        "browser": browser,
        "os": os,
        "location": "Ubicación desconocida"
    }


@router.post("/register/begin")
async def register_begin(
    request: WebAuthnRegistrationBeginRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Inicia el proceso de registro de una nueva passkey
    
    - Requiere usuario autenticado
    - Retorna las opciones para que el frontend cree la passkey
    """
    user_id = current_user.get("sub")
    email = current_user.get("email")
    username = current_user.get("username") or email.split("@")[0]

    logger.info(f"🔑 Iniciando registro de passkey para usuario: {user_id}")
    logger.info(f"   Email: {email}")
    logger.info(f"   Username: {username}")

    try:
        # Generar opciones de registro
        options = await webauthn_service.generate_registration_options(
            user_id=user_id,
            email=email,
            username=username,
            device_name=request.device_name
        )

        # Guardar challenge temporalmente (asociado al usuario)
        _challenge_store[user_id] = {
            "challenge": options["challenge"],
            "timestamp": datetime.now().timestamp()
        }

        logger.info(f"✅ Opciones de registro generadas para usuario: {user_id}")

        return options

    except Exception as e:
        logger.error(f"❌ Error iniciando registro de passkey: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al iniciar registro: {str(e)}"
        )


@router.post("/register/complete", response_model=WebAuthnRegistrationCompleteResponse)
async def register_complete(
    request: WebAuthnRegistrationCompleteRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    req: Request = None
):
    """
    Completa el registro de una passkey
    
    - Verifica la respuesta del autenticador
    - Almacena la credencial en Supabase
    """
    user_id = current_user.get("sub")

    logger.info(f"🔐 Completando registro de passkey para usuario: {user_id}")

    # Obtener challenge almacenado
    stored = _challenge_store.get(user_id)
    if not stored:
        logger.warning(f"⚠️ No se encontró challenge para usuario: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No hay registro en progreso o el challenge ha expirado"
        )

    challenge = stored["challenge"]
    logger.info(f"   Challenge encontrado, verificando respuesta...")

    try:
        # Verificar la respuesta de registro
        verified, credential_data, error = await webauthn_service.verify_registration(
            user_id=user_id,
            credential_id=request.credential_id,
            client_data_json=request.client_data_json,
            attestation_object=request.attestation_object,
            challenge=challenge
        )

        if not verified:
            logger.error(f"❌ Verificación fallida: {error}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Verificación fallida: {error}"
            )

        # Guardar credencial en base de datos
        saved = await webauthn_service.save_credential(
            user_id=user_id,
            credential_id=request.credential_id,
            public_key=credential_data["public_key"],
            sign_count=credential_data["sign_count"],
            device_name=request.device_name or current_user.get("username"),
            device_type=request.device_type
        )

        if not saved:
            logger.error(f"❌ Error al guardar credencial en base de datos")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al guardar la credencial"
            )

        # ✅ Registrar cambio de seguridad: Passkey registrada
        ip_address = req.client.host if req else "unknown"
        user_agent = req.headers.get("User-Agent", "Desconocido")
        device_info = _parse_device_info(user_agent, ip_address)
        
        await session_service.add_security_change(
            user_id=user_id,
            change_type="passkey_register",
            ip_address=ip_address,
            location=device_info.get("location", "Desconocida"),
            details={
                "device_name": request.device_name,
                "credential_id": request.credential_id
            }
        )
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type="PASSKEY_REGISTERED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "device_name": request.device_name,
                "credential_id": request.credential_id
            }
        )

        # Limpiar challenge almacenado
        del _challenge_store[user_id]

        logger.info(f"✅ Passkey registrada exitosamente para usuario: {user_id}")

        return WebAuthnRegistrationCompleteResponse(
            success=True,
            credential_id=request.credential_id,
            message="Passkey registrada exitosamente"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error completando registro: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al completar registro: {str(e)}"
        )


@router.post("/login/begin", response_model=WebAuthnLoginBeginResponse)
async def login_begin(
    request: WebAuthnLoginBeginRequest,
    request_obj: Request
):
    """
    Inicia el proceso de login con passkey
    
    - Si se proporciona email, busca el usuario
    - Retorna las opciones para autenticación
    """
    logger.info(f"🔑 Iniciando login con passkey")
    logger.info(f"   Email proporcionado: {request.email}")
    logger.info(f"   RP ID configurado: {webauthn_service.rp_id}")
    logger.info(f"   Origin configurado: {webauthn_service.origin}")

    try:
        allowed_credentials = []
        user_id = None

        # Si se proporcionó email, buscar usuario
        if request.email:
            logger.info(f"   Buscando usuario por email: {request.email}")
            if supabase_auth.is_available():
                try:
                    admin_client = supabase_auth.get_admin_client()
                    response = admin_client.auth.admin.list_users()
                    users = response.users if hasattr(response, 'users') else []
                    
                    for user in users:
                        if user.email == request.email:
                            user_id = user.id
                            logger.info(f"   ✅ Usuario encontrado: {user_id}")
                            credentials = await webauthn_service.get_user_credentials(user_id)
                            allowed_credentials = credentials
                            logger.info(f"   Credenciales encontradas: {len(allowed_credentials)}")
                            break
                    
                    if not user_id:
                        logger.warning(f"   ⚠️ No se encontró usuario con email: {request.email}")
                except Exception as e:
                    logger.warning(f"   Error buscando usuario por email: {e}")
            else:
                logger.warning(f"   ⚠️ Supabase Auth no disponible")

        # Generar opciones de autenticación
        logger.info(f"   Generando opciones de autenticación...")
        options = await webauthn_service.generate_authentication_options(
            user_id=user_id,
            allowed_credentials=allowed_credentials if allowed_credentials else None
        )

        logger.info(f"   Opciones generadas exitosamente")
        logger.info(f"   Challenge: {options['challenge'][:20]}...")

        # Guardar challenge temporalmente
        session_id = request_obj.headers.get("X-Session-ID", request.email or "anonymous")
        _challenge_store[f"login_{session_id}"] = {
            "challenge": options["challenge"],
            "user_id": user_id,
            "timestamp": datetime.now().timestamp()
        }

        logger.info(f"   Challenge guardado para sesión: {session_id}")

        return WebAuthnLoginBeginResponse(
            challenge=options["challenge"],
            rp_id=options["rp_id"],
            allow_credentials=options["allow_credentials"],
            timeout=options["timeout"]
        )

    except Exception as e:
        logger.error(f"❌ Error iniciando login con passkey: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al iniciar login: {str(e)}"
        )


@router.post("/login/complete", response_model=WebAuthnLoginCompleteResponse)
async def login_complete(
    request: WebAuthnLoginCompleteRequest,
    request_obj: Request
):
    """
    Completa el login con passkey
    
    - Verifica la respuesta del autenticador
    - Genera tokens JWT para el usuario autenticado
    - ✅ REGISTRA SESIÓN E HISTORIAL DE LOGIN
    """
    logger.info(f"🔐 Completando login con passkey")
    logger.info(f"   Credential ID recibido: {request.credential_id[:30]}...")

    # Obtener challenge almacenado
    session_id = request_obj.headers.get("X-Session-ID", "anonymous")
    logger.info(f"   Session ID: {session_id}")
    
    stored = _challenge_store.get(f"login_{session_id}")
    if not stored:
        logger.warning(f"   ⚠️ No se encontró challenge para sesión: {session_id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No hay login en progreso o el challenge ha expirado"
        )

    challenge = stored["challenge"]
    expected_user_id = stored.get("user_id")
    logger.info(f"   Challenge encontrado, verificando respuesta...")

    try:
        # ✅ OBTENER CREDENCIAL CON BÚSQUEDA NORMALIZADA
        logger.info(f"   Buscando credencial: {request.credential_id[:30]}...")
        credential = await webauthn_service.get_credential_by_id(request.credential_id)

        if not credential:
            logger.warning(f"   ⚠️ Credencial no encontrada: {request.credential_id[:30]}...")
            logger.info(f"   💡 Sugerencia: Verifica que la passkey esté registrada correctamente")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credencial no encontrada. Por favor, asegúrate de tener una passkey registrada."
            )

        logger.info(f"   ✅ Credencial encontrada para usuario: {credential['user_id']}")
        logger.info(f"      Credential ID en BD: {credential['credential_id'][:30]}...")

        # Si se esperaba un usuario específico, verificar que coincide
        if expected_user_id and credential["user_id"] != expected_user_id:
            logger.warning(f"   ⚠️ Credencial no pertenece al usuario esperado")
            logger.warning(f"      Esperado: {expected_user_id}")
            logger.warning(f"      Encontrado: {credential['user_id']}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credencial no pertenece al usuario esperado"
            )

        # Verificar autenticación
        logger.info(f"   Verificando autenticación...")
        verified, new_sign_count, error = await webauthn_service.verify_authentication(
            credential_id=request.credential_id,
            client_data_json=request.client_data_json,
            authenticator_data=request.authenticator_data,
            signature=request.signature,
            challenge=challenge,
            stored_credential=credential,
            user_id=session_id
        )

        if not verified:
            logger.error(f"   ❌ Autenticación fallida: {error}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Autenticación fallida: {error}"
            )

        # Actualizar sign_count en la credencial
        await webauthn_service.update_credential_sign_count(request.credential_id, new_sign_count)
        logger.info(f"   ✅ Sign count actualizado: {new_sign_count}")

        # Obtener información del usuario
        user_id = credential["user_id"]
        user_data = await supabase_auth.get_user_by_id(user_id)

        if not user_data:
            logger.error(f"   ❌ Usuario no encontrado: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )

        # ✅ GENERAR TOKEN JWT
        logger.info(f"   Generando token JWT para usuario: {user_id}")
        
        token_expire = datetime.utcnow() + timedelta(hours=settings.TOKEN_EXPIRE_HOURS)
        
        token_data = {
            "sub": user_id,
            "email": user_data["email"],
            "user_metadata": {
                "username": user_data.get("username"),
                "full_name": user_data.get("full_name")
            },
            "exp": token_expire,
            "iat": datetime.utcnow()
        }
        
        # Generar token
        try:
            import jwt
            access_token = jwt.encode(
                token_data,
                settings.SECRET_KEY,
                algorithm="HS256"
            )
            logger.info(f"   ✅ Token JWT generado exitosamente")
        except Exception as jwt_error:
            logger.error(f"   ❌ Error generando token JWT: {jwt_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al generar token de autenticación"
            )

        # ✅ REGISTRAR SESIÓN E HISTORIAL (LOGIN PASSKEY)
        ip_address = request_obj.client.host if request_obj.client else "unknown"
        user_agent = request_obj.headers.get("User-Agent", "Desconocido")
        device_info = _parse_device_info(user_agent, ip_address)
        
        # ✅ 1. Registrar en historial de login
        await session_service.add_login_history(
            user_id=user_id,
            login_type="passkey",
            status="success",
            ip_address=ip_address,
            device_name=device_info.get("device_name", "Desconocido"),
            device_type=device_info.get("device_type", "web"),
            device_brand=device_info.get("device_brand"),
            device_model=device_info.get("device_model"),
            browser=device_info.get("browser"),
            os=device_info.get("os"),
            location=device_info.get("location", "Desconocida"),
            details={
                "method": "passkey",
                "credential_id": credential["credential_id"],
                "device_name_credential": credential.get("device_name")
            }
        )
        
        # ✅ 2. Crear sesión activa
        session_token = str(uuid.uuid4())
        await session_service.create_session(
            user_id=user_id,
            session_data={
                "session_token": session_token,
                "device_name": device_info.get("device_name", "Desconocido"),
                "device_type": device_info.get("device_type", "web"),
                "device_brand": device_info.get("device_brand"),
                "device_model": device_info.get("device_model"),
                "browser": device_info.get("browser"),
                "os": device_info.get("os"),
                "ip_address": ip_address,
                "location": device_info.get("location", "Desconocida"),
                "is_current": True
            }
        )
        logger.info(f"   ✅ Sesión creada para usuario {user_id} (Passkey)")
        
        # ✅ 3. Registrar evento de seguridad
        await security_service.log_security_event(
            user_id=user_id,
            event_type=SecurityEventType.LOGIN_SUCCESS,
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "method": "passkey",
                "credential_id": credential["credential_id"]
            }
        )
        
        # ✅ 4. Actualizar último uso de la credencial
        await webauthn_service.update_credential_sign_count(request.credential_id, new_sign_count)

        # Limpiar challenge almacenado
        if f"login_{session_id}" in _challenge_store:
            del _challenge_store[f"login_{session_id}"]

        logger.info(f"✅ Login con passkey exitoso para usuario: {user_id}")

        return WebAuthnLoginCompleteResponse(
            success=True,
            access_token=access_token,
            refresh_token=None,
            user={
                "id": user_data["user_id"],
                "email": user_data["email"],
                "username": user_data.get("username"),
                "full_name": user_data.get("full_name")
            },
            message="Login exitoso"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error completando login con passkey: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al completar login: {str(e)}"
        )


@router.get("/credentials", response_model=List[WebAuthnCredentialResponse])
async def list_credentials(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Lista todas las passkeys registradas por el usuario
    """
    user_id = current_user.get("sub")
    logger.info(f"📋 Listando passkeys para usuario: {user_id}")

    try:
        credentials = await webauthn_service.get_user_credentials(user_id)
        logger.info(f"   {len(credentials)} credenciales encontradas")

        return [
            WebAuthnCredentialResponse(
                id=cred["id"],
                credential_id=cred["credential_id"],
                device_name=cred.get("device_name"),
                device_type=cred.get("device_type"),
                created_at=cred["created_at"],
                last_used=cred.get("last_used")
            )
            for cred in credentials
        ]

    except Exception as e:
        logger.error(f"❌ Error listando credenciales: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al listar credenciales: {str(e)}"
        )


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    req: Request = None
):
    """
    Elimina una passkey específica
    """
    user_id = current_user.get("sub")
    logger.info(f"🗑️ Eliminando passkey {credential_id[:30]}... para usuario: {user_id}")

    try:
        deleted = await webauthn_service.delete_credential(user_id, credential_id)

        if not deleted:
            logger.warning(f"   ⚠️ Credencial no encontrada: {credential_id[:30]}...")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credencial no encontrada"
            )

        # ✅ Registrar cambio de seguridad: Passkey eliminada
        ip_address = req.client.host if req else "unknown"
        user_agent = req.headers.get("User-Agent", "Desconocido")
        device_info = _parse_device_info(user_agent, ip_address)
        
        await session_service.add_security_change(
            user_id=user_id,
            change_type="passkey_delete",
            ip_address=ip_address,
            location=device_info.get("location", "Desconocida"),
            details={
                "credential_id": credential_id
            }
        )
        
        await security_service.log_security_event(
            user_id=user_id,
            event_type="PASSKEY_DELETED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={
                "credential_id": credential_id
            }
        )

        logger.info(f"   ✅ Passkey eliminada exitosamente")
        return {
            "success": True,
            "message": "Passkey eliminada exitosamente"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error eliminando credencial: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar credencial: {str(e)}"
        )


@router.get("/health")
async def webauthn_health():
    """
    Endpoint de health check para WebAuthn
    """
    return {
        "status": "healthy",
        "rp_id": webauthn_service.rp_id,
        "rp_name": webauthn_service.rp_name,
        "origin": webauthn_service.origin,
        "configured": True
    }


@router.get("/debug/credentials")
async def debug_list_credentials():
    """
    🔍 ENDPOINT DE DIAGNÓSTICO: Lista todas las credenciales registradas
    (Solo para depuración, no usar en producción)
    """
    if not supabase_auth.is_available():
        return {"error": "Supabase no disponible"}
    
    try:
        admin_client = supabase_auth.get_admin_client()
        response = admin_client.table("user_passkeys").select("*").limit(100).execute()
        
        # Ocultar datos sensibles para el log
        safe_credentials = []
        for cred in response.data:
            safe_credentials.append({
                "id": cred["id"],
                "user_id": cred["user_id"][:8] + "...",
                "credential_id": cred["credential_id"][:20] + "...",
                "device_name": cred.get("device_name"),
                "device_type": cred.get("device_type"),
                "rp_id": cred.get("rp_id"),
                "created_at": cred["created_at"],
                "last_used": cred.get("last_used"),
                "sign_count": cred.get("sign_count")
            })
        
        return {
            "total": len(response.data),
            "credentials": safe_credentials
        }
        
    except Exception as e:
        logger.error(f"Error en debug: {e}")
        return {"error": str(e)}