"""
Router para endpoints de WebAuthn/Passkeys
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import Dict, Any, List
import logging
from datetime import datetime, timedelta

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
from app.dependencies import get_current_user
from app.config import settings

router = APIRouter(prefix="/api/webauthn", tags=["webauthn", "passkeys"])
logger = logging.getLogger(__name__)

# Almacenamiento temporal para challenges (en producción usar Redis)
_challenge_store = {}


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
    current_user: Dict[str, Any] = Depends(get_current_user)
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
    """
    logger.info(f"🔐 Completando login con passkey")

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
        # Obtener credencial almacenada
        logger.info(f"   Buscando credencial: {request.credential_id[:20]}...")
        credential = await webauthn_service.get_credential_by_id(request.credential_id)

        if not credential:
            logger.warning(f"   ⚠️ Credencial no encontrada: {request.credential_id[:20]}...")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credencial no encontrada"
            )

        logger.info(f"   Credencial encontrada para usuario: {credential['user_id']}")

        # Si se esperaba un usuario específico, verificar que coincide
        if expected_user_id and credential["user_id"] != expected_user_id:
            logger.warning(f"   ⚠️ Credencial no pertenece al usuario esperado")
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

        # ✅ GENERAR TOKEN JWT - CORREGIDO (sin campo 'aud')
        logger.info(f"   Generando token JWT para usuario: {user_id}")
        
        # Crear payload del token (sin 'aud' para evitar el error)
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
            # "aud": "authenticated"  # ← ELIMINADO para evitar error "Invalid audience"
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
            logger.info(f"   Token expira en: {token_expire}")
            logger.info(f"   Token data: {token_data}")
        except Exception as jwt_error:
            logger.error(f"   ❌ Error generando token JWT: {jwt_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al generar token de autenticación"
            )

        # Limpiar challenge almacenado
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
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Elimina una passkey específica
    """
    user_id = current_user.get("sub")
    logger.info(f"🗑️ Eliminando passkey {credential_id[:20]}... para usuario: {user_id}")

    try:
        deleted = await webauthn_service.delete_credential(user_id, credential_id)

        if not deleted:
            logger.warning(f"   ⚠️ Credencial no encontrada: {credential_id[:20]}...")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credencial no encontrada"
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