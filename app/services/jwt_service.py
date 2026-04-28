# app/services/jwt_service.py
"""
Servicio para manejo de tokens JWT
Genera y valida tokens de acceso y refresco para la API
"""
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import logging
from app.config import settings

logger = logging.getLogger(__name__)


def create_access_token(
    subject: str, 
    additional_claims: Optional[Dict[str, Any]] = None, 
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Crea un access token JWT
    
    Args:
        subject: Identificador del usuario (user_id)
        additional_claims: Claims adicionales para incluir en el token
        expires_delta: Tiempo de expiración personalizado (default: 1 hora)
    
    Returns:
        Token JWT codificado como string
    """
    if expires_delta is None:
        expires_delta = timedelta(hours=1)
    
    # ✅ Usar timezone-aware UTC para evitar problemas de zona horaria
    now = datetime.now(timezone.utc)
    exp = now + expires_delta
    
    payload = {
        "sub": subject,
        "exp": exp,
        "iat": now,
        "type": "access"
    }
    
    if additional_claims:
        payload.update(additional_claims)
    
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    
    # Log para depuración
    logger.info(f"✅ Access token creado para usuario: {subject}")
    logger.info(f"   Creado en UTC: {now.isoformat()}")
    logger.info(f"   Expira en UTC: {exp.isoformat()}")
    logger.info(f"   Expira en timestamp: {int(exp.timestamp())}")
    
    return token


def create_refresh_token(
    subject: str, 
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Crea un refresh token JWT
    
    Args:
        subject: Identificador del usuario (user_id)
        expires_delta: Tiempo de expiración personalizado (default: 7 días)
    
    Returns:
        Token JWT codificado como string
    """
    if expires_delta is None:
        expires_delta = timedelta(days=7)
    
    # ✅ Usar timezone-aware UTC para evitar problemas de zona horaria
    now = datetime.now(timezone.utc)
    
    payload = {
        "sub": subject,
        "exp": now + expires_delta,
        "iat": now,
        "type": "refresh"
    }
    
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    logger.debug(f"✅ Refresh token creado para usuario: {subject}")
    
    return token


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodifica y valida un token JWT
    """
    try:
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=["HS256"]
        )
        logger.debug(f"✅ Token decodificado exitosamente para usuario: {payload.get('sub')}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("⚠️ Token expirado")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"⚠️ Token inválido: {str(e)}")
        return None


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verifica específicamente un access token"""
    payload = decode_token(token)
    
    if payload and payload.get("type") == "access":
        return payload
    
    if payload:
        logger.warning(f"⚠️ Token no es de tipo access, es: {payload.get('type')}")
    
    return None


def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    """Verifica específicamente un refresh token"""
    payload = decode_token(token)
    
    if payload and payload.get("type") == "refresh":
        return payload
    
    if payload:
        logger.warning(f"⚠️ Token no es de tipo refresh, es: {payload.get('type')}")
    
    return None


def get_token_expiration(token: str) -> Optional[datetime]:
    """Obtiene la fecha de expiración de un token"""
    payload = decode_token(token)
    
    if payload and payload.get("exp"):
        return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    
    return None


def is_token_expired(token: str) -> bool:
    """Verifica si un token ha expirado"""
    expiration = get_token_expiration(token)
    
    if expiration is None:
        return True
    
    return expiration < datetime.now(timezone.utc)


def get_token_time_left(token: str) -> Optional[int]:
    """Obtiene el tiempo restante en segundos antes de que expire el token"""
    expiration = get_token_expiration(token)
    
    if expiration is None:
        return None
    
    time_left = (expiration - datetime.now(timezone.utc)).total_seconds()
    
    return max(0, int(time_left))


def refresh_access_token(refresh_token: str) -> Optional[str]:
    """Genera un nuevo access token a partir de un refresh token válido"""
    payload = verify_refresh_token(refresh_token)
    
    if not payload:
        logger.warning("⚠️ Refresh token inválido, no se puede generar nuevo access token")
        return None
    
    user_id = payload.get("sub")
    
    if not user_id:
        logger.warning("⚠️ Refresh token no contiene subject (user_id)")
        return None
    
    # Crear nuevo access token
    new_access_token = create_access_token(
        subject=user_id,
        additional_claims={
            "email": payload.get("email"),
            "username": payload.get("username"),
            "full_name": payload.get("full_name")
        }
    )
    
    logger.info(f"✅ Nuevo access token generado para usuario: {user_id}")
    
    return new_access_token


def get_user_id_from_token(token: str) -> Optional[str]:
    """Extrae el user_id (subject) de un token"""
    payload = decode_token(token)
    
    if payload:
        return payload.get("sub")
    
    return None


def get_email_from_token(token: str) -> Optional[str]:
    """Extrae el email de un token"""
    payload = decode_token(token)
    
    if payload:
        return payload.get("email")
    
    return None