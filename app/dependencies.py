# app/dependencies.py
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from app.services.supabase_auth_service import SupabaseAuthService
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)


# ============================================
# SERVICIO DE AUTENTICACIÓN CON SUPABASE
# ============================================

class AuthService:
    """Servicio de autenticación que usa Supabase"""
    
    def __init__(self):
        self.supabase_auth = SupabaseAuthService()
    
    async def get_current_user(self, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict[str, Any]:
        """
        Valida el token de Supabase y retorna la información del usuario
        Ahora también valida que la versión del token coincida (invalida sesiones tras cambio de contraseña)
        """
        # Verificar que Supabase está configurado
        if not settings.is_supabase_configured():
            logger.error("❌ Supabase no está configurado")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Servicio de autenticación no disponible"
            )
        
        # Verificar que se proporcionó un token
        if not credentials:
            logger.warning("⚠️ No se proporcionó token de autenticación")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        token = credentials.credentials
        logger.info(f"🔍 Validando token con Supabase: {token[:30]}...")
        
        try:
            # Validar token con Supabase
            user_data = await self.supabase_auth.verify_token(token)
            
            if not user_data:
                logger.error("❌ Token inválido o expirado")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            user_id = user_data.get("user_id")
            logger.info(f"✅ Token válido para usuario: {user_id}")
            
            # ============================================
            # NUEVO: VALIDAR TOKEN_VERSION (Cierre de sesiones activas)
            # ============================================
            is_version_valid = await self.supabase_auth.verify_token_version(token, user_id)
            
            if not is_version_valid:
                logger.warning(f"⚠️ Token version inválido para usuario {user_id}. "
                             "El usuario cambió su contraseña recientemente.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Your session has expired due to password change. Please login again.",
                    headers={"WWW-Authenticate": "Bearer"}
                )
            
            # Retornar información del usuario incluyendo token_version
            token_version = await self.supabase_auth.get_token_version(user_id)
            
            return {
                "sub": user_data.get("user_id"),
                "email": user_data.get("email"),
                "username": user_data.get("username") or user_data.get("email", "").split("@")[0],
                "email_verified": user_data.get("email_verified", False),
                "name": user_data.get("full_name") or user_data.get("username"),
                "preferred_username": user_data.get("username") or user_data.get("email", "").split("@")[0],
                "user_metadata": user_data.get("user_metadata", {}),
                "session_id": user_data.get("session_id"),
                "token_version": token_version  # Incluimos la versión por si el frontend la necesita
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"❌ Error validando token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"}
            )
    
    async def get_current_user_optional(
        self, 
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> Optional[Dict[str, Any]]:
        """Versión opcional que no lanza error si no hay token"""
        if not credentials:
            return None
        
        try:
            return await self.get_current_user(credentials)
        except HTTPException:
            return None


# ============================================
# DEPENDENCIAS PARA FASTAPI
# ============================================

_auth_service = AuthService()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Dependencia principal para obtener el usuario autenticado"""
    return await _auth_service.get_current_user(credentials)


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """Dependencia opcional que no falla si no hay token"""
    return await _auth_service.get_current_user_optional(credentials)


async def get_auth_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[str]:
    """Dependencia que solo retorna el token sin validar el usuario"""
    if not credentials:
        return None
    return credentials.credentials


async def get_current_user_id(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> str:
    """Dependencia que solo retorna el ID del usuario autenticado"""
    return current_user.get("sub")


# ============================================
# DEPENDENCIAS PARA VERIFICACIÓN DE ROLES
# ============================================

async def require_role(required_role: str):
    """Factory function para crear dependencias que requieren un rol específico"""
    async def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        roles = current_user.get("user_metadata", {}).get("roles", [])
        
        if "roles" in current_user:
            roles = current_user.get("roles", [])
        
        if required_role not in roles:
            logger.warning(f"❌ Usuario {current_user.get('sub')} no tiene rol {required_role}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required"
            )
        
        return current_user
    
    return role_checker


async def require_admin(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Dependencia que verifica que el usuario tenga rol de administrador"""
    roles = current_user.get("user_metadata", {}).get("roles", [])
    if "roles" in current_user:
        roles = current_user.get("roles", [])
    
    is_admin = "admin" in roles
    
    if not is_admin:
        logger.warning(f"❌ Usuario {current_user.get('sub')} no es administrador")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    return current_user


async def get_supabase_client(
    token: Optional[str] = Depends(get_auth_token)
):
    """Dependencia que retorna un cliente de Supabase autenticado con el token del usuario"""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token required"
        )
    
    auth_service = SupabaseAuthService()
    return auth_service.get_authenticated_client(token)


__all__ = [
    "get_current_user",
    "get_current_user_optional",
    "get_auth_token",
    "get_current_user_id",
    "require_role",
    "require_admin",
    "get_supabase_client",
]