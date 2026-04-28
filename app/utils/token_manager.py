import secrets
import time
import hashlib
import hmac
from typing import Dict, Optional, Any
from app.config import settings
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class PasswordResetToken:
    """Modelo para tokens de reseteo de contraseña"""
    def __init__(self, token: str, user_id: str, email: str, expires_at: float):
        self.token = token
        self.user_id = user_id
        self.email = email
        self.expires_at = expires_at
        self.created_at = time.time()
    
    def is_expired(self) -> bool:
        """Verifica si el token ha expirado"""
        return time.time() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el token a diccionario"""
        return {
            "token": self.token,
            "user_id": self.user_id,
            "email": self.email,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "is_expired": self.is_expired()
        }

class TokenManager:
    """
    Gestor de tokens para reseteo de contraseña
    Almacena tokens en memoria (para producción usar Redis o base de datos)
    """
    
    # Almacenamiento en memoria (diccionario)
    _reset_tokens: Dict[str, PasswordResetToken] = {}
    
    @classmethod
    def create_token(cls, user_id: str, email: str, expire_hours: int = None) -> str:
        """
        Genera un token único para reseteo de contraseña
        
        Args:
            user_id: ID del usuario en Keycloak
            email: Email del usuario
            expire_hours: Horas de validez (usa settings.TOKEN_EXPIRE_HOURS por defecto)
        
        Returns:
            Token generado
        """
        if expire_hours is None:
            expire_hours = settings.TOKEN_EXPIRE_HOURS
        
        # Generar token criptográficamente seguro
        token = secrets.token_urlsafe(32)
        
        # Calcular fecha de expiración
        expires_at = time.time() + (expire_hours * 3600)
        
        # Crear y almacenar token
        token_obj = PasswordResetToken(
            token=token,
            user_id=user_id,
            email=email,
            expires_at=expires_at
        )
        
        cls._reset_tokens[token] = token_obj
        
        logger.info(f"Token creado para usuario {user_id} (expira en {expire_hours}h)")
        
        # Limpiar tokens expirados periódicamente (opcional)
        cls._clean_expired_tokens()
        
        return token
    
    @classmethod
    def verify_token(cls, token: str) -> Optional[PasswordResetToken]:
        """
        Verifica si un token es válido y no ha expirado
        
        Args:
            token: Token a verificar
        
        Returns:
            Token object si es válido, None si no
        """
        token_obj = cls._reset_tokens.get(token)
        
        if not token_obj:
            logger.warning(f"Token no encontrado: {token[:8]}...")
            return None
        
        if token_obj.is_expired():
            logger.warning(f"Token expirado: {token[:8]}...")
            # Eliminar token expirado automáticamente
            cls.delete_token(token)
            return None
        
        logger.info(f"Token válido para usuario: {token_obj.user_id}")
        return token_obj
    
    @classmethod
    def delete_token(cls, token: str) -> bool:
        """
        Elimina un token (usado después de resetear contraseña)
        
        Args:
            token: Token a eliminar
        
        Returns:
            True si se eliminó, False si no existía
        """
        if token in cls._reset_tokens:
            del cls._reset_tokens[token]
            logger.info(f"Token eliminado: {token[:8]}...")
            return True
        
        return False
    
    @classmethod
    def _clean_expired_tokens(cls) -> int:
        """
        Elimina todos los tokens expirados
        Útil para liberar memoria
        
        Returns:
            Número de tokens eliminados
        """
        expired = []
        current_time = time.time()
        
        for token, token_obj in cls._reset_tokens.items():
            if current_time > token_obj.expires_at:
                expired.append(token)
        
        for token in expired:
            del cls._reset_tokens[token]
        
        if expired:
            logger.info(f"Se eliminaron {len(expired)} tokens expirados")
        
        return len(expired)
    
    @classmethod
    def get_user_tokens(cls, user_id: str) -> list:
        """
        Obtiene todos los tokens activos de un usuario
        
        Args:
            user_id: ID del usuario
        
        Returns:
            Lista de tokens activos
        """
        tokens = []
        current_time = time.time()
        
        for token, token_obj in cls._reset_tokens.items():
            if token_obj.user_id == user_id and current_time <= token_obj.expires_at:
                tokens.append(token_obj.to_dict())
        
        return tokens
    
    @classmethod
    def revoke_user_tokens(cls, user_id: str) -> int:
        """
        Revoca todos los tokens activos de un usuario
        
        Args:
            user_id: ID del usuario
        
        Returns:
            Número de tokens revocados
        """
        revoked = []
        
        for token, token_obj in cls._reset_tokens.items():
            if token_obj.user_id == user_id:
                revoked.append(token)
        
        for token in revoked:
            del cls._reset_tokens[token]
        
        if revoked:
            logger.info(f"Se revocaron {len(revoked)} tokens del usuario {user_id}")
        
        return len(revoked)
    
    @classmethod
    def get_stats(cls) -> Dict[str, Any]:
        """
        Obtiene estadísticas de los tokens almacenados
        
        Returns:
            Diccionario con estadísticas
        """
        total = len(cls._reset_tokens)
        expired = cls._clean_expired_tokens()
        
        return {
            "total_tokens": total,
            "expired_tokens": expired,
            "active_tokens": total - expired
        }

# Alias para facilitar importaciones
PasswordResetTokenManager = TokenManager