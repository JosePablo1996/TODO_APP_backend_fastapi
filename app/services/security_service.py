# app/services/security_service.py
"""
Servicio centralizado para seguridad y auditoría.
Maneja:
- Eventos de seguridad
- Gestión de sesiones (token_version)
- Bloqueo de cuentas (rate limiting)
- Expiración de contraseñas
- Políticas de contraseñas
"""
import logging
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID

from app.services.supabase_auth_service import supabase_auth
from app.config import settings

logger = logging.getLogger(__name__)


class SecurityEventType:
    """Tipos de eventos de seguridad predefinidos"""
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    LOGOUT_ALL_SESSIONS = "LOGOUT_ALL_SESSIONS"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PASSWORD_CHANGE_FAILED = "PASSWORD_CHANGE_FAILED"
    PASSWORD_RESET_VIA_OTP = "PASSWORD_RESET_VIA_OTP"
    PASSWORD_EXPIRING_SOON = "PASSWORD_EXPIRING_SOON"
    PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
    PASSWORD_REUSE_ATTEMPT = "PASSWORD_REUSE_ATTEMPT"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    TWO_FACTOR_ENABLED = "TWO_FACTOR_ENABLED"
    TWO_FACTOR_DISABLED = "TWO_FACTOR_DISABLED"
    TWO_FACTOR_VERIFIED = "TWO_FACTOR_VERIFIED"
    TWO_FACTOR_FAILED = "TWO_FACTOR_FAILED"
    PROFILE_UPDATED = "PROFILE_UPDATED"
    AVATAR_UPLOADED = "AVATAR_UPLOADED"
    AVATAR_DELETED = "AVATAR_DELETED"
    BANNER_UPLOADED = "BANNER_UPLOADED"
    BANNER_DELETED = "BANNER_DELETED"


class SecurityService:
    """
    Servicio centralizado para seguridad y auditoría.
    Maneja:
    - Eventos de seguridad
    - Gestión de sesiones (token_version)
    - Bloqueo de cuentas (rate limiting)
    - Expiración de contraseñas
    - Políticas de contraseñas
    """

    def __init__(self):
        # Rate limiting configuration
        self.max_login_attempts = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
        self.lockout_duration_minutes = getattr(settings, 'LOGIN_LOCKOUT_MINUTES', 15)
        self.session_timeout_hours = getattr(settings, 'SESSION_TIMEOUT_HOURS', 24)
        
        # Política por defecto
        self.default_policy = {
            "max_age_days": 90,
            "prevent_reuse_count": 5,
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special_chars": True
        }
        
        logger.info("✅ SecurityService inicializado")
        logger.info(f"   Max login attempts: {self.max_login_attempts}")
        logger.info(f"   Lockout duration: {self.lockout_duration_minutes} minutes")

    # ============================================
    # POLÍTICAS DE CONTRASEÑAS
    # ============================================

    async def get_password_policy(self) -> Dict[str, Any]:
        """Obtiene la política actual de contraseñas desde la base de datos."""
        try:
            admin_client = supabase_auth.get_admin_client()
            result = admin_client.table("password_policies").select("*").limit(1).execute()
            
            if result.data and len(result.data) > 0:
                policy = result.data[0]
                # Eliminar campos internos
                policy.pop("id", None)
                policy.pop("created_at", None)
                policy.pop("updated_at", None)
                logger.debug(f"📋 Política obtenida: max_age={policy.get('max_age_days')} días")
                return policy
        except Exception as e:
            logger.error(f"❌ Error obteniendo política: {e}")
        
        logger.info(f"📋 Usando política por defecto")
        return self.default_policy.copy()

    async def update_password_policy(self, updates: Dict[str, Any]) -> bool:
        """Actualiza la política de contraseñas (solo admin)."""
        try:
            admin_client = supabase_auth.get_admin_client()
            current = await self.get_password_policy()
            
            # Buscar política existente
            existing = admin_client.table("password_policies").select("id").limit(1).execute()
            
            now = datetime.now(timezone.utc).isoformat()
            updated_data = {**updates, "updated_at": now}
            
            if existing.data and len(existing.data) > 0:
                admin_client.table("password_policies")\
                    .update(updated_data)\
                    .eq("id", existing.data[0]["id"])\
                    .execute()
            else:
                updated_data["created_at"] = now
                admin_client.table("password_policies").insert(updated_data).execute()
            
            logger.info(f"✅ Política actualizada: {updates}")
            return True
        except Exception as e:
            logger.error(f"❌ Error actualizando política: {e}")
            return False

    # ============================================
    # VALIDACIÓN DE FORTALEZA DE CONTRASEÑA
    # ============================================

    def validate_password_strength(self, password: str, policy: Dict = None) -> Tuple[bool, List[str]]:
        """Valida la fortaleza de una contraseña según la política."""
        if policy is None:
            policy = self.default_policy
        
        errors = []
        
        min_length = policy.get("min_length", 8)
        if len(password) < min_length:
            errors.append(f"La contraseña debe tener al menos {min_length} caracteres")
        
        if policy.get("require_uppercase", True) and not any(c.isupper() for c in password):
            errors.append("La contraseña debe contener al menos una letra mayúscula")
        
        if policy.get("require_lowercase", True) and not any(c.islower() for c in password):
            errors.append("La contraseña debe contener al menos una letra minúscula")
        
        if policy.get("require_numbers", True) and not any(c.isdigit() for c in password):
            errors.append("La contraseña debe contener al menos un número")
        
        if policy.get("require_special_chars", True):
            special_chars = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?"
            if not any(c in special_chars for c in password):
                errors.append("La contraseña debe contener al menos un carácter especial")
        
        return len(errors) == 0, errors

    def hash_password_for_history(self, password: str) -> str:
        """Genera hash SHA-256 para almacenar en historial."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    # ============================================
    # HISTORIAL DE CONTRASEÑAS
    # ============================================

    async def record_password_history(self, user_id: str, password_hash: str) -> bool:
        """Registra un hash de contraseña en el historial."""
        try:
            admin_client = supabase_auth.get_admin_client()
            admin_client.table("password_history").insert({
                "user_id": user_id,
                "password_hash": password_hash,
                "created_at": datetime.now(timezone.utc).isoformat()
            }).execute()
            logger.debug(f"📝 Historial registrado para usuario {user_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Error registrando historial: {e}")
            return False

    async def check_password_reuse(self, user_id: str, new_password_hash: str) -> Tuple[bool, int]:
        """Verifica si una contraseña ya fue usada recientemente."""
        try:
            policy = await self.get_password_policy()
            prevent_reuse = policy.get("prevent_reuse_count", 5)
            
            admin_client = supabase_auth.get_admin_client()
            result = admin_client.table("password_history")\
                .select("password_hash")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .limit(prevent_reuse)\
                .execute()
            
            recent_hashes = [r["password_hash"] for r in (result.data or [])]
            
            if new_password_hash in recent_hashes:
                times_used = recent_hashes.count(new_password_hash)
                logger.warning(f"⚠️ Intento de reutilización de contraseña para usuario {user_id}")
                return False, times_used
            
            return True, 0
        except Exception as e:
            logger.error(f"❌ Error verificando reuso: {e}")
            return True, 0

    async def cleanup_old_password_history(self, user_id: str, keep_count: int = 20) -> int:
        """Limpia historial antiguo de contraseñas."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            # Obtener IDs antiguos
            result = admin_client.table("password_history")\
                .select("id")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .offset(keep_count)\
                .execute()
            
            if not result.data:
                return 0
            
            ids_to_delete = [r["id"] for r in result.data]
            
            for record_id in ids_to_delete:
                admin_client.table("password_history")\
                    .delete()\
                    .eq("id", record_id)\
                    .execute()
            
            logger.info(f"🗑️ Limpiados {len(ids_to_delete)} registros antiguos para usuario {user_id}")
            return len(ids_to_delete)
        except Exception as e:
            logger.error(f"❌ Error limpiando historial: {e}")
            return 0

    # ============================================
    # EXPIRACIÓN DE CONTRASEÑAS
    # ============================================

    async def calculate_expiry_date(self) -> datetime:
        """Calcula fecha de expiración basada en la política actual."""
        policy = await self.get_password_policy()
        max_age_days = policy.get("max_age_days", 90)
        return datetime.now(timezone.utc) + timedelta(days=max_age_days)

    async def is_password_expired(self, user_id: str) -> Tuple[bool, Optional[int]]:
        """Verifica si la contraseña del usuario ha expirado."""
        try:
            user_metadata = await self.get_user_metadata(user_id)
            password_expires_at = user_metadata.get("password_expires_at")
            
            if not password_expires_at:
                return False, None
            
            # Convertir a datetime si es string
            if isinstance(password_expires_at, str):
                expires_at = datetime.fromisoformat(password_expires_at.replace('Z', '+00:00'))
            else:
                expires_at = password_expires_at
            
            now = datetime.now(timezone.utc)
            
            if expires_at < now:
                logger.warning(f"⚠️ Contraseña expirada para usuario {user_id}")
                return True, 0
            
            days_remaining = (expires_at - now).days
            return False, days_remaining
            
        except Exception as e:
            logger.error(f"❌ Error verificando expiración: {e}")
            return False, None

    async def update_password_expiry(self, user_id: str) -> bool:
        """Actualiza la fecha de expiración de la contraseña."""
        try:
            expiry_date = await self.calculate_expiry_date()
            expiry_iso = expiry_date.isoformat()
            
            await self.update_user_metadata(user_id, {
                "password_changed_at": datetime.now(timezone.utc).isoformat(),
                "password_expires_at": expiry_iso
            })
            
            logger.info(f"📅 Fecha de expiración actualizada para usuario {user_id}: {expiry_iso}")
            return True
        except Exception as e:
            logger.error(f"❌ Error actualizando expiración: {e}")
            return False

    def should_notify_expiry(self, days_remaining: int, last_notified_days: Optional[int] = None) -> bool:
        """Determina si se debe enviar notificación de expiración."""
        thresholds = [30, 14, 7, 3, 1]
        
        if days_remaining <= 0:
            return False
        
        for threshold in thresholds:
            if days_remaining <= threshold:
                if last_notified_days is None or last_notified_days > threshold:
                    return True
        
        return False

    def get_expiry_warning_message(self, days_remaining: int) -> str:
        """Obtiene mensaje de advertencia según días restantes."""
        if days_remaining <= 0:
            return "Tu contraseña ha expirado. Debes cambiarla para continuar."
        elif days_remaining == 1:
            return "Tu contraseña expirará mañana. Por favor, cámbiala cuanto antes."
        elif days_remaining <= 3:
            return f"Tu contraseña expirará en {days_remaining} días. Te recomendamos cambiarla pronto."
        elif days_remaining <= 7:
            return f"Tu contraseña expirará en {days_remaining} días. Considera cambiarla para mayor seguridad."
        elif days_remaining <= 30:
            return f"Tu contraseña expirará en {days_remaining} días. Puedes cambiarla cuando lo desees."
        else:
            return f"Tu contraseña está vigente por {days_remaining} días más."

    # ============================================
    # EVENTOS DE SEGURIDAD - CORREGIDO
    # ============================================

    async def log_security_event(
        self,
        user_id: str,
        event_type: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict] = None
    ) -> bool:
        """
        Registra un evento de seguridad en la base de datos.
        ✅ CORREGIDO: Manejo correcto de la respuesta de Supabase
        """
        try:
            admin_client = supabase_auth.get_admin_client()
            
            event_data = {
                "user_id": user_id,
                "event_type": event_type,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "details": details or {},
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Ejecutar inserción
            result = admin_client.table("security_events").insert(event_data).execute()
            
            # ✅ Verificar si la operación fue exitosa
            # En Supabase, si no hay error, la inserción fue exitosa
            if hasattr(result, 'data'):
                logger.info(f"📝 Evento de seguridad registrado: {event_type} para usuario {user_id}")
                return True
            else:
                # Si no hay datos pero no hubo error, consideramos éxito
                logger.info(f"📝 Evento de seguridad registrado: {event_type} para usuario {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"❌ Error registrando evento de seguridad: {str(e)}")
            # ✅ No fallar la operación principal si el log falla
            return False

    async def get_security_events(
        self,
        user_id: str,
        event_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict]:
        """Obtiene eventos de seguridad de un usuario."""
        try:
            admin_client = supabase_auth.get_admin_client()
            query = admin_client.table("security_events")\
                .select("*")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .limit(limit)\
                .offset(offset)
            
            if event_type:
                query = query.eq("event_type", event_type)
            
            result = query.execute()
            return result.data if result.data else []
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo eventos de seguridad: {e}")
            return []

    async def get_recent_security_events(self, user_id: str, hours: int = 24) -> List[Dict]:
        """Obtiene eventos de seguridad recientes."""
        try:
            admin_client = supabase_auth.get_admin_client()
            cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            
            result = admin_client.table("security_events")\
                .select("*")\
                .eq("user_id", user_id)\
                .gte("created_at", cutoff_time)\
                .order("created_at", desc=True)\
                .execute()
            
            return result.data if result.data else []
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo eventos recientes: {e}")
            return []

    # ============================================
    # RATE LIMITING
    # ============================================

    async def record_failed_login(
        self, 
        email: str, 
        ip_address: str, 
        user_id: Optional[str] = None
    ) -> Dict:
        """
        Registra un intento de login fallido.
        Retorna información sobre el estado de bloqueo.
        """
        try:
            admin_client = supabase_auth.get_admin_client()
            
            # Buscar registro de intentos fallidos existente
            result = admin_client.table("login_attempts")\
                .select("*")\
                .eq("email", email)\
                .eq("ip_address", ip_address)\
                .execute()
            
            now = datetime.now(timezone.utc)
            
            if result.data and len(result.data) > 0:
                attempt = result.data[0]
                
                # Verificar si ya está bloqueado y si el bloqueo expiró
                if attempt.get("is_locked") and attempt.get("locked_until"):
                    locked_until = datetime.fromisoformat(attempt["locked_until"].replace('Z', '+00:00'))
                    if locked_until > now:
                        # Todavía bloqueado
                        return {
                            "attempts": attempt.get("attempt_count", 0),
                            "is_locked": True,
                            "locked_until": locked_until,
                            "max_attempts": self.max_login_attempts,
                            "remaining_attempts": 0
                        }
                    else:
                        # Bloqueo expirado, resetear
                        await self.reset_failed_logins(email, ip_address)
                        return await self.record_failed_login(email, ip_address, user_id)
                
                # Incrementar contador
                new_count = attempt.get("attempt_count", 0) + 1
                is_locked = new_count >= self.max_login_attempts
                locked_until = (now + timedelta(minutes=self.lockout_duration_minutes)).isoformat() if is_locked else None
                
                admin_client.table("login_attempts")\
                    .update({
                        "attempt_count": new_count,
                        "last_attempt": now.isoformat(),
                        "is_locked": is_locked,
                        "locked_until": locked_until,
                        "updated_at": now.isoformat(),
                        "user_id": user_id
                    })\
                    .eq("id", attempt["id"])\
                    .execute()
            else:
                # Primer intento fallido
                new_count = 1
                is_locked = False
                locked_until = None
                
                admin_client.table("login_attempts").insert({
                    "email": email,
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "attempt_count": new_count,
                    "last_attempt": now.isoformat(),
                    "is_locked": is_locked,
                    "locked_until": locked_until,
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat()
                }).execute()
            
            # Registrar evento de seguridad
            await self.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.LOGIN_FAILED,
                ip_address=ip_address,
                details={
                    "email": email,
                    "attempt_count": new_count,
                    "max_attempts": self.max_login_attempts,
                    "is_locked": is_locked
                }
            )
            
            if is_locked:
                await self.log_security_event(
                    user_id=user_id,
                    event_type=SecurityEventType.ACCOUNT_LOCKED,
                    ip_address=ip_address,
                    details={
                        "email": email,
                        "reason": "too_many_failed_attempts",
                        "locked_until": locked_until
                    }
                )
            
            return {
                "attempts": new_count,
                "is_locked": is_locked,
                "locked_until": locked_until,
                "max_attempts": self.max_login_attempts,
                "remaining_attempts": max(0, self.max_login_attempts - new_count)
            }
            
        except Exception as e:
            logger.error(f"❌ Error registrando intento fallido: {e}")
            return {
                "attempts": 1,
                "is_locked": False,
                "max_attempts": self.max_login_attempts,
                "remaining_attempts": self.max_login_attempts - 1
            }

    async def reset_failed_logins(self, email: str, ip_address: str) -> bool:
        """Resetea los intentos fallidos de login."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            admin_client.table("login_attempts")\
                .delete()\
                .eq("email", email)\
                .eq("ip_address", ip_address)\
                .execute()
            
            logger.info(f"✅ Intentos fallidos reseteados para {email} desde IP {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error resetando intentos fallidos: {e}")
            return False

    async def is_account_locked(
        self, 
        email: str, 
        ip_address: str
    ) -> Tuple[bool, Optional[datetime], Optional[int]]:
        """Verifica si una cuenta está bloqueada."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            result = admin_client.table("login_attempts")\
                .select("*")\
                .eq("email", email)\
                .eq("ip_address", ip_address)\
                .execute()
            
            if result.data and len(result.data) > 0:
                attempt = result.data[0]
                
                if attempt.get("is_locked") and attempt.get("locked_until"):
                    locked_until = datetime.fromisoformat(attempt["locked_until"].replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    
                    if locked_until > now:
                        remaining_attempts = 0
                        return True, locked_until, remaining_attempts
                    else:
                        await self.reset_failed_logins(email, ip_address)
                        return False, None, self.max_login_attempts
                
                attempt_count = attempt.get("attempt_count", 0)
                remaining_attempts = max(0, self.max_login_attempts - attempt_count)
                return False, None, remaining_attempts
            
            return False, None, self.max_login_attempts
            
        except Exception as e:
            logger.error(f"❌ Error verificando bloqueo: {e}")
            return False, None, self.max_login_attempts

    async def get_failed_attempts_info(self, email: str, ip_address: str) -> Dict:
        """Obtiene información detallada sobre los intentos fallidos."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            result = admin_client.table("login_attempts")\
                .select("*")\
                .eq("email", email)\
                .eq("ip_address", ip_address)\
                .execute()
            
            if result.data and len(result.data) > 0:
                attempt = result.data[0]
                now = datetime.now(timezone.utc)
                
                is_locked = False
                locked_until = None
                seconds_remaining = 0
                
                if attempt.get("is_locked") and attempt.get("locked_until"):
                    locked_until = datetime.fromisoformat(attempt["locked_until"].replace('Z', '+00:00'))
                    if locked_until > now:
                        is_locked = True
                        seconds_remaining = int((locked_until - now).total_seconds())
                
                return {
                    "attempts": attempt.get("attempt_count", 0),
                    "is_locked": is_locked,
                    "locked_until": locked_until.isoformat() if locked_until else None,
                    "seconds_remaining": seconds_remaining,
                    "minutes_remaining": (seconds_remaining + 59) // 60,
                    "max_attempts": self.max_login_attempts,
                    "remaining_attempts": max(0, self.max_login_attempts - attempt.get("attempt_count", 0))
                }
            
            return {
                "attempts": 0,
                "is_locked": False,
                "locked_until": None,
                "seconds_remaining": 0,
                "minutes_remaining": 0,
                "max_attempts": self.max_login_attempts,
                "remaining_attempts": self.max_login_attempts
            }
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo información de intentos: {e}")
            return {
                "attempts": 0,
                "is_locked": False,
                "locked_until": None,
                "seconds_remaining": 0,
                "minutes_remaining": 0,
                "max_attempts": self.max_login_attempts,
                "remaining_attempts": self.max_login_attempts
            }

    # ============================================
    # GESTIÓN DE SESIONES (TOKEN VERSION)
    # ============================================

    async def invalidate_all_sessions(self, user_id: str) -> int:
        """Invalida todas las sesiones de un usuario incrementando session_version."""
        try:
            current_metadata = await self.get_user_metadata(user_id)
            current_version = current_metadata.get("session_version", 0)
            new_version = current_version + 1
            
            await self.update_user_metadata(user_id, {"session_version": new_version})
            
            logger.info(f"✅ Session_version incrementado para usuario {user_id}: {current_version} → {new_version}")
            return 1
            
        except Exception as e:
            logger.error(f"❌ Error invalidando sesiones: {e}")
            return 0

    async def verify_session_version(self, user_id: str, token_version: int) -> bool:
        """Verifica si la versión del token coincide con la sesión actual."""
        try:
            current_metadata = await self.get_user_metadata(user_id)
            current_version = current_metadata.get("session_version", 0)
            
            return token_version >= current_version
            
        except Exception as e:
            logger.error(f"❌ Error verificando session_version: {e}")
            return True

    # ============================================
    # MÉTODOS DE METADATA
    # ============================================

    async def get_user_metadata(self, user_id: str) -> Dict[str, Any]:
        """Obtiene metadata de un usuario."""
        try:
            admin_client = supabase_auth.get_admin_client()
            result = admin_client.table("profiles").select("*").eq("id", user_id).execute()
            
            if result.data and len(result.data) > 0:
                return result.data[0]
            
            return {}
        except Exception as e:
            logger.error(f"❌ Error obteniendo metadata: {e}")
            return {}

    async def update_user_metadata(self, user_id: str, metadata: Dict[str, Any]) -> bool:
        """Actualiza metadata de un usuario en la tabla profiles."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            existing = admin_client.table("profiles").select("*").eq("id", user_id).execute()
            
            if existing.data and len(existing.data) > 0:
                admin_client.table("profiles").update(metadata).eq("id", user_id).execute()
            else:
                insert_data = {"id": user_id, **metadata}
                admin_client.table("profiles").insert(insert_data).execute()
            
            logger.debug(f"✅ Metadata actualizada para usuario {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error actualizando metadata: {e}")
            return False


# Instancia global
security_service = SecurityService()