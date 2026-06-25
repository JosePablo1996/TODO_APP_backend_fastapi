# app/services/session_service.py
"""
Servicio para gestión de sesiones y seguridad
"""
import logging
import json
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone

from app.services.supabase_auth_service import supabase_auth
from app.services.security_service import security_service

logger = logging.getLogger(__name__)


class SessionService:
    """Servicio para gestión de sesiones y seguridad"""

    def __init__(self):
        self.session_timeout_hours = 24
        self.max_sessions_per_user = 20

    # ============================================
    # GESTIÓN DE SESIONES
    # ============================================

    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Obtiene todas las sesiones activas de un usuario."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            response = admin_client.table("user_sessions")\
                .select("*")\
                .eq("user_id", user_id)\
                .order("last_activity", desc=True)\
                .execute()
            
            sessions = response.data if response.data else []
            
            now = datetime.now(timezone.utc)
            expired_ids = []
            
            for session in sessions:
                last_activity = datetime.fromisoformat(session["last_activity"].replace('Z', '+00:00'))
                if (now - last_activity) > timedelta(hours=self.session_timeout_hours):
                    expired_ids.append(session["id"])
            
            for session_id in expired_ids:
                await self.delete_session(session_id)
            
            if expired_ids:
                response = admin_client.table("user_sessions")\
                    .select("*")\
                    .eq("user_id", user_id)\
                    .order("last_activity", desc=True)\
                    .execute()
                sessions = response.data if response.data else []
            
            return sessions
            
        except Exception as e:
            logger.error(f"Error obteniendo sesiones para {user_id}: {str(e)}")
            return []

    async def delete_session(self, session_id: str) -> bool:
        """Elimina una sesión específica."""
        try:
            admin_client = supabase_auth.get_admin_client()
            admin_client.table("user_sessions")\
                .delete()\
                .eq("id", session_id)\
                .execute()
            
            logger.info(f"✅ Sesión {session_id} eliminada")
            return True
            
        except Exception as e:
            logger.error(f"Error eliminando sesión {session_id}: {str(e)}")
            return False

    async def delete_all_sessions(self, user_id: str, exclude_current: bool = True) -> int:
        """Elimina todas las sesiones de un usuario."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            query = admin_client.table("user_sessions")\
                .delete()\
                .eq("user_id", user_id)
            
            if exclude_current:
                query = query.eq("is_current", False)
            
            result = query.execute()
            deleted_count = len(result.data) if result.data else 0
            logger.info(f"✅ {deleted_count} sesiones eliminadas para usuario {user_id}")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error eliminando sesiones para {user_id}: {str(e)}")
            return 0

    async def create_session(self, user_id: str, session_data: Dict[str, Any]) -> Optional[str]:
        """Crea una nueva sesión para el usuario."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            sessions = await self.get_user_sessions(user_id)
            if len(sessions) >= self.max_sessions_per_user:
                oldest = sessions[-1] if sessions else None
                if oldest:
                    await self.delete_session(oldest["id"])
            
            if session_data.get("is_current", False):
                admin_client.table("user_sessions")\
                    .update({"is_current": False})\
                    .eq("user_id", user_id)\
                    .execute()
            
            now = datetime.now(timezone.utc).isoformat()
            session_data.update({
                "user_id": user_id,
                "created_at": now,
                "updated_at": now,
                "last_activity": now
            })
            
            response = admin_client.table("user_sessions").insert(session_data).execute()
            
            if response.data:
                session_id = response.data[0]["id"]
                logger.info(f"✅ Sesión creada para usuario {user_id}: {session_id}")
                return session_id
            
            return None
            
        except Exception as e:
            logger.error(f"Error creando sesión para {user_id}: {str(e)}")
            return None

    async def update_session_activity(self, session_id: str) -> bool:
        """Actualiza la última actividad de una sesión."""
        try:
            admin_client = supabase_auth.get_admin_client()
            now = datetime.now(timezone.utc).isoformat()
            
            admin_client.table("user_sessions")\
                .update({
                    "last_activity": now,
                    "updated_at": now
                })\
                .eq("id", session_id)\
                .execute()
            
            return True
            
        except Exception as e:
            logger.error(f"Error actualizando actividad de sesión {session_id}: {str(e)}")
            return False

    async def get_current_session(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Obtiene la sesión actual del usuario."""
        try:
            admin_client = supabase_auth.get_admin_client()
            response = admin_client.table("user_sessions")\
                .select("*")\
                .eq("user_id", user_id)\
                .eq("is_current", True)\
                .limit(1)\
                .execute()
            
            if response.data:
                return response.data[0]
            return None
            
        except Exception as e:
            logger.error(f"Error obteniendo sesión actual para {user_id}: {str(e)}")
            return None

    # ============================================
    # HISTORIAL DE LOGIN
    # ============================================

    async def add_login_history(
        self,
        user_id: str,
        login_type: str,
        status: str,
        **kwargs
    ) -> bool:
        """Registra un evento de login en el historial."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            history_data = {
                "user_id": user_id,
                "login_type": login_type,
                "status": status,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            optional_fields = [
                "ip_address", "device_name", "device_type", "device_brand",
                "device_model", "browser", "os", "location", "details"
            ]
            
            for field in optional_fields:
                if field in kwargs and kwargs[field] is not None:
                    history_data[field] = kwargs[field]
            
            if "details" in history_data and isinstance(history_data["details"], dict):
                history_data["details"] = json.dumps(history_data["details"])
            
            admin_client.table("login_history").insert(history_data).execute()
            
            logger.debug(f"✅ Historial de login registrado para usuario {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error registrando historial de login para {user_id}: {str(e)}")
            return False

    async def update_login_history(
        self,
        user_id: str,
        login_type: str,
        status: str,
        **kwargs
    ) -> bool:
        """Actualiza el último registro de historial de login."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            result = admin_client.table("login_history")\
                .select("*")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .limit(1)\
                .execute()
            
            if not result.data:
                return await self.add_login_history(user_id, login_type, status, **kwargs)
            
            last_entry = result.data[0]
            last_login_type = last_entry.get("login_type")
            
            if last_login_type == "password" and login_type == "2fa":
                update_data = {
                    "login_type": "2fa",
                    "status": status,
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }
                
                optional_fields = [
                    "ip_address", "device_name", "device_type", "device_brand",
                    "device_model", "browser", "os", "location"
                ]
                
                for field in optional_fields:
                    if field in kwargs and kwargs[field] is not None:
                        update_data[field] = kwargs[field]
                
                if "details" in kwargs and isinstance(kwargs["details"], dict):
                    update_data["details"] = json.dumps(kwargs["details"])
                
                if len(update_data) > 2:
                    admin_client.table("login_history")\
                        .update(update_data)\
                        .eq("id", last_entry["id"])\
                        .execute()
                    logger.debug(f"✅ Historial de login actualizado para usuario {user_id} (password → 2fa)")
                
                return True
            else:
                return await self.add_login_history(user_id, login_type, status, **kwargs)
        
        except Exception as e:
            logger.error(f"Error actualizando historial de login para {user_id}: {str(e)}")
            return False

    async def get_login_history(
        self,
        user_id: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Obtiene el historial de login del usuario con filtros."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            query = admin_client.table("login_history")\
                .select("*")\
                .eq("user_id", user_id)
            
            if filters:
                if filters.get("login_type") and filters["login_type"] != "all":
                    query = query.eq("login_type", filters["login_type"])
                if filters.get("status") and filters["status"] != "all":
                    query = query.eq("status", filters["status"])
                if filters.get("date_from"):
                    query = query.gte("created_at", filters["date_from"])
                if filters.get("date_to"):
                    query = query.lte("created_at", filters["date_to"])
            
            query = query.order("created_at", desc=True)\
                .limit(limit)\
                .offset(offset)
            
            response = query.execute()
            
            if response.data:
                for item in response.data:
                    if "details" in item and isinstance(item["details"], str):
                        try:
                            item["details"] = json.loads(item["details"])
                        except (json.JSONDecodeError, TypeError):
                            item["details"] = {}
                    elif "details" not in item:
                        item["details"] = {}
            
            return response.data if response.data else []
            
        except Exception as e:
            logger.error(f"Error obteniendo historial de login para {user_id}: {str(e)}")
            return []

    async def get_login_history_count(self, user_id: str) -> int:
        """Obtiene el número total de registros de login."""
        try:
            admin_client = supabase_auth.get_admin_client()
            response = admin_client.table("login_history")\
                .select("*", count="exact")\
                .eq("user_id", user_id)\
                .execute()
            
            return response.count if hasattr(response, 'count') else 0
            
        except Exception as e:
            logger.error(f"Error obteniendo conteo de historial para {user_id}: {str(e)}")
            return 0

    # ============================================
    # CAMBIOS DE SEGURIDAD
    # ============================================

    async def add_security_change(
        self,
        user_id: str,
        change_type: str,
        **kwargs
    ) -> bool:
        """Registra un cambio de seguridad."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            change_data = {
                "user_id": user_id,
                "change_type": change_type,
                "status": kwargs.get("status", "success"),
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            optional_fields = [
                "old_value", "new_value", "ip_address", "location", "details"
            ]
            
            for field in optional_fields:
                if field in kwargs and kwargs[field] is not None:
                    change_data[field] = kwargs[field]
            
            if "details" in change_data and isinstance(change_data["details"], dict):
                change_data["details"] = json.dumps(change_data["details"])
            
            admin_client.table("security_changes").insert(change_data).execute()
            
            logger.debug(f"✅ Cambio de seguridad registrado para usuario {user_id}: {change_type}")
            return True
            
        except Exception as e:
            logger.error(f"Error registrando cambio de seguridad para {user_id}: {str(e)}")
            return False

    async def get_security_changes(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Obtiene el historial de cambios de seguridad."""
        try:
            admin_client = supabase_auth.get_admin_client()
            
            response = admin_client.table("security_changes")\
                .select("*")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .limit(limit)\
                .offset(offset)\
                .execute()
            
            if response.data:
                for item in response.data:
                    if "details" in item and isinstance(item["details"], str):
                        try:
                            item["details"] = json.loads(item["details"])
                        except (json.JSONDecodeError, TypeError):
                            item["details"] = {}
                    elif "details" not in item:
                        item["details"] = {}
            
            return response.data if response.data else []
            
        except Exception as e:
            logger.error(f"Error obteniendo cambios de seguridad para {user_id}: {str(e)}")
            return []

    async def get_security_changes_count(self, user_id: str) -> int:
        """Obtiene el número total de cambios de seguridad."""
        try:
            admin_client = supabase_auth.get_admin_client()
            response = admin_client.table("security_changes")\
                .select("*", count="exact")\
                .eq("user_id", user_id)\
                .execute()
            
            return response.count if hasattr(response, 'count') else 0
            
        except Exception as e:
            logger.error(f"Error obteniendo conteo de cambios para {user_id}: {str(e)}")
            return 0

    # ============================================
    # ESTADÍSTICAS DE SEGURIDAD
    # ============================================

    async def get_security_stats(self, user_id: str) -> Dict[str, Any]:
        """
        Obtiene estadísticas de seguridad del usuario.
        """
        try:
            admin_client = supabase_auth.get_admin_client()
            
            # Obtener total de logins
            login_count = await self.get_login_history_count(user_id)
            
            # Obtener dispositivos únicos
            devices_response = admin_client.table("user_sessions")\
                .select("device_type, os")\
                .eq("user_id", user_id)\
                .execute()
            
            unique_devices = set()
            for session in devices_response.data:
                key = f"{session.get('device_type', 'unknown')}|{session.get('os', 'unknown')}"
                unique_devices.add(key)
            
            # ✅ Último login - SIN UBICACIÓN
            history_response = admin_client.table("login_history")\
                .select("*")\
                .eq("user_id", user_id)\
                .order("created_at", desc=True)\
                .limit(1)\
                .execute()
            
            last_login = None
            if history_response.data and len(history_response.data) > 0:
                last = history_response.data[0]
                device_name = last.get("device_name") or last.get("device_type") or "Desconocido"
                last_login = {
                    "date": last["created_at"],
                    "device": device_name,
                    "ip": last.get("ip_address", "N/A")
                }
            
            # Verificar Passkey
            passkey_response = admin_client.table("user_passkeys")\
                .select("id")\
                .eq("user_id", user_id)\
                .limit(1)\
                .execute()
            has_passkey = len(passkey_response.data) > 0 if passkey_response.data else False
            
            # Verificar 2FA
            twofa_response = admin_client.table("user_two_factor")\
                .select("enabled")\
                .eq("user_id", user_id)\
                .execute()
            has_2fa = False
            if twofa_response.data and len(twofa_response.data) > 0:
                has_2fa = twofa_response.data[0].get("enabled", False)
            
            # Días desde último cambio de contraseña
            days_since_password_change = None
            user_metadata = await security_service.get_user_metadata(user_id)
            password_changed_at = user_metadata.get("password_changed_at")
            if password_changed_at:
                try:
                    changed_date = datetime.fromisoformat(password_changed_at.replace('Z', '+00:00'))
                    days_since_password_change = (datetime.now(timezone.utc) - changed_date).days
                except:
                    pass
            
            # ============================================
            # CALCULAR PUNTAJE DE SEGURIDAD
            # ============================================
            security_score = 0
            recommendations = []
            
            # 1. Passkey (+20)
            if has_passkey:
                security_score += 20
            else:
                recommendations.append("Registra una Passkey para acceso biométrico seguro")
            
            # 2. 2FA (+25)
            if has_2fa:
                security_score += 25
            else:
                recommendations.append("Activa la autenticación de dos factores (2FA) para mayor seguridad")
            
            # 3. Contraseña reciente (+15 si < 90 días)
            if days_since_password_change is not None:
                if days_since_password_change < 90:
                    security_score += 15
                elif days_since_password_change > 180:
                    security_score -= 5
                    recommendations.append("Tu contraseña tiene más de 180 días. Cámbiala por seguridad.")
                else:
                    security_score += 5
            else:
                security_score += 5
            
            # 4. Sesiones activas (hasta +10)
            sessions_count = len(devices_response.data)
            if sessions_count <= 2:
                security_score += 10
            elif sessions_count <= 4:
                security_score += 5
            elif sessions_count > 5:
                security_score -= 5
                recommendations.append(f"Tienes {sessions_count} sesiones activas. Revisa y cierra las que no uses.")
            
            # 5. Múltiples dispositivos (+10)
            if len(unique_devices) >= 2:
                security_score += 10
            
            # 6. Historial de login (+5 si hay más de 10 logins)
            if login_count > 10:
                security_score += 5
            
            # ✅ SI TIENE 2FA Y PASSKEY, FORZAR 100%
            if has_2fa and has_passkey:
                security_score = 100
                recommendations = ["✅ Tu cuenta tiene el máximo nivel de seguridad"]
            # ✅ SI TIENE SOLO 2FA O SOLO PASSKEY, MÍNIMO 60%
            elif has_2fa or has_passkey:
                security_score = max(security_score, 60)
            
            # Asegurar que el puntaje no exceda 100 ni sea menor a 0
            security_score = max(0, min(security_score, 100))
            
            # Si no hay recomendaciones, añadir una positiva
            if len(recommendations) == 0:
                recommendations.append("✅ Tu cuenta tiene un buen nivel de seguridad. ¡Sigue así!")
            
            return {
                "total_logins": login_count,
                "unique_devices": len(unique_devices),
                "last_login": last_login,
                "security_score": security_score,
                "recommendations": recommendations,
                "has_passkey": has_passkey,
                "has_2fa": has_2fa,
                "days_since_password_change": days_since_password_change
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas de seguridad para {user_id}: {str(e)}")
            return {
                "total_logins": 0,
                "unique_devices": 0,
                "last_login": None,
                "security_score": 0,
                "recommendations": ["No se pudieron cargar las estadísticas de seguridad"],
                "has_passkey": False,
                "has_2fa": False,
                "days_since_password_change": None
            }


# ✅ INSTANCIA GLOBAL - ESTO ES LO QUE FALTABA
session_service = SessionService()