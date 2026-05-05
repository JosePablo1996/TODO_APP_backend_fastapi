# app/services/supabase_auth_service.py
"""
Servicio de autenticación con Supabase Auth
Maneja registro, login, verificación de tokens y gestión de usuarios
"""
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import jwt
import httpx
from fastapi import HTTPException, status
from supabase import create_client, Client

from app.config import settings

logger = logging.getLogger(__name__)


class SupabaseAuthService:
    """Servicio para manejar autenticación con Supabase Auth"""

    def __init__(self):
        self.url = settings.SUPABASE_URL
        self.service_key = settings.SUPABASE_SERVICE_KEY
        self.anon_key = settings.SUPABASE_ANON_KEY
        
        self.is_configured = bool(self.url and self.service_key)
        self._client: Optional[Client] = None
        self._anon_client: Optional[Client] = None

        if self.is_configured:
            try:
                self._client = create_client(self.url, self.service_key)
                if self.anon_key:
                    self._anon_client = create_client(self.url, self.anon_key)
                logger.info("✅ SupabaseAuthService inicializado correctamente")
                logger.info(f"   URL: {self.url}")
                self._check_webauthn_table()
            except Exception as e:
                logger.error(f"❌ Error inicializando SupabaseAuthService: {str(e)}", exc_info=True)
                self._client = None
                self._anon_client = None
        else:
            logger.warning("⚠️ SupabaseAuthService no configurado - Supabase no disponible")

    @property
    def client(self) -> Optional[Client]:
        return self._client

    @property
    def anon_client(self) -> Optional[Client]:
        return self._anon_client

    def _check_webauthn_table(self):
        try:
            if self._client:
                logger.info("🔍 Verificando tabla public.user_passkeys...")
                response = self._client.table("user_passkeys").select("id").limit(1).execute()
                logger.info("✅ Tabla public.user_passkeys existe y es accesible")
                return True
        except Exception as e:
            error_msg = str(e)
            if "PGRST205" in error_msg:
                logger.debug("ℹ️ Tabla public.user_passkeys no encontrada")
            else:
                logger.warning(f"⚠️ Error verificando tabla user_passkeys: {error_msg[:100]}")
            return False

    def get_admin_client(self) -> Client:
        if not self._client:
            raise Exception("Supabase Auth no está configurado")
        return self._client

    def get_authenticated_client(self, access_token: str) -> Client:
        if not self.url or not self.anon_key:
            raise Exception("Supabase no está configurado")
        return create_client(
            self.url,
            self.anon_key,
            options={"headers": {"Authorization": f"Bearer {access_token}"}}
        )

    # ============================================
    # MÉTODO CREATE_USER (API REST DIRECTA)
    # ============================================
    
    async def create_user(
        self, 
        email: str, 
        password: str, 
        username: Optional[str] = None,
        full_name: Optional[str] = None,
        user_metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Crea un nuevo usuario en Supabase Auth usando la API REST directamente.
        """
        logger.info(f"📝 Creando usuario en Supabase: {email}")
        
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
            raise Exception("Supabase no está configurado")
        
        try:
            metadata = user_metadata or {}
            if username:
                metadata["username"] = username
            if full_name:
                metadata["full_name"] = full_name
            metadata["token_version"] = 1
            
            # ✅ Usar la API REST de Supabase directamente (bypassea el SDK)
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.url}/auth/v1/admin/users",
                    headers={
                        "apikey": self.service_key,
                        "Authorization": f"Bearer {self.service_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "email": email,
                        "password": password,
                        "email_confirm": True,
                        "user_metadata": metadata
                    }
                )
                
                if response.status_code >= 400:
                    error_detail = response.json() if response.text else {}
                    logger.error(f"❌ Error Supabase: {response.status_code} - {error_detail}")
                    
                    if response.status_code == 422:
                        raise Exception("El usuario ya existe")
                    raise Exception(f"Error al crear usuario: {error_detail.get('msg', 'Error desconocido')}")
                
                user = response.json()
                user_id = user.get("id")
                
                logger.info(f"✅ Usuario creado exitosamente: {email} (ID: {user_id})")
                
                # ✅ Crear perfil manualmente
                try:
                    await client.post(
                        f"{self.url}/rest/v1/profiles",
                        headers={
                            "apikey": self.service_key,
                            "Authorization": f"Bearer {self.service_key}",
                            "Content-Type": "application/json",
                            "Prefer": "return=minimal"
                        },
                        json={
                            "id": user_id,
                            "email": email,
                            "username": username or email.split('@')[0],
                            "full_name": full_name or "",
                            "created_at": datetime.now().isoformat()
                        }
                    )
                    logger.info(f"✅ Perfil creado para usuario: {user_id}")
                except Exception as profile_error:
                    logger.warning(f"⚠️ Error creando perfil (no crítico): {profile_error}")
                
                return {
                    "user_id": user_id,
                    "email": email,
                    "username": username or email.split('@')[0],
                    "created_at": datetime.now().isoformat(),
                    "user_metadata": metadata
                }
                
        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Error creando usuario: {error_msg}")
            
            if "ya existe" in error_msg.lower():
                raise Exception("El usuario ya existe")
            raise Exception(f"Error al registrar usuario: {error_msg[:200]}")

    # ============================================
    # MÉTODO LOGIN
    # ============================================
    
    async def login(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        logger.info(f"🔐 Intentando login para: {email}")
        
        if not self.is_configured:
            raise Exception("Supabase no está configurado")
        
        try:
            if not self._anon_client:
                self._anon_client = create_client(self.url, self.anon_key)
            
            response = self._anon_client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if not response or not response.user or not response.session:
                logger.warning(f"⚠️ Login fallido para: {email}")
                return None
            
            user = response.user
            session = response.session
            
            logger.info(f"✅ Login exitoso para: {email} (ID: {user.id})")
            
            return {
                "access_token": session.access_token,
                "refresh_token": session.refresh_token,
                "token_type": "bearer",
                "expires_in": session.expires_in,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.user_metadata.get("username") if user.user_metadata else email.split('@')[0],
                    "full_name": user.user_metadata.get("full_name") if user.user_metadata else None,
                    "email_verified": user.email_confirmed_at is not None
                }
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Error en login: {error_msg}")
            if "Invalid login credentials" in error_msg:
                raise Exception("Email o contraseña incorrectos")
            raise Exception(f"Error en login: {error_msg}")

    # ============================================
    # MÉTODO VERIFY_TOKEN
    # ============================================

    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None

        try:
            logger.debug(f"🔍 Verificando token con Supabase: {token[:30]}...")
            admin_client = self.get_admin_client()
            user_response = admin_client.auth.get_user(token)
            
            if user_response and user_response.user:
                user = user_response.user
                return {
                    "user_id": user.id,
                    "email": user.email,
                    "email_verified": user.email_confirmed_at is not None,
                    "username": user.user_metadata.get("username") if user.user_metadata else None,
                    "full_name": user.user_metadata.get("full_name") if user.user_metadata else None,
                    "user_metadata": user.user_metadata or {},
                    "created_at": user.created_at.isoformat() if user.created_at else None,
                    "last_sign_in_at": user.last_sign_in_at.isoformat() if user.last_sign_in_at else None
                }
                
        except Exception as e:
            logger.debug(f"⚠️ Verificación con Supabase falló: {str(e)[:100]}")
            
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                user_id = payload.get("sub")
                user_metadata = payload.get("user_metadata", {})
                
                return {
                    "user_id": user_id,
                    "email": payload.get("email"),
                    "email_verified": True,
                    "username": user_metadata.get("username"),
                    "full_name": user_metadata.get("full_name"),
                    "user_metadata": user_metadata,
                    "created_at": datetime.fromtimestamp(payload.get("iat", 0)).isoformat() if payload.get("iat") else None,
                    "last_sign_in_at": None
                }
                
            except jwt.ExpiredSignatureError:
                logger.warning("⚠️ Token local expirado")
                return None
            except jwt.InvalidTokenError:
                return None
            except Exception:
                return None

    # ============================================
    # MÉTODOS DE USUARIO
    # ============================================

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None

        try:
            admin_client = self.get_admin_client()
            user_response = admin_client.auth.admin.get_user_by_id(user_id)
            
            if not user_response or not user_response.user:
                return None

            user = user_response.user
            
            return {
                "user_id": user.id,
                "email": user.email,
                "email_verified": user.email_confirmed_at is not None,
                "username": user.user_metadata.get("username") if user.user_metadata else None,
                "full_name": user.user_metadata.get("full_name") if user.user_metadata else None,
                "user_metadata": user.user_metadata or {},
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_sign_in_at": user.last_sign_in_at.isoformat() if user.last_sign_in_at else None
            }
        except Exception as e:
            logger.error(f"❌ Error obteniendo usuario por ID {user_id}: {str(e)}")
            return None

    async def update_user(self, user_id: str, email: str = None, password: str = None, 
                          username: str = None, full_name: str = None, 
                          metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None

        try:
            admin_client = self.get_admin_client()
            current_user_data = await self.get_user_by_id(user_id)
            if not current_user_data:
                return None

            update_data = {}
            if email:
                update_data["email"] = email
            if password:
                update_data["password"] = password

            current_metadata = current_user_data.get("user_metadata", {}).copy()
            if username:
                current_metadata["username"] = username
            if full_name:
                current_metadata["full_name"] = full_name
            if metadata:
                current_metadata.update(metadata)

            update_data["user_metadata"] = current_metadata

            if update_data:
                response = admin_client.auth.admin.update_user_by_id(user_id, update_data)
                if response and response.user:
                    logger.info(f"✅ Usuario actualizado: {user_id}")
                    return await self.get_user_by_id(user_id)
            
            return current_user_data
        except Exception as e:
            logger.error(f"❌ Error actualizando usuario {user_id}: {str(e)}")
            return None

    async def update_profile(self, user_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None

        try:
            current_user_data = await self.get_user_by_id(user_id)
            if not current_user_data:
                return None

            current_metadata = current_user_data.get("user_metadata", {}).copy()
            
            changed = False
            for field in ["full_name", "bio", "avatar", "banner"]:
                if field in updates:
                    current_metadata[field] = updates[field]
                    changed = True

            if not changed:
                return current_user_data

            update_data = {"user_metadata": current_metadata}
            admin_client = self.get_admin_client()
            response = admin_client.auth.admin.update_user_by_id(user_id, update_data)
            
            if response and response.user:
                logger.info(f"✅ Perfil actualizado: {user_id}")
                return await self.get_user_by_id(user_id)
            
            return current_user_data
        except Exception as e:
            logger.error(f"❌ Error actualizando perfil {user_id}: {str(e)}")
            return None

    async def delete_user(self, user_id: str) -> bool:
        if not self.is_configured:
            return False
        try:
            admin_client = self.get_admin_client()
            admin_client.auth.admin.delete_user(user_id)
            logger.info(f"✅ Usuario eliminado: {user_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Error eliminando usuario {user_id}: {str(e)}")
            return False

    async def update_user_password(self, user_id: str, new_password: str) -> bool:
        logger.info(f"🔐 Actualizando contraseña para usuario: {user_id}")
        result = await self.update_user(user_id, password=new_password)
        return result is not None

    # ============================================
    # MÉTODOS PARA TOKEN_VERSION
    # ============================================

    async def get_token_version(self, user_id: str) -> int:
        try:
            user_data = await self.get_user_by_id(user_id)
            if not user_data:
                return 1
            return user_data.get("user_metadata", {}).get("token_version", 1)
        except Exception as e:
            logger.error(f"❌ Error obteniendo token_version: {e}")
            return 1

    async def increment_token_version(self, user_id: str) -> bool:
        try:
            current_version = await self.get_token_version(user_id)
            new_version = current_version + 1
            
            user_data = await self.get_user_by_id(user_id)
            if not user_data:
                return False
            
            current_metadata = user_data.get("user_metadata", {})
            new_metadata = {**current_metadata, "token_version": new_version}
            
            admin_client = self.get_admin_client()
            admin_client.auth.admin.update_user_by_id(user_id, {"user_metadata": new_metadata})
            
            logger.info(f"✅ Token_version incrementado: {current_version} → {new_version}")
            return True
        except Exception as e:
            logger.error(f"❌ Error incrementando token_version: {e}")
            return False

    async def verify_token_version(self, token: str, user_id: str) -> bool:
        try:
            current_version = await self.get_token_version(user_id)
            token_version = 1
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                token_version = payload.get("token_version", 1)
            except Exception:
                pass
            
            is_valid = token_version == current_version
            if not is_valid:
                logger.warning(f"⚠️ Token version mismatch para {user_id}")
            return is_valid
        except Exception as e:
            logger.error(f"❌ Error verificando token_version: {e}")
            return True

    def is_available(self) -> bool:
        available = self.is_configured and self._client is not None
        return available


# Instancia global
supabase_auth = SupabaseAuthService()