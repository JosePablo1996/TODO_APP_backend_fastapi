# app/services/supabase_auth_service.py
"""
Servicio de autenticación con Supabase Auth
Maneja registro, login, verificación de tokens y gestión de usuarios
"""
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import jwt
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
                # Cliente con service role key (operaciones administrativas)
                self._client = create_client(self.url, self.service_key)
                
                # Cliente con anon key (operaciones de usuario)
                if self.anon_key:
                    self._anon_client = create_client(self.url, self.anon_key)
                    
                logger.info("✅ SupabaseAuthService inicializado correctamente")
                logger.info(f"   URL: {self.url}")
                logger.info(f"   Service Key: {self.service_key[:20]}...")
                
                # Verificar conexión con la tabla user_passkeys (no crítico)
                self._check_webauthn_table()
                
            except Exception as e:
                logger.error(f"❌ Error inicializando SupabaseAuthService: {str(e)}", exc_info=True)
                self._client = None
                self._anon_client = None
        else:
            logger.warning("⚠️ SupabaseAuthService no configurado - Supabase no disponible")

    @property
    def client(self) -> Optional[Client]:
        """Retorna el cliente admin (service role)"""
        return self._client

    @property
    def anon_client(self) -> Optional[Client]:
        """Retorna el cliente anónimo para operaciones de usuario"""
        return self._anon_client

    def _check_webauthn_table(self):
        """Verifica que la tabla user_passkeys exista (no crítico)"""
        try:
            if self._client:
                logger.info("🔍 Verificando tabla public.user_passkeys...")
                response = self._client.table("user_passkeys").select("id").limit(1).execute()
                logger.info("✅ Tabla public.user_passkeys existe y es accesible")
                return True
        except Exception as e:
            error_msg = str(e)
            if "PGRST205" in error_msg:
                logger.debug("ℹ️ Tabla public.user_passkeys no encontrada (se creará cuando se use)")
            else:
                logger.warning(f"⚠️ Error verificando tabla user_passkeys: {error_msg[:100]}")
            return False

    def get_admin_client(self) -> Client:
        """Obtiene el cliente con service role key (para operaciones admin)"""
        if not self._client:
            raise Exception("Supabase Auth no está configurado")
        return self._client

    def get_authenticated_client(self, access_token: str) -> Client:
        """
        Crea un cliente autenticado con el token del usuario
        Útil para operaciones que requieren el contexto del usuario
        """
        if not self.url or not self.anon_key:
            raise Exception("Supabase no está configurado")
        
        client = create_client(
            self.url,
            self.anon_key,
            options={
                "headers": {
                    "Authorization": f"Bearer {access_token}"
                }
            }
        )
        return client

    # ============================================
    # MÉTODO CREATE_USER
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
        Crea un nuevo usuario en Supabase Auth
        """
        logger.info(f"📝 Creando usuario en Supabase: {email}")
        
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
            raise Exception("Supabase no está configurado")
        
        try:
            admin_client = self.get_admin_client()
            
            # Preparar metadatos del usuario
            metadata = user_metadata or {}
            if username:
                metadata["username"] = username
            if full_name:
                metadata["full_name"] = full_name
            
            # Inicializar token_version en 1 para nuevos usuarios
            metadata["token_version"] = 1
            
            # Preparar datos del usuario
            user_data = {
                "email": email,
                "password": password,
                "email_confirm": True,
                "user_metadata": metadata
            }
            
            logger.debug(f"   Creando usuario con datos: email={email}, username={username}")
            
            # Crear usuario usando el cliente admin de Supabase
            response = admin_client.auth.admin.create_user(user_data)
            
            if not response or not response.user:
                logger.error("❌ No se pudo crear el usuario")
                return None
            
            user = response.user
            logger.info(f"✅ Usuario creado exitosamente: {email} (ID: {user.id})")
            
            # Crear perfil en la tabla profiles
            try:
                profile_data = {
                    "id": user.id,
                    "email": email,
                    "username": username or email.split('@')[0],
                    "full_name": full_name or "",
                    "created_at": datetime.now().isoformat()
                }
                
                admin_client.table("profiles").insert(profile_data).execute()
                logger.info(f"✅ Perfil creado para usuario: {user.id}")
            except Exception as profile_error:
                logger.warning(f"⚠️ Error creando perfil (no crítico): {profile_error}")
            
            return {
                "user_id": user.id,
                "email": user.email,
                "username": username or email.split('@')[0],
                "created_at": user.created_at,
                "user_metadata": user.user_metadata or {}
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Error creando usuario en Supabase: {error_msg}")
            
            if "User already registered" in error_msg or "already exists" in error_msg:
                raise Exception("El usuario ya existe")
            elif "password" in error_msg.lower():
                raise Exception("La contraseña no cumple con los requisitos de seguridad")
            else:
                raise Exception(f"Error creando usuario: {error_msg}")

    # ============================================
    # MÉTODO LOGIN
    # ============================================
    
    async def login(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Inicia sesión con email y contraseña en Supabase Auth
        """
        logger.info(f"🔐 Intentando login para: {email}")
        
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
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
            else:
                raise Exception(f"Error en login: {error_msg}")

    # ============================================
    # MÉTODO VERIFY_TOKEN - ACTUALIZADO (maneja ambos tipos de tokens)
    # ============================================

    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verifica un token JWT y retorna la información del usuario
        Soporta:
        1. Tokens de Supabase (para login con email/contraseña)
        2. Tokens generados localmente (para login con passkey)
        """
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
            return None

        # ✅ PRIMERO: Intentar verificar con Supabase
        try:
            logger.debug(f"🔍 Verificando token con Supabase: {token[:30]}...")
            admin_client = self.get_admin_client()
            user_response = admin_client.auth.get_user(token)
            
            if user_response and user_response.user:
                user = user_response.user
                logger.debug(f"✅ Token válido para usuario (Supabase): {user.id}")
                
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
            error_msg = str(e)
            logger.debug(f"⚠️ Verificación con Supabase falló: {error_msg[:100]}")
            
            # ✅ SEGUNDO: Intentar verificar con nuestro propio JWT (para passkey login)
            try:
                logger.debug(f"🔍 Intentando verificar token local: {token[:30]}...")
                
                # Decodificar el token con nuestra SECRET_KEY
                payload = jwt.decode(
                    token, 
                    settings.SECRET_KEY, 
                    algorithms=["HS256"]
                )
                
                user_id = payload.get("sub")
                logger.debug(f"✅ Token local válido para usuario: {user_id}")
                
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
            except jwt.InvalidTokenError as jwt_error:
                logger.error(f"❌ Token local inválido: {jwt_error}")
                return None
            except Exception as e:
                logger.error(f"❌ Error verificando token local: {e}")
                return None

    # ============================================
    # MÉTODOS DE USUARIO
    # ============================================

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene información de un usuario por su ID
        """
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
            return None

        try:
            logger.debug(f"🔍 Obteniendo usuario por ID: {user_id}")
            admin_client = self.get_admin_client()
            user_response = admin_client.auth.admin.get_user_by_id(user_id)
            
            if not user_response or not user_response.user:
                logger.warning(f"⚠️ Usuario no encontrado: {user_id}")
                return None

            user = user_response.user
            logger.debug(f"✅ Usuario encontrado: {user.email}")
            
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
            logger.error(f"❌ Error obteniendo usuario por ID {user_id}: {str(e)}", exc_info=True)
            return None

    async def update_user(self, user_id: str, email: str = None, password: str = None, 
                          username: str = None, full_name: str = None, metadata: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Actualiza un usuario en Supabase Auth
        """
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
            return None

        try:
            logger.info(f"✏️ Actualizando usuario: {user_id}")
            admin_client = self.get_admin_client()
            
            current_user_data = await self.get_user_by_id(user_id)
            if not current_user_data:
                logger.error(f"❌ Usuario no encontrado: {user_id}")
                return None

            update_data = {}
            if email:
                update_data["email"] = email
                logger.debug(f"   Actualizando email: {email}")
            if password:
                update_data["password"] = password
                logger.debug(f"   Actualizando password")

            current_metadata = current_user_data.get("user_metadata", {})
            new_metadata = current_metadata.copy()

            if username:
                new_metadata["username"] = username
                logger.debug(f"   Actualizando username: {username}")
            if full_name:
                new_metadata["full_name"] = full_name
                logger.debug(f"   Actualizando full_name: {full_name}")
            
            if metadata:
                new_metadata.update(metadata)
                logger.debug(f"   Actualizando metadata adicional")

            if new_metadata != current_metadata:
                update_data["user_metadata"] = new_metadata
                logger.debug(f"   Metadata actualizada")

            if update_data:
                response = admin_client.auth.admin.update_user_by_id(user_id, update_data)
                if response and response.user:
                    logger.info(f"✅ Usuario actualizado exitosamente: {user_id}")
                    return await self.get_user_by_id(user_id)
            
            logger.info(f"ℹ️ No se realizaron cambios para usuario: {user_id}")
            return current_user_data

        except Exception as e:
            logger.error(f"❌ Error actualizando usuario {user_id}: {str(e)}", exc_info=True)
            return None

    async def update_profile(self, user_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Método específico para actualizar el perfil (full_name, bio, avatar, banner)
        """
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
            return None

        try:
            logger.info(f"✏️ Actualizando perfil para usuario: {user_id}")
            logger.debug(f"   Actualizaciones: {list(updates.keys())}")
            
            current_user_data = await self.get_user_by_id(user_id)
            if not current_user_data:
                logger.error(f"❌ Usuario no encontrado: {user_id}")
                return None

            current_metadata = current_user_data.get("user_metadata", {}).copy()
            
            changed = False
            if "full_name" in updates:
                current_metadata["full_name"] = updates["full_name"]
                changed = True
                logger.debug(f"   Actualizando full_name: {updates['full_name']}")
            if "bio" in updates:
                current_metadata["bio"] = updates["bio"]
                changed = True
                logger.debug(f"   Actualizando bio: {updates['bio'][:50]}...")
            if "avatar" in updates:
                current_metadata["avatar"] = updates["avatar"]
                changed = True
                logger.debug(f"   Actualizando avatar: {updates['avatar'][:50]}...")
            if "banner" in updates:
                current_metadata["banner"] = updates["banner"]
                changed = True
                logger.debug(f"   Actualizando banner: {updates['banner'][:50]}...")

            if not changed:
                logger.info(f"ℹ️ No se realizaron cambios en el perfil")
                return current_user_data

            update_data = {"user_metadata": current_metadata}
            admin_client = self.get_admin_client()
            response = admin_client.auth.admin.update_user_by_id(user_id, update_data)
            
            if response and response.user:
                logger.info(f"✅ Perfil actualizado exitosamente para usuario: {user_id}")
                return await self.get_user_by_id(user_id)
            
            logger.warning(f"⚠️ No se pudo actualizar el perfil para usuario: {user_id}")
            return current_user_data

        except Exception as e:
            logger.error(f"❌ Error actualizando perfil para usuario {user_id}: {str(e)}", exc_info=True)
            return None

    async def delete_user(self, user_id: str) -> bool:
        """Elimina un usuario de Supabase Auth"""
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
            return False
        try:
            logger.info(f"🗑️ Eliminando usuario: {user_id}")
            admin_client = self.get_admin_client()
            admin_client.auth.admin.delete_user(user_id)
            logger.info(f"✅ Usuario eliminado exitosamente: {user_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Error eliminando usuario {user_id}: {str(e)}", exc_info=True)
            return False

    async def update_user_password(self, user_id: str, new_password: str) -> bool:
        """Actualiza la contraseña de un usuario"""
        logger.info(f"🔐 Actualizando contraseña para usuario: {user_id}")
        result = await self.update_user(user_id, password=new_password)
        if result:
            logger.info(f"✅ Contraseña actualizada exitosamente")
        else:
            logger.error(f"❌ Error actualizando contraseña")
        return result is not None

    # ============================================
    # MÉTODOS PARA TOKEN_VERSION (Cierre de sesiones activas)
    # ============================================

    async def get_token_version(self, user_id: str) -> int:
        """
        Obtiene la versión actual del token para un usuario
        Si no existe, retorna 1 (versión inicial)
        """
        try:
            user_data = await self.get_user_by_id(user_id)
            if not user_data:
                logger.warning(f"⚠️ Usuario no encontrado para token_version: {user_id}")
                return 1
            
            user_metadata = user_data.get("user_metadata", {})
            token_version = user_metadata.get("token_version", 1)
            
            logger.debug(f"📌 Token version para {user_id}: {token_version}")
            return token_version
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo token_version para {user_id}: {e}")
            return 1  # Valor por defecto seguro

    async def increment_token_version(self, user_id: str) -> bool:
        """
        Incrementa la versión del token para un usuario
        Esto invalida TODAS las sesiones activas anteriores
        Retorna True si fue exitoso, False si no
        """
        try:
            logger.info(f"🔄 Incrementando token_version para usuario: {user_id}")
            
            # Obtener versión actual
            current_version = await self.get_token_version(user_id)
            new_version = current_version + 1
            
            # Obtener usuario actual para preservar otros metadatos
            user_data = await self.get_user_by_id(user_id)
            if not user_data:
                logger.error(f"❌ No se encontró usuario: {user_id}")
                return False
            
            current_metadata = user_data.get("user_metadata", {})
            new_metadata = {**current_metadata, "token_version": new_version}
            
            # Actualizar metadata en Supabase Auth
            admin_client = self.get_admin_client()
            admin_client.auth.admin.update_user_by_id(
                user_id,
                {"user_metadata": new_metadata}
            )
            
            logger.info(f"✅ Token_version incrementado: {current_version} → {new_version} para {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error incrementando token_version para {user_id}: {e}")
            return False

    async def verify_token_version(self, token: str, user_id: str) -> bool:
        """
        Verifica que la versión del token coincida con la versión actual del usuario
        Retorna True si es válido, False si está desactualizado
        """
        try:
            # Obtener versión actual del usuario
            current_version = await self.get_token_version(user_id)
            
            # Intentar extraer versión del token (si está en el payload)
            token_version = 1  # Valor por defecto
            
            try:
                # Decodificar sin verificar firma solo para leer metadata
                payload = jwt.decode(token, options={"verify_signature": False})
                token_version = payload.get("token_version", 1)
            except Exception as e:
                logger.debug(f"⚠️ No se pudo extraer token_version del payload: {e}")
            
            is_valid = token_version == current_version
            
            if not is_valid:
                logger.warning(f"⚠️ Token version mismatch para {user_id}: "
                             f"token={token_version}, current={current_version}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"❌ Error verificando token_version: {e}")
            return True  # En caso de error, permitir acceso (fail open)

    def is_available(self) -> bool:
        """Verifica si el servicio está disponible"""
        available = self.is_configured and self._client is not None
        if not available:
            logger.debug(f"⚠️ SupabaseAuthService no disponible")
        return available


# Instancia global
supabase_auth = SupabaseAuthService()