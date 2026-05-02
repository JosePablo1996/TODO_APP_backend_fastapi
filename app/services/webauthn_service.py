"""
Servicio para manejar WebAuthn/Passkeys
"""
import base64
import json
import logging
import os
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    RegistrationCredential,
    AuthenticationCredential,
)
from app.config import settings
from app.services.supabase_auth_service import supabase_auth

logger = logging.getLogger(__name__)


class WebAuthnService:
    """Servicio para manejar WebAuthn/Passkeys"""

    def __init__(self):
        # Obtener FRONTEND_URL de settings
        frontend_url = settings.FRONTEND_URL
        render_host = os.getenv("RENDER_EXTERNAL_HOSTNAME", "")
        is_render = bool(render_host)
        
        # ✅ CORREGIDO: Si FRONTEND_URL contiene localhost, usar localhost primero
        if frontend_url and "localhost" in frontend_url:
            self.rp_id = "localhost"
            self.origin = frontend_url
            logger.info(f"🏠 [WEBAUTHN] Usando configuración local (FRONTEND_URL={frontend_url})")
        elif is_render:
            self.rp_id = render_host
            self.origin = f"https://{render_host}"
            logger.info(f"🔄 [WEBAUTHN] Detectado entorno Render (sin localhost)")
        elif frontend_url:
            self.rp_id = frontend_url.replace("https://", "").replace("http://", "").split(":")[0]
            self.origin = frontend_url
            logger.info(f"🌐 [WEBAUTHN] Usando FRONTEND_URL configurado: {frontend_url}")
        else:
            self.rp_id = "localhost"
            self.origin = "http://localhost:5173"
            logger.info(f"🏠 [WEBAUTHN] Usando configuración por defecto (localhost)")
        
        self.rp_name = settings.API_TITLE

        # ✅ CORREGIDO: Orígenes permitidos en orden correcto (localhost PRIMERO)
        self.allowed_origins = [
            "http://localhost:5173",
            "http://localhost:8000",
            self.origin,
            "https://todo-app-backend-fastapi-klh2.onrender.com",
            "android:apk-key-hash:com.todoappmanager.flutter",
        ]
        # Eliminar duplicados manteniendo el orden
        self.allowed_origins = list(dict.fromkeys(self.allowed_origins))

        self.registration_challenges: Dict[str, Dict[str, Any]] = {}
        self.authentication_challenges: Dict[str, Dict[str, Any]] = {}

        logger.info(f"✅ WebAuthnService inicializado")
        logger.info(f"   RP ID: {self.rp_id}")
        logger.info(f"   RP Name: {self.rp_name}")
        logger.info(f"   Origin principal: {self.origin}")
        logger.info(f"   Orígenes permitidos: {self.allowed_origins}")
        logger.info(f"   Entorno: {'Render' if is_render else 'Local'}")

    def _encode_credential_id(self, credential_id: bytes) -> str:
        """Codifica credential_id a base64url"""
        return base64.urlsafe_b64encode(credential_id).decode('utf-8').rstrip('=')

    def _decode_credential_id(self, credential_id: str) -> bytes:
        """Decodifica credential_id de base64url"""
        padding = 4 - (len(credential_id) % 4)
        if padding != 4:
            credential_id += '=' * padding
        return base64.urlsafe_b64decode(credential_id)

    def _cleanup_expired_challenges(self):
        """Limpia challenges expirados (más de 5 minutos)"""
        now = datetime.now()
        expired_registration = []
        expired_authentication = []
        
        for user_id, data in self.registration_challenges.items():
            created_at = datetime.fromisoformat(data["created_at"])
            if now - created_at > timedelta(minutes=5):
                expired_registration.append(user_id)
        
        for user_id, data in self.authentication_challenges.items():
            created_at = datetime.fromisoformat(data["created_at"])
            if now - created_at > timedelta(minutes=5):
                expired_authentication.append(user_id)
        
        for user_id in expired_registration:
            del self.registration_challenges[user_id]
            logger.debug(f"🧹 Challenge de registro expirado limpiado para usuario: {user_id}")
        
        for user_id in expired_authentication:
            del self.authentication_challenges[user_id]
            logger.debug(f"🧹 Challenge de autenticación expirado limpiado para usuario: {user_id}")

    async def get_user_credentials(self, user_id: str) -> List[Dict[str, Any]]:
        """Obtiene todas las credenciales WebAuthn de un usuario"""
        logger.debug(f"📋 Obteniendo credenciales para usuario: {user_id}")
        
        if not supabase_auth.is_available():
            logger.warning("⚠️ Supabase no está disponible para obtener credenciales")
            return []

        try:
            admin_client = supabase_auth.get_admin_client()
            response = admin_client.table("user_passkeys").select("*").eq("user_id", user_id).execute()

            credentials = []
            for cred in response.data:
                credentials.append({
                    "id": cred["id"],
                    "credential_id": cred["credential_id"],
                    "device_name": cred.get("device_name"),
                    "device_type": cred.get("device_type"),
                    "created_at": cred["created_at"],
                    "last_used": cred.get("last_used")
                })

            logger.debug(f"   {len(credentials)} credenciales encontradas")
            return credentials
            
        except Exception as e:
            error_msg = str(e)
            if "PGRST205" in error_msg:
                logger.debug("ℹ️ Tabla user_passkeys aún no creada (se creará al primer uso)")
            else:
                logger.error(f"❌ Error obteniendo credenciales: {error_msg[:200]}")
            return []

    async def get_credential_by_id(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Obtiene una credencial por su ID"""
        logger.debug(f"🔍 Buscando credencial por ID: {credential_id[:20]}...")
        
        if not supabase_auth.is_available():
            logger.warning("⚠️ Supabase no está disponible para buscar credencial")
            return None

        try:
            admin_client = supabase_auth.get_admin_client()
            response = admin_client.table("user_passkeys").select("*").eq("credential_id", credential_id).execute()

            if response.data and len(response.data) > 0:
                cred = response.data[0]
                logger.debug(f"   ✅ Credencial encontrada para usuario: {cred['user_id']}")
                return cred

            logger.debug(f"   ⚠️ Credencial no encontrada")
            return None
            
        except Exception as e:
            error_msg = str(e)
            if "PGRST205" in error_msg:
                logger.debug("ℹ️ Tabla user_passkeys aún no creada")
            else:
                logger.error(f"❌ Error obteniendo credencial: {error_msg[:200]}")
            return None

    async def save_credential(
        self,
        user_id: str,
        credential_id: str,
        public_key: bytes,
        sign_count: int,
        device_name: Optional[str] = None,
        device_type: Optional[str] = None
    ) -> bool:
        """Guarda una nueva credencial WebAuthn"""
        logger.info(f"💾 Guardando credencial para usuario: {user_id}")
        logger.debug(f"   Credential ID: {credential_id[:20]}...")
        logger.debug(f"   Sign count: {sign_count}")
        logger.debug(f"   Device name: {device_name}")
        logger.debug(f"   Device type: {device_type}")
        
        if not supabase_auth.is_available():
            logger.error("❌ Supabase no está disponible para guardar credencial")
            return False

        try:
            admin_client = supabase_auth.get_admin_client()

            public_key_b64 = base64.b64encode(public_key).decode('utf-8')
            now = datetime.now().isoformat()

            credential_data = {
                "user_id": user_id,
                "credential_id": credential_id,
                "public_key": public_key_b64,
                "sign_count": sign_count,
                "device_name": device_name,
                "device_type": device_type,
                "created_at": now,
                "updated_at": now
            }

            logger.debug(f"   Insertando en tabla user_passkeys...")
            response = admin_client.table("user_passkeys").insert(credential_data).execute()

            if response.data and len(response.data) > 0:
                logger.info(f"✅ Credencial guardada exitosamente para usuario {user_id}")
                return True
            else:
                logger.error("❌ Error al guardar credencial - respuesta vacía")
                return False

        except Exception as e:
            error_msg = str(e)
            if "PGRST205" in error_msg:
                logger.error("❌ La tabla user_passkeys no existe en Supabase")
            else:
                logger.error(f"❌ Error guardando credencial: {error_msg[:200]}")
            return False

    async def update_credential_sign_count(self, credential_id: str, new_sign_count: int) -> bool:
        """Actualiza el sign_count de una credencial"""
        logger.debug(f"🔄 Actualizando sign_count para credencial: {credential_id[:20]}...")
        
        if not supabase_auth.is_available():
            logger.warning("⚠️ Supabase no está disponible para actualizar sign_count")
            return False

        try:
            admin_client = supabase_auth.get_admin_client()
            response = admin_client.table("user_passkeys").update({
                "sign_count": new_sign_count,
                "last_used": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }).eq("credential_id", credential_id).execute()

            success = len(response.data) > 0
            if success:
                logger.debug(f"✅ Sign_count actualizado exitosamente")
            return success
            
        except Exception as e:
            logger.error(f"❌ Error actualizando sign_count: {str(e)[:200]}")
            return False

    async def delete_credential(self, user_id: str, credential_id: str) -> bool:
        """Elimina una credencial WebAuthn"""
        logger.info(f"🗑️ Eliminando credencial para usuario: {user_id}")
        
        if not supabase_auth.is_available():
            logger.warning("⚠️ Supabase no está disponible para eliminar credencial")
            return False

        try:
            admin_client = supabase_auth.get_admin_client()
            response = admin_client.table("user_passkeys").delete().eq("user_id", user_id).eq("credential_id", credential_id).execute()

            success = len(response.data) > 0
            if success:
                logger.info(f"✅ Credencial eliminada exitosamente")
            return success
            
        except Exception as e:
            logger.error(f"❌ Error eliminando credencial: {str(e)[:200]}")
            return False

    # ============================================
    # GENERAR OPCIONES DE REGISTRO
    # ============================================

    async def generate_registration_options(
        self,
        user_id: str,
        email: str,
        username: str,
        device_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Genera opciones para registrar una nueva passkey"""
        logger.info(f"🔑 Generando opciones de registro para usuario: {user_id}")

        self._cleanup_expired_challenges()

        try:
            registration_options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=user_id.encode('utf-8'),
                user_name=username,
                user_display_name=email,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.PREFERRED,
                    authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM
                ),
                attestation="none"
            )

            challenge_b64 = base64.urlsafe_b64encode(registration_options.challenge).decode('utf-8').rstrip('=')

            self.registration_challenges[user_id] = {
                "challenge": challenge_b64,
                "challenge_bytes": registration_options.challenge,
                "created_at": datetime.now().isoformat()
            }
            
            logger.debug(f"   ✅ Challenge almacenado para usuario: {user_id}")

            return {
                "challenge": challenge_b64,
                "user_id": user_id,
                "username": username,
                "display_name": email,
                "rp_id": self.rp_id,
                "rp_name": self.rp_name,
                "attestation": "none",
                "pub_key_cred_params": [
                    {"type": "public-key", "alg": -7},
                    {"type": "public-key", "alg": -257}
                ]
            }

        except Exception as e:
            logger.error(f"❌ Error generando opciones de registro: {str(e)}", exc_info=True)
            raise

    # ============================================
    # VERIFICAR REGISTRO (CON SOPORTE JSON + CBOR)
    # ============================================

    async def verify_registration(
        self,
        user_id: str,
        credential_id: str,
        client_data_json: str,
        attestation_object: str,
        challenge: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Verifica la respuesta de registro de passkey (soporta JSON y CBOR)"""
        logger.info(f"🔐 Verificando registro para usuario: {user_id}")
        
        stored_data = self.registration_challenges.get(user_id)
        if not stored_data:
            logger.error(f"❌ No se encontró challenge almacenado para usuario: {user_id}")
            return False, None, "No se encontró challenge para verificación."
        
        stored_challenge_string = stored_data["challenge"]
        stored_challenge_bytes = stored_data["challenge_bytes"]
        
        logger.info(f"   🌐 RP ID: {self.rp_id}")
        logger.info(f"   🌐 Orígenes permitidos: {self.allowed_origins}")
        
        if challenge != stored_challenge_string:
            logger.error(f"❌ Challenge no coincide")
            return False, None, "Challenge no coincide."
        
        logger.info("   ✅ Challenge verificado correctamente")
        
        try:
            # Decodificar attestation_object
            padding = 4 - (len(attestation_object) % 4)
            if padding != 4:
                attestation_object += '=' * padding
            attestation_object_bytes = base64.urlsafe_b64decode(attestation_object)
            
            # ✅ Intentar detectar si es JSON (Flutter) o CBOR (Web)
            try:
                decoded_text = attestation_object_bytes.decode('utf-8')
                if decoded_text.startswith('{'):
                    logger.info("   📱 Detectado formato JSON (Flutter)")
                    return await self._verify_registration_json(
                        user_id=user_id,
                        credential_id=credential_id,
                        client_data_json=client_data_json,
                        attestation_json=decoded_text,
                        stored_challenge_bytes=stored_challenge_bytes,
                    )
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            
            # Es CBOR (Web)
            logger.info("   🌐 Detectado formato CBOR (Web)")
            return await self._verify_registration_cbor(
                user_id=user_id,
                credential_id=credential_id,
                client_data_json=client_data_json,
                attestation_object=attestation_object,
                stored_challenge_bytes=stored_challenge_bytes,
            )
            
        except Exception as e:
            logger.error(f"❌ Error verificando registro: {str(e)}", exc_info=True)
            return False, None, str(e)

    async def _verify_registration_json(
        self,
        user_id: str,
        credential_id: str,
        client_data_json: str,
        attestation_json: str,
        stored_challenge_bytes: bytes,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Verifica registro desde formato JSON (Flutter)"""
        try:
            attestation_data = json.loads(attestation_json)
            auth_data_b64 = attestation_data.get('authData', '')
            
            logger.debug(f"   authData (Base64URL): {auth_data_b64[:30]}...")
            
            credential_dict = {
                "id": credential_id,
                "rawId": credential_id,
                "type": "public-key",
                "response": {
                    "clientDataJSON": client_data_json,
                    "attestationObject": attestation_json.encode('utf-8'),
                }
            }
            
            # Intentar con cada origen permitido
            last_error = None
            for origin in self.allowed_origins:
                try:
                    logger.debug(f"   Intentando verificar con origin: {origin}")
                    
                    verification = verify_registration_response(
                        credential=credential_dict,
                        expected_challenge=stored_challenge_bytes,
                        expected_rp_id=self.rp_id,
                        expected_origin=origin,
                        require_user_verification=True,
                    )
                    
                    logger.info(f"✅ Registro JSON verificado con origin: {origin}")
                    
                    public_key = verification.credential_public_key
                    sign_count = verification.sign_count
                    
                    del self.registration_challenges[user_id]
                    
                    return True, {
                        "credential_id": credential_id,
                        "public_key": public_key,
                        "sign_count": sign_count
                    }, None
                    
                except Exception as e:
                    last_error = str(e)
                    logger.debug(f"   ❌ Falló con origin '{origin}': {last_error[:100]}")
                    continue
            
            logger.error(f"❌ Todos los orígenes fallaron. Último error: {last_error}")
            return False, None, f"Verificación JSON fallida: {last_error}"
            
        except Exception as e:
            logger.error(f"❌ Error en verificación JSON: {str(e)}")
            return False, None, str(e)

    async def _verify_registration_cbor(
        self,
        user_id: str,
        credential_id: str,
        client_data_json: str,
        attestation_object: str,
        stored_challenge_bytes: bytes,
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Verifica registro desde formato CBOR (Web)"""
        last_error = None
        
        credential_dict = {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json,
                "attestationObject": attestation_object,
            }
        }
        
        for origin in self.allowed_origins:
            try:
                logger.debug(f"   Intentando verificar CBOR con origin: {origin}")
                
                verification = verify_registration_response(
                    credential=credential_dict,
                    expected_challenge=stored_challenge_bytes,
                    expected_rp_id=self.rp_id,
                    expected_origin=origin,
                    require_user_verification=True,
                )
                
                logger.info(f"✅ Registro CBOR verificado con origin: {origin}")
                
                public_key = verification.credential_public_key
                sign_count = verification.sign_count
                
                del self.registration_challenges[user_id]
                
                return True, {
                    "credential_id": credential_id,
                    "public_key": public_key,
                    "sign_count": sign_count
                }, None
                
            except Exception as e:
                last_error = str(e)
                logger.debug(f"   ❌ Falló con origin '{origin}': {last_error[:100]}")
                continue
        
        logger.error(f"❌ Todos los orígenes fallaron. Último error: {last_error}")
        return False, None, f"Verificación CBOR fallida: {last_error}"

    # ============================================
    # GENERAR OPCIONES DE AUTENTICACIÓN
    # ============================================

    async def generate_authentication_options(
        self,
        user_id: Optional[str] = None,
        allowed_credentials: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Genera opciones para autenticación con passkey"""
        logger.info(f"🔑 Generando opciones de autenticación")

        self._cleanup_expired_challenges()

        try:
            allow_credentials = None
            if allowed_credentials:
                allow_credentials = [
                    {"id": cred["credential_id"], "type": "public-key"}
                    for cred in allowed_credentials
                ]

            auth_options = generate_authentication_options(
                rp_id=self.rp_id,
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.PREFERRED
            )

            challenge_b64 = base64.urlsafe_b64encode(auth_options.challenge).decode('utf-8').rstrip('=')

            session_id = user_id or "anonymous"
            self.authentication_challenges[session_id] = {
                "challenge": challenge_b64,
                "challenge_bytes": auth_options.challenge,
                "user_id": user_id,
                "created_at": datetime.now().isoformat()
            }

            logger.debug(f"   ✅ Challenge almacenado para sesión: {session_id}")

            return {
                "challenge": challenge_b64,
                "rp_id": self.rp_id,
                "allow_credentials": allow_credentials,
                "timeout": 60000
            }

        except Exception as e:
            logger.error(f"❌ Error generando opciones de autenticación: {str(e)}", exc_info=True)
            raise

    # ============================================
    # VERIFICAR AUTENTICACIÓN (CON MÚLTIPLES ORÍGENES)
    # ============================================

    async def verify_authentication(
        self,
        credential_id: str,
        client_data_json: str,
        authenticator_data: str,
        signature: str,
        challenge: str,
        stored_credential: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        """Verifica la respuesta de autenticación con passkey"""
        logger.info(f"🔐 Verificando autenticación")
        logger.debug(f"   RP ID: {self.rp_id}")
        logger.debug(f"   Orígenes permitidos: {self.allowed_origins}")

        session_id = user_id or "anonymous"
        stored_data = self.authentication_challenges.get(session_id)
        
        if not stored_data:
            logger.error(f"❌ No se encontró challenge almacenado para sesión: {session_id}")
            return False, None, "No se encontró challenge para verificación"
        
        stored_challenge_string = stored_data["challenge"]
        stored_challenge_bytes = stored_data["challenge_bytes"]
        
        if challenge != stored_challenge_string:
            logger.error(f"❌ Challenge no coincide")
            return False, None, "Challenge no coincide"
        
        logger.debug("   ✅ Challenge verificado correctamente")
        
        public_key_bytes = base64.b64decode(stored_credential["public_key"])
        
        credential_dict = {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json,
                "authenticatorData": authenticator_data,
                "signature": signature,
            }
        }
        
        # Intentar con cada origen permitido
        last_error = None
        for origin in self.allowed_origins:
            try:
                logger.debug(f"   Intentando verificar con origin: {origin}")
                
                verification = verify_authentication_response(
                    credential=credential_dict,
                    expected_challenge=stored_challenge_bytes,
                    expected_rp_id=self.rp_id,
                    expected_origin=origin,
                    credential_public_key=public_key_bytes,
                    credential_current_sign_count=stored_credential["sign_count"],
                    require_user_verification=True,
                )

                logger.info(f"✅ Autenticación verificada con origin: {origin}")
                
                if session_id in self.authentication_challenges:
                    del self.authentication_challenges[session_id]
                
                return True, verification.new_sign_count, None

            except Exception as e:
                last_error = str(e)
                logger.debug(f"   ❌ Falló con origin '{origin}': {last_error[:100]}")
                continue
        
        logger.error(f"❌ Todos los orígenes fallaron. Último error: {last_error}")
        return False, None, f"Autenticación fallida: {last_error}"


# Instancia global
webauthn_service = WebAuthnService()