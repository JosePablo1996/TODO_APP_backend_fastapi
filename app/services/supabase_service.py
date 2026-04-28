"""
Servicio para interactuar con Supabase Storage
"""
import httpx
from app.config import settings
import logging
from typing import Optional
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)


class SupabaseStorageService:
    """Servicio para interactuar con Supabase Storage usando HTTP directo"""

    def __init__(self):
        self.url = settings.SUPABASE_URL
        self.key = settings.SUPABASE_SERVICE_KEY
        self.is_configured = bool(self.url and self.key)
        
        if self.is_configured:
            self.storage_url = f"{self.url}/storage/v1"
            self.headers = {
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
                "apikey": self.key
            }
            self._verified_buckets = set()
            logger.info("✅ SupabaseStorageService inicializado correctamente")
        else:
            logger.warning("⚠️ Supabase Storage no configurado")
            self.storage_url = ""
            self.headers = {}

    async def ensure_bucket_exists(self, bucket: str) -> bool:
        """Verifica si un bucket existe y tiene permisos"""
        if not self.is_configured:
            return False
        
        if bucket in self._verified_buckets:
            return True

        try:
            list_url = f"{self.storage_url}/bucket"
            headers = {
                "Authorization": f"Bearer {self.key}",
                "apikey": self.key
            }
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(list_url, headers=headers)
                
                if response.status_code == 200:
                    buckets = response.json()
                    bucket_names = [b.get("name") for b in buckets]
                    
                    if bucket in bucket_names:
                        self._verified_buckets.add(bucket)
                        logger.info(f"✅ Bucket '{bucket}' existe")
                        return True
                    else:
                        logger.error(f"❌ Bucket '{bucket}' no existe. Buckets disponibles: {bucket_names}")
                        return False
                else:
                    logger.error(f"Error listando buckets: {response.status_code} - {response.text}")
                    return False
        except Exception as e:
            logger.error(f"Error verificando bucket: {str(e)}")
            return False

    async def upload_file_with_user_token(
        self,
        bucket: str,
        user_id: str,
        user_token: str,
        file_content: bytes,
        filename: str,
        content_type: str
    ) -> Optional[str]:
        """Sube un archivo a Supabase Storage usando el token del usuario"""
        if not self.is_configured:
            logger.error("❌ Supabase no está configurado")
            return None

        bucket_exists = await self.ensure_bucket_exists(bucket)
        if not bucket_exists:
            logger.error(f"❌ El bucket '{bucket}' no existe en Supabase")
            return None

        try:
            file_ext = filename.split('.')[-1] if '.' in filename else 'bin'
            timestamp = int(datetime.now().timestamp())
            unique_name = f"{user_id}/{timestamp}-{uuid.uuid4()}.{file_ext}"
            upload_url = f"{self.storage_url}/object/{bucket}/{unique_name}"
            
            headers = {
                "Authorization": f"Bearer {user_token}",
                "apikey": self.key,
                "Content-Type": content_type
            }
            
            logger.info(f"📤 Subiendo archivo: {bucket}/{unique_name}")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    upload_url,
                    headers=headers,
                    content=file_content
                )
                
                if response.status_code in [200, 201]:
                    # Construir la URL pública
                    public_url = f"{self.storage_url}/object/public/{bucket}/{unique_name}"
                    logger.info(f"✅ Archivo subido: {public_url}")
                    return public_url
                else:
                    logger.error(f"❌ Error subiendo: {response.status_code} - {response.text}")
                    return None
        except Exception as e:
            logger.error(f"❌ Excepción subiendo archivo: {str(e)}")
            return None

    async def delete_file(self, bucket: str, file_url: str) -> bool:
        """Elimina un archivo de Supabase Storage"""
        if not self.is_configured:
            return False

        try:
            # Extraer el path de la URL
            path = None
            
            # Patrones comunes en las URLs de Supabase
            patterns = [
                f"/public/{bucket}/",
                f"/object/public/{bucket}/",
                f"/object/{bucket}/"
            ]
            
            for pattern in patterns:
                if pattern in file_url:
                    path = file_url.split(pattern)[-1]
                    break
            
            # Fallback si el patrón exacto no coincide pero el bucket está presente
            if not path and f"/{bucket}/" in file_url:
                parts = file_url.split(f"/{bucket}/")
                if len(parts) > 1:
                    path = parts[-1]

            if not path:
                logger.error(f"No se pudo extraer el path de la URL: {file_url}")
                return False

            delete_url = f"{self.storage_url}/object/{bucket}/{path}"
            headers = {
                "Authorization": f"Bearer {self.key}",
                "apikey": self.key
            }
            
            logger.info(f"🗑️ Eliminando archivo: {bucket}/{path}")
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.delete(delete_url, headers=headers)
                
                if response.status_code in [200, 204]:
                    logger.info("✅ Archivo eliminado")
                    return True
                else:
                    logger.error(f"❌ Error eliminando: {response.status_code} - {response.text}")
                    return False
        except Exception as e:
            logger.error(f"❌ Excepción eliminando archivo: {str(e)}")
            return False

    async def test_connection(self) -> dict:
        """Prueba la conexión con Supabase"""
        result = {
            "configured": self.is_configured,
            "url": self.url,
            "storage_url": self.storage_url,
            "buckets": [],
            "error": None
        }

        if not self.is_configured:
            result["error"] = "Supabase no está configurado"
            return result

        try:
            list_url = f"{self.storage_url}/bucket"
            headers = {
                "Authorization": f"Bearer {self.key}",
                "apikey": self.key
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(list_url, headers=headers)
                
                if response.status_code == 200:
                    buckets = response.json()
                    result["buckets"] = [b.get("name") for b in buckets]
                    result["success"] = True
                else:
                    result["error"] = f"Error {response.status_code}: {response.text}"
        except Exception as e:
            result["error"] = str(e)
            
        return result


# Instancia global
supabase_storage = SupabaseStorageService()