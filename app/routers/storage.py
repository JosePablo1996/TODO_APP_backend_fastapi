# app/routers/storage.py
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from typing import Optional, List
import logging
import httpx
import uuid
from datetime import datetime
from app.dependencies import get_current_user
from app.config import settings

router = APIRouter(prefix="/api/storage", tags=["storage"])
logger = logging.getLogger(__name__)

# ============================================
# SERVICIO DE SUPABASE
# ============================================

class SupabaseStorageService:
    """Servicio para interactuar con Supabase Storage"""
    
    def __init__(self):
        self.url = settings.SUPABASE_URL
        self.key = settings.SUPABASE_SERVICE_KEY
        self.storage_url = f"{self.url}/storage/v1" if self.url else None
        self.is_configured = bool(self.url and self.key)
        # Cache de buckets verificados
        self._verified_buckets = set()
        
        if self.is_configured:
            logger.info("✅ Supabase Storage configurado en storage.py")
        else:
            logger.warning("⚠️ Supabase Storage no configurado")
    
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
    
    async def upload_file(
        self, 
        bucket: str, 
        user_id: str, 
        file_content: bytes, 
        filename: str, 
        content_type: str
    ) -> Optional[str]:
        """Sube un archivo a Supabase Storage"""
        if not self.is_configured:
            logger.error("Supabase no está configurado")
            return None
        
        # Verificar que el bucket existe
        bucket_exists = await self.ensure_bucket_exists(bucket)
        if not bucket_exists:
            logger.error(f"❌ El bucket '{bucket}' no existe en Supabase")
            return None
        
        try:
            # Generar nombre único
            file_ext = filename.split('.')[-1] if '.' in filename else 'bin'
            timestamp = int(datetime.now().timestamp())
            unique_name = f"{user_id}/{timestamp}-{uuid.uuid4()}.{file_ext}"
            
            upload_url = f"{self.storage_url}/object/{bucket}/{unique_name}"
            
            headers = {
                "Authorization": f"Bearer {self.key}",
                "apikey": self.key,
                "Content-Type": content_type
            }
            
            logger.info(f"📤 Subiendo archivo a Supabase: {bucket}/{unique_name}")
            logger.info(f"   Tamaño: {len(file_content)} bytes")
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    upload_url,
                    headers=headers,
                    content=file_content
                )
                
                if response.status_code in [200, 201]:
                    # Obtener URL pública
                    public_url = f"{self.storage_url}/object/public/{bucket}/{unique_name}"
                    logger.info(f"✅ Archivo subido exitosamente: {public_url}")
                    return public_url
                else:
                    logger.error(f"❌ Error subiendo archivo: {response.status_code} - {response.text}")
                    return None
                    
        except httpx.TimeoutException:
            logger.error(f"⏰ Timeout al subir archivo a Supabase")
            return None
        except Exception as e:
            logger.error(f"❌ Excepción subiendo archivo: {str(e)}")
            return None
    
    async def delete_file(self, bucket: str, file_url: str) -> bool:
        """Elimina un archivo de Supabase Storage"""
        if not self.is_configured:
            return False
        
        try:
            # Extraer el path de la URL - soporta múltiples formatos
            path = None
            
            # Patrones comunes de URL de Supabase
            patterns = [
                f"/public/{bucket}/",
                f"/object/public/{bucket}/",
                f"/object/{bucket}/"
            ]
            
            for pattern in patterns:
                if pattern in file_url:
                    path = file_url.split(pattern)[-1]
                    break
            
            # Si no se encontró con los patrones, intentar con el bucket
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
                    logger.info("✅ Archivo eliminado exitosamente")
                    return True
                else:
                    logger.error(f"❌ Error eliminando archivo: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Excepción eliminando archivo: {str(e)}")
            return False
    
    async def get_file_url(self, bucket: str, file_path: str) -> Optional[str]:
        """Obtiene la URL pública de un archivo"""
        if not self.is_configured:
            return None
        
        try:
            public_url = f"{self.storage_url}/object/public/{bucket}/{file_path}"
            return public_url
        except Exception as e:
            logger.error(f"Error obteniendo URL pública: {str(e)}")
            return None

# Instancia global
storage_service = SupabaseStorageService()

# ============================================
# ENDPOINTS DE STORAGE
# ============================================

@router.post("/upload", response_model=dict)
async def upload_file(
    bucket: str,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint genérico para subir archivos a un bucket específico
    
    - **bucket**: Nombre del bucket (avatars, banners, etc.)
    - **file**: Archivo a subir (imagen, documento, etc.)
    """
    if not storage_service.is_configured:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase no está configurado"
        )
    
    # Validar que el bucket es válido
    allowed_buckets = ["avatars", "banners", "uploads"]
    if bucket not in allowed_buckets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Bucket no permitido. Permitidos: {', '.join(allowed_buckets)}"
        )
    
    # Validar tipo de archivo
    allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tipo de archivo no permitido. Permitidos: {', '.join(allowed_types)}"
        )
    
    # Validar tamaño (5MB por defecto, 2MB para avatars)
    max_size = 5 * 1024 * 1024
    if bucket == "avatars":
        max_size = 2 * 1024 * 1024
    
    content = await file.read()
    
    if len(content) > max_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Archivo demasiado grande. Máximo {max_size // (1024 * 1024)}MB"
        )
    
    # Subir archivo
    url = await storage_service.upload_file(
        bucket=bucket,
        user_id=current_user["sub"],
        file_content=content,
        filename=file.filename or "file.bin",
        content_type=file.content_type
    )
    
    if not url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error subiendo archivo a Supabase"
        )
    
    return {
        "message": "Archivo subido correctamente",
        "url": url,
        "bucket": bucket,
        "filename": file.filename,
        "size": len(content)
    }


@router.delete("/{bucket}/{path:path}", response_model=dict)
async def delete_file_by_path(
    bucket: str,
    path: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint para eliminar archivos usando bucket y path
    
    - **bucket**: Nombre del bucket (avatars, banners, etc.)
    - **path**: Ruta del archivo dentro del bucket
    """
    if not storage_service.is_configured:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase no está configurado"
        )
    
    # Validar que el bucket es válido
    allowed_buckets = ["avatars", "banners", "uploads"]
    if bucket not in allowed_buckets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Bucket no permitido. Permitidos: {', '.join(allowed_buckets)}"
        )
    
    # Validar que el path pertenece al usuario actual (seguridad)
    user_id = current_user["sub"]
    if not path.startswith(user_id):
        logger.warning(f"⚠️ Usuario {user_id} intentando eliminar archivo de otro usuario: {path}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para eliminar este archivo"
        )
    
    success = await storage_service.delete_file(bucket, f"/object/{bucket}/{path}")
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error eliminando archivo"
        )
    
    return {
        "message": "Archivo eliminado correctamente",
        "bucket": bucket,
        "path": path,
        "success": True
    }


@router.delete("/delete", response_model=dict)
async def delete_file_by_url(
    bucket: str,
    file_url: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint para eliminar archivos usando la URL completa
    
    - **bucket**: Nombre del bucket (avatars, banners, etc.)
    - **file_url**: URL completa del archivo
    """
    if not storage_service.is_configured:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase no está configurado"
        )
    
    # Validar que el bucket es válido
    allowed_buckets = ["avatars", "banners", "uploads"]
    if bucket not in allowed_buckets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Bucket no permitido. Permitidos: {', '.join(allowed_buckets)}"
        )
    
    # Validar que la URL pertenece al usuario actual (seguridad)
    user_id = current_user["sub"]
    if user_id not in file_url:
        logger.warning(f"⚠️ Usuario {user_id} intentando eliminar archivo de otro usuario: {file_url}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para eliminar este archivo"
        )
    
    success = await storage_service.delete_file(bucket, file_url)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error eliminando archivo"
        )
    
    return {
        "message": "Archivo eliminado correctamente",
        "url": file_url,
        "bucket": bucket,
        "success": True
    }


@router.get("/buckets", response_model=dict)
async def list_buckets(
    current_user: dict = Depends(get_current_user)
):
    """
    Lista los buckets disponibles (solo admin)
    """
    if not storage_service.is_configured:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase no está configurado"
        )
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            headers = {
                "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                "apikey": settings.SUPABASE_SERVICE_KEY
            }
            response = await client.get(
                f"{settings.SUPABASE_URL}/storage/v1/bucket",
                headers=headers
            )
            
            if response.status_code == 200:
                buckets = response.json()
                return {
                    "buckets": buckets,
                    "count": len(buckets)
                }
            else:
                logger.error(f"Error listando buckets: {response.status_code} - {response.text}")
                return {
                    "buckets": [],
                    "count": 0,
                    "error": response.text
                }
    except httpx.TimeoutException:
        logger.error("Timeout al listar buckets")
        return {
            "buckets": [],
            "count": 0,
            "error": "Timeout de conexión con Supabase"
        }
    except Exception as e:
        logger.error(f"Error listando buckets: {str(e)}")
        return {
            "buckets": [],
            "count": 0,
            "error": str(e)
        }


@router.get("/health", response_model=dict)
async def storage_health_check():
    """
    Verifica el estado del servicio de storage
    """
    if not storage_service.is_configured:
        return {
            "status": "unconfigured",
            "message": "Supabase Storage no está configurado",
            "url": None
        }
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            headers = {
                "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                "apikey": settings.SUPABASE_SERVICE_KEY
            }
            response = await client.get(
                f"{settings.SUPABASE_URL}/storage/v1/bucket",
                headers=headers
            )
            
            if response.status_code == 200:
                return {
                    "status": "healthy",
                    "message": "Supabase Storage está funcionando correctamente",
                    "url": settings.SUPABASE_URL,
                    "buckets_count": len(response.json())
                }
            else:
                return {
                    "status": "unhealthy",
                    "message": f"Error conectando con Supabase: {response.status_code}",
                    "url": settings.SUPABASE_URL
                }
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Error: {str(e)}",
            "url": settings.SUPABASE_URL
        }


@router.post("/test-upload", response_model=dict)
async def test_upload(
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint de prueba para verificar que el storage funciona
    """
    if not storage_service.is_configured:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Supabase no está configurado"
        )
    
    # Probar conexión con Supabase
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            headers = {
                "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                "apikey": settings.SUPABASE_SERVICE_KEY
            }
            response = await client.get(
                f"{settings.SUPABASE_URL}/storage/v1/bucket",
                headers=headers
            )
            
            if response.status_code == 200:
                buckets = response.json()
                bucket_names = [b.get("name") for b in buckets]
                
                return {
                    "success": True,
                    "message": "Conexión con Supabase exitosa",
                    "buckets": bucket_names,
                    "user_id": current_user["sub"]
                }
            else:
                return {
                    "success": False,
                    "message": f"Error conectando con Supabase: {response.status_code}",
                    "response": response.text
                }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }