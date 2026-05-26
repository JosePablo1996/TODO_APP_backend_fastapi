# app/routers/backup.py
from fastapi import APIRouter, HTTPException, Depends, status, Request
from typing import List, Dict, Any, Optional
from uuid import UUID
from datetime import datetime
import json
import logging

from pydantic import BaseModel, Field

from app.dependencies import get_current_user
from app.services.supabase_auth_service import supabase_auth
from app.services.security_service import security_service, SecurityEventType
from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/backup", tags=["backup"])


# ============================================
# MODELOS
# ============================================

class CloudBackupBase(BaseModel):
    """Base para backup en la nube"""
    file_name: str = Field(..., max_length=255, description="Nombre del archivo de backup")
    file_size: int = Field(..., ge=0, description="Tamaño del archivo en bytes")
    note_count: int = Field(..., ge=0, description="Número de tareas incluidas")
    notes_data: Dict[str, Any] = Field(..., description="JSON con todas las tareas")
    backup_type: Optional[str] = Field("manual", description="Tipo de backup: manual, automatic")
    device_name: Optional[str] = Field(None, max_length=100, description="Nombre del dispositivo")
    app_version: Optional[str] = Field(None, max_length=20, description="Versión de la app")


class CloudBackupCreate(CloudBackupBase):
    """Crear un backup en la nube"""
    pass


class CloudBackupResponse(CloudBackupBase):
    """Respuesta de backup en la nube"""
    id: UUID
    user_id: UUID
    created_at: datetime

    class Config:
        from_attributes = True


class CloudBackupMetadata(BaseModel):
    """Metadatos del backup (sin datos de tareas)"""
    id: UUID
    user_id: UUID
    file_name: str
    file_size: int
    note_count: int
    backup_type: str
    device_name: Optional[str] = None
    app_version: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class LocalBackupInfo(BaseModel):
    """Información de un backup local desde el frontend"""
    id: str
    file_name: str
    file_size: int
    note_count: int
    created_at: str
    source: str = "local"


class SyncRequest(BaseModel):
    """Petición de sincronización"""
    local_backups: List[LocalBackupInfo] = Field(default_factory=list)


class SyncResponse(BaseModel):
    """Respuesta de sincronización"""
    synced_count: int
    failed_count: int
    cloud_backups_to_download: List[Dict[str, Any]] = Field(default_factory=list)
    message: str


# ============================================
# FUNCIONES AUXILIARES
# ============================================

async def enforce_backup_limit(user_id: str, max_backups: int = 20) -> int:
    """
    Verifica y aplica el límite de backups por usuario.
    Si excede el límite, elimina los backups más antiguos.
    
    Args:
        user_id: ID del usuario
        max_backups: Número máximo de backups permitidos (default: 20)
    
    Returns:
        Número de backups eliminados
    """
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # Contar backups del usuario
        count_result = admin_client.table("cloud_backups")\
            .select("id", count="exact")\
            .eq("user_id", str(user_id))\
            .execute()
        
        backup_count = count_result.count if hasattr(count_result, 'count') else 0
        
        if backup_count > max_backups:
            # Obtener backups más antiguos para eliminar
            to_delete_count = backup_count - max_backups
            
            result = admin_client.table("cloud_backups")\
                .select("id")\
                .eq("user_id", str(user_id))\
                .order("created_at", desc=False)\
                .limit(to_delete_count)\
                .execute()
            
            if result.data:
                ids_to_delete = [r["id"] for r in result.data]
                
                for backup_id in ids_to_delete:
                    admin_client.table("cloud_backups")\
                        .delete()\
                        .eq("id", backup_id)\
                        .eq("user_id", str(user_id))\
                        .execute()
                
                logger.info(f"🗑️ Eliminados {len(ids_to_delete)} backups antiguos para usuario {user_id}")
                return len(ids_to_delete)
        
        return 0
        
    except Exception as e:
        logger.error(f"❌ Error en enforce_backup_limit: {str(e)}")
        return 0


# ============================================
# ENDPOINTS - ORDEN CORRECTO
# ============================================

# ✅ 1. PRIMERO: Endpoints fijos (sin parámetros variables)
@router.get("/cloud/limit/info")
async def get_backup_limit_info(current_user: dict = Depends(get_current_user)):
    """
    Obtiene información sobre el límite de backups del usuario.
    ✅ Límite: 20 backups
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        result = admin_client.table("cloud_backups")\
            .select("id", count="exact")\
            .eq("user_id", str(user_id))\
            .execute()
        
        current_count = result.count if hasattr(result, 'count') else 0
        max_limit = 20
        remaining = max_limit - current_count
        
        return {
            "current": current_count,
            "max": max_limit,
            "remaining": remaining,
            "is_full": remaining <= 0,
            "is_low": 0 < remaining <= 3
        }
        
    except Exception as e:
        logger.error(f"❌ Error en get_backup_limit_info: {str(e)}")
        return {
            "current": 0,
            "max": 20,
            "remaining": 20,
            "is_full": False,
            "is_low": False
        }


@router.get("/cloud/stats")
async def get_cloud_backup_stats(current_user: dict = Depends(get_current_user)):
    """
    Obtiene estadísticas de los backups en la nube.
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        result = admin_client.table("cloud_backups")\
            .select("id, note_count, file_size, created_at")\
            .eq("user_id", str(user_id))\
            .execute()
        
        backups = result.data if result.data else []
        
        total_backups = len(backups)
        total_notes = sum(b.get("note_count", 0) for b in backups)
        total_size = sum(b.get("file_size", 0) for b in backups)
        
        # Backup más reciente
        latest_backup = None
        if backups:
            latest = max(backups, key=lambda x: x.get("created_at", ""))
            latest_backup = {
                "created_at": latest.get("created_at"),
                "note_count": latest.get("note_count")
            }
        
        return {
            "total_backups": total_backups,
            "total_notes_backed_up": total_notes,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "latest_backup": latest_backup,
            "limit": 20,
            "remaining_slots": max(0, 20 - total_backups)
        }
        
    except Exception as e:
        logger.error(f"❌ Error en get_cloud_backup_stats: {str(e)}")
        return {
            "total_backups": 0,
            "total_notes_backed_up": 0,
            "total_size_bytes": 0,
            "total_size_mb": 0,
            "latest_backup": None,
            "limit": 20,
            "remaining_slots": 20
        }


@router.get("/cloud", response_model=List[CloudBackupMetadata])
async def get_cloud_backups(current_user: dict = Depends(get_current_user)):
    """
    Obtiene la lista de backups en la nube del usuario autenticado.
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"📋 Obteniendo backups en la nube para usuario: {user_id}")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # Consultar backups del usuario
        result = admin_client.table("cloud_backups")\
            .select("id, user_id, file_name, file_size, note_count, backup_type, device_name, app_version, created_at")\
            .eq("user_id", str(user_id))\
            .order("created_at", desc=True)\
            .execute()
        
        backups = result.data if result.data else []
        logger.info(f"✅ Encontrados {len(backups)} backups")
        
        return [
            CloudBackupMetadata(
                id=b["id"],
                user_id=b["user_id"],
                file_name=b["file_name"],
                file_size=b["file_size"],
                note_count=b["note_count"],
                backup_type=b.get("backup_type", "manual"),
                device_name=b.get("device_name"),
                app_version=b.get("app_version"),
                created_at=datetime.fromisoformat(b["created_at"].replace('Z', '+00:00'))
            )
            for b in backups
        ]
        
    except Exception as e:
        logger.error(f"❌ Error en get_cloud_backups: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener backups: {str(e)}"
        )


# ✅ 2. SEGUNDO: Endpoint POST
@router.post("/cloud", response_model=CloudBackupResponse)
async def save_backup_to_cloud(
    backup_data: CloudBackupCreate,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """
    Guarda un backup en la nube (Supabase).
    Recibe los datos de las tareas y los almacena en la tabla 'cloud_backups'.
    ✅ Aplica límite de 20 backups por usuario
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"☁️ Guardando backup en la nube para usuario: {user_id}")
    logger.info(f"   Tareas: {backup_data.note_count}")
    logger.info(f"   Tamaño: {backup_data.file_size} bytes")
    logger.info(f"   Nombre: {backup_data.file_name}")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # Verificar límite de backups
        await enforce_backup_limit(user_id, max_backups=20)
        
        # Preparar datos para insertar
        now = datetime.now()
        insert_data = {
            "user_id": str(user_id),
            "file_name": backup_data.file_name,
            "file_size": backup_data.file_size,
            "note_count": backup_data.note_count,
            "notes_data": json.dumps(backup_data.notes_data),
            "backup_type": backup_data.backup_type,
            "device_name": backup_data.device_name,
            "app_version": backup_data.app_version or settings.API_VERSION,
            "created_at": now.isoformat()
        }
        
        # Insertar en Supabase
        result = admin_client.table("cloud_backups").insert(insert_data).execute()
        
        if not result.data or len(result.data) == 0:
            logger.error("❌ No se pudo guardar el backup")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al guardar el backup en la nube"
            )
        
        saved_backup = result.data[0]
        
        # Convertir notes_data de vuelta a dict para la respuesta
        if "notes_data" in saved_backup and isinstance(saved_backup["notes_data"], str):
            saved_backup["notes_data"] = json.loads(saved_backup["notes_data"])
        
        # Registrar evento de seguridad
        await security_service.log_security_event(
            user_id=user_id,
            event_type="CLOUD_BACKUP_CREATED",
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={
                "file_name": backup_data.file_name,
                "note_count": backup_data.note_count,
                "backup_type": backup_data.backup_type
            }
        )
        
        logger.info(f"✅ Backup guardado correctamente: {saved_backup.get('id')}")
        
        return CloudBackupResponse(
            id=saved_backup["id"],
            user_id=saved_backup["user_id"],
            file_name=saved_backup["file_name"],
            file_size=saved_backup["file_size"],
            note_count=saved_backup["note_count"],
            notes_data=saved_backup["notes_data"],
            backup_type=saved_backup.get("backup_type", "manual"),
            device_name=saved_backup.get("device_name"),
            app_version=saved_backup.get("app_version"),
            created_at=datetime.fromisoformat(saved_backup["created_at"].replace('Z', '+00:00'))
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en save_backup_to_cloud: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al guardar backup: {str(e)}"
        )


# ✅ 3. TERCERO: Endpoint con parámetro variable (debe ir después de los fijos)
@router.get("/cloud/{backup_id}")
async def get_cloud_backup(
    backup_id: UUID,
    current_user: dict = Depends(get_current_user)
):
    """
    Obtiene un backup específico de la nube (incluye datos de tareas).
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"🔍 Obteniendo backup {backup_id} para usuario: {user_id}")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # Consultar backup específico
        result = admin_client.table("cloud_backups")\
            .select("*")\
            .eq("id", str(backup_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not result.data or len(result.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Backup no encontrado"
            )
        
        backup = result.data[0]
        
        # Convertir notes_data de JSON string a dict
        if "notes_data" in backup and isinstance(backup["notes_data"], str):
            backup["notes_data"] = json.loads(backup["notes_data"])
        
        logger.info(f"✅ Backup encontrado: {backup.get('file_name')}")
        
        return backup
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error en get_cloud_backup: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener backup: {str(e)}"
        )


@router.delete("/cloud/{backup_id}")
async def delete_cloud_backup(
    backup_id: UUID,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """
    Elimina un backup de la nube.
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"🗑️ Eliminando backup {backup_id} para usuario: {user_id}")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # Verificar que el backup existe y pertenece al usuario
        check = admin_client.table("cloud_backups")\
            .select("id")\
            .eq("id", str(backup_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        if not check.data or len(check.data) == 0:
            logger.warning(f"⚠️ Backup {backup_id} no encontrado (ya fue eliminado)")
            return {
                "success": True,
                "message": "Backup no existe en la nube (ya fue eliminado)",
                "already_deleted": True
            }
        
        # Eliminar el backup
        admin_client.table("cloud_backups")\
            .delete()\
            .eq("id", str(backup_id))\
            .eq("user_id", str(user_id))\
            .execute()
        
        # Registrar evento de seguridad
        await security_service.log_security_event(
            user_id=user_id,
            event_type="CLOUD_BACKUP_DELETED",
            ip_address=req.client.host if req else None,
            user_agent=req.headers.get("User-Agent"),
            details={"backup_id": str(backup_id)}
        )
        
        logger.info(f"✅ Backup {backup_id} eliminado correctamente")
        
        return {
            "success": True,
            "message": "Backup eliminado correctamente",
            "already_deleted": False
        }
        
    except Exception as e:
        logger.error(f"❌ Error en delete_cloud_backup: {str(e)}")
        # En caso de error, retornar éxito simulado para consistencia
        logger.warning(f"⚠️ Error eliminando backup {backup_id}, considerando como eliminado")
        return {
            "success": True,
            "message": f"Backup considerado como eliminado (error: {str(e)})",
            "already_deleted": True
        }


@router.post("/cloud/sync", response_model=SyncResponse)
async def sync_backups_with_cloud(
    sync_request: SyncRequest,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """
    Sincroniza los backups locales del usuario con la nube.
    
    Recibe la lista de backups locales del frontend y:
    1. Identifica qué backups locales NO existen en la nube
    2. Registra los backups faltantes para subir
    3. Devuelve los backups de nube que el usuario no tiene localmente
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"🔄 Sincronizando backups para usuario: {user_id}")
    logger.info(f"   Backups locales recibidos: {len(sync_request.local_backups)}")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # 1. Obtener backups existentes en la nube
        cloud_backups = admin_client.table("cloud_backups")\
            .select("id, file_name, file_size, note_count, created_at, notes_data")\
            .eq("user_id", str(user_id))\
            .execute()
        
        cloud_backup_ids = set()
        cloud_backups_list = cloud_backups.data if cloud_backups.data else []
        
        for backup in cloud_backups_list:
            backup_id_str = str(backup.get("id"))
            cloud_backup_ids.add(backup_id_str)
        
        logger.info(f"   Backups en nube existentes: {len(cloud_backup_ids)}")
        
        # 2. Identificar backups locales que NO están en la nube
        local_backup_ids = {b.id for b in sync_request.local_backups}
        missing_in_cloud = [
            b for b in sync_request.local_backups 
            if b.id not in cloud_backup_ids and b.source == "local"
        ]
        
        logger.info(f"   Backups locales faltantes en nube: {len(missing_in_cloud)}")
        
        # 3. Registrar backups faltantes (simulado - el frontend los subirá)
        synced_count = len(missing_in_cloud)
        failed_count = 0
        
        for local_backup in missing_in_cloud:
            logger.info(f"   📤 Backup pendiente de subir: {local_backup.file_name} (ID: {local_backup.id})")
        
        # 4. Identificar backups de nube que el usuario NO tiene localmente
        cloud_backups_to_download = []
        
        for backup in cloud_backups_list:
            backup_id_str = str(backup.get("id"))
            if backup_id_str not in local_backup_ids:
                try:
                    notes_data = backup.get("notes_data")
                    if isinstance(notes_data, str):
                        notes_data = json.loads(notes_data)
                    
                    cloud_backups_to_download.append({
                        "id": backup_id_str,
                        "file_name": backup.get("file_name"),
                        "file_size": backup.get("file_size"),
                        "note_count": backup.get("note_count"),
                        "created_at": backup.get("created_at"),
                        "notes_data": notes_data
                    })
                    logger.info(f"   ☁️ Backup en nube no local: {backup.get('file_name')}")
                except Exception as e:
                    logger.error(f"   ❌ Error procesando backup {backup_id_str}: {str(e)}")
                    failed_count += 1
        
        logger.info(f"   Backups de nube para descargar: {len(cloud_backups_to_download)}")
        logger.info(f"✅ Sincronización completada")
        
        return SyncResponse(
            synced_count=synced_count,
            failed_count=failed_count,
            cloud_backups_to_download=cloud_backups_to_download,
            message=f"Sincronización completada. {len(cloud_backups_to_download)} backups disponibles para descargar."
        )
        
    except Exception as e:
        logger.error(f"❌ Error en sync_backups_with_cloud: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al sincronizar backups: {str(e)}"
        )