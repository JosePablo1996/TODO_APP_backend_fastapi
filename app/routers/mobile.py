# app/routers/mobile.py (NUEVO)
"""
Router específico para funcionalidades de app móvil
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging
from app.dependencies import get_current_user, get_auth_token
from app.services.supabase_auth_service import supabase_auth
from app.config import settings

router = APIRouter(prefix="/api/mobile", tags=["mobile"])
logger = logging.getLogger(__name__)

# ============================================
# MODELOS ESPECÍFICOS PARA MÓVIL
# ============================================

class DeviceRegistrationRequest(BaseModel):
    """Registro de dispositivo para notificaciones push"""
    device_token: str = Field(..., description="Token FCM/APNs del dispositivo")
    platform: str = Field(..., description="ios o android")
    device_name: Optional[str] = None
    device_model: Optional[str] = None
    app_version: Optional[str] = None

class SyncRequest(BaseModel):
    """Solicitud de sincronización"""
    last_sync_timestamp: str = Field(..., description="Timestamp ISO de última sincronización")
    device_id: Optional[str] = None

class SyncResponse(BaseModel):
    """Respuesta de sincronización"""
    tasks_created: List[Dict[str, Any]] = []
    tasks_updated: List[Dict[str, Any]] = []
    tasks_deleted: List[str] = []
    profile_updated: Optional[Dict[str, Any]] = None
    server_timestamp: str
    has_more: bool = False

class OfflineActionRequest(BaseModel):
    """Acción realizada offline para sincronizar"""
    action_type: str = Field(..., description="create, update, delete")
    resource_type: str = Field(..., description="task, profile")
    resource_id: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    client_timestamp: str
    device_id: str

# ============================================
# ENDPOINTS MÓVILES
# ============================================

@router.post("/device/register")
async def register_device(
    request: DeviceRegistrationRequest,
    current_user: dict = Depends(get_current_user)
):
    """Registra un dispositivo móvil para notificaciones push"""
    user_id = current_user.get("sub")
    logger.info(f"📱 Registrando dispositivo móvil para usuario: {user_id}")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        device_data = {
            "user_id": user_id,
            "device_token": request.device_token,
            "platform": request.platform,
            "device_name": request.device_name,
            "device_model": request.device_model,
            "app_version": request.app_version,
            "is_active": True,
            "last_seen": datetime.now().isoformat(),
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Verificar si el dispositivo ya existe
        existing = admin_client.table("mobile_devices").select("*").eq(
            "device_token", request.device_token
        ).execute()
        
        if existing.data and len(existing.data) > 0:
            # Actualizar
            admin_client.table("mobile_devices").update({
                "is_active": True,
                "last_seen": datetime.now().isoformat(),
                "platform": request.platform,
                "app_version": request.app_version,
                "updated_at": datetime.now().isoformat()
            }).eq("device_token", request.device_token).execute()
        else:
            # Insertar nuevo
            admin_client.table("mobile_devices").insert(device_data).execute()
        
        logger.info(f"✅ Dispositivo registrado: {request.platform}")
        
        return {
            "success": True,
            "message": "Dispositivo registrado exitosamente",
            "device_token": request.device_token
        }
        
    except Exception as e:
        logger.error(f"❌ Error registrando dispositivo: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error registrando dispositivo: {str(e)}"
        )


@router.post("/device/unregister")
async def unregister_device(
    device_token: str,
    current_user: dict = Depends(get_current_user)
):
    """Desregistra un dispositivo móvil"""
    user_id = current_user.get("sub")
    logger.info(f"📱 Desregistrando dispositivo: {device_token}")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        admin_client.table("mobile_devices").update({
            "is_active": False,
            "updated_at": datetime.now().isoformat()
        }).eq("device_token", device_token).eq("user_id", user_id).execute()
        
        return {"success": True, "message": "Dispositivo desregistrado"}
        
    except Exception as e:
        logger.error(f"❌ Error desregistrando dispositivo: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error desregistrando dispositivo: {str(e)}"
        )


@router.post("/sync", response_model=SyncResponse)
async def sync_data(
    request: SyncRequest,
    current_user: dict = Depends(get_current_user)
):
    """Sincroniza datos desde última actualización"""
    user_id = current_user.get("sub")
    logger.info(f"🔄 Sincronizando datos para usuario: {user_id}")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        last_sync = datetime.fromisoformat(request.last_sync_timestamp.replace('Z', '+00:00'))
        
        server_now = datetime.now().isoformat()
        
        # Obtener tareas creadas/actualizadas desde última sincronización
        tasks_response = admin_client.table("tasks").select("*").eq(
            "user_id", user_id
        ).gte("updated_at", last_sync.isoformat()).execute()
        
        # Obtener tareas eliminadas
        deleted_response = admin_client.table("tasks_deleted").select(
            "task_id"
        ).eq("user_id", user_id).gte("deleted_at", last_sync.isoformat()).execute()
        
        tasks_created = []
        tasks_updated = []
        
        for task in tasks_response.data:
            task_created_at = task.get("created_at")
            if task_created_at and datetime.fromisoformat(task_created_at.replace('Z', '+00:00')) >= last_sync:
                tasks_created.append(task)
            else:
                tasks_updated.append(task)
        
        deleted_task_ids = [d["task_id"] for d in deleted_response.data]
        
        # Obtener perfil actualizado
        user_response = admin_client.auth.admin.get_user_by_id(user_id)
        profile = None
        
        if user_response and user_response.user:
            user_data = user_response.user
            user_updated = user_data.updated_at
            
            if user_updated and user_updated >= last_sync:
                profile = {
                    "id": user_data.id,
                    "email": user_data.email,
                    "username": user_data.user_metadata.get("username") if user_data.user_metadata else None,
                    "full_name": user_data.user_metadata.get("full_name") if user_data.user_metadata else None,
                    "avatar": user_data.user_metadata.get("avatar") if user_data.user_metadata else None,
                    "banner": user_data.user_metadata.get("banner") if user_data.user_metadata else None
                }
        
        return SyncResponse(
            tasks_created=tasks_created,
            tasks_updated=tasks_updated,
            tasks_deleted=deleted_task_ids,
            profile_updated=profile,
            server_timestamp=server_now,
            has_more=len(tasks_response.data) >= 100  # Si hay muchos, indicar paginación
        )
        
    except Exception as e:
        logger.error(f"❌ Error sincronizando: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error sincronizando datos: {str(e)}"
        )


@router.post("/sync/offline-actions")
async def sync_offline_actions(
    actions: List[OfflineActionRequest],
    current_user: dict = Depends(get_current_user)
):
    """Sincroniza acciones realizadas offline"""
    user_id = current_user.get("sub")
    logger.info(f"📤 Sincronizando {len(actions)} acciones offline")
    
    results = []
    
    try:
        admin_client = supabase_auth.get_admin_client()
        
        for action in actions:
            try:
                if action.resource_type == "task":
                    if action.action_type == "create" and action.data:
                        # Crear tarea desde offline
                        response = admin_client.table("tasks").insert(action.data).execute()
                        results.append({
                            "action_id": action.client_timestamp,
                            "success": True,
                            "server_id": response.data[0]["id"] if response.data else None
                        })
                    
                    elif action.action_type == "update" and action.resource_id:
                        # Actualizar tarea
                        admin_client.table("tasks").update(
                            action.data or {}
                        ).eq("id", action.resource_id).eq("user_id", user_id).execute()
                        results.append({
                            "action_id": action.client_timestamp,
                            "success": True
                        })
                    
                    elif action.action_type == "delete" and action.resource_id:
                        # Soft delete
                        admin_client.table("tasks").delete().eq(
                            "id", action.resource_id
                        ).eq("user_id", user_id).execute()
                        
                        # Registrar en tabla de eliminados
                        admin_client.table("tasks_deleted").insert({
                            "task_id": action.resource_id,
                            "user_id": user_id,
                            "deleted_at": datetime.now().isoformat()
                        }).execute()
                        
                        results.append({
                            "action_id": action.client_timestamp,
                            "success": True
                        })
            except Exception as e:
                logger.error(f"Error en acción offline: {str(e)}")
                results.append({
                    "action_id": action.client_timestamp if action else "unknown",
                    "success": False,
                    "error": str(e)
                })
        
        return {
            "success": True,
            "results": results,
            "server_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"❌ Error sincronizando acciones offline: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error sincronizando acciones offline: {str(e)}"
        )


@router.get("/user/devices")
async def get_user_devices(
    current_user: dict = Depends(get_current_user)
):
    """Obtiene los dispositivos registrados del usuario"""
    user_id = current_user.get("sub")
    
    try:
        admin_client = supabase_auth.get_admin_client()
        response = admin_client.table("mobile_devices").select("*").eq(
            "user_id", user_id
        ).eq("is_active", True).execute()
        
        return {
            "devices": response.data,
            "count": len(response.data)
        }
        
    except Exception as e:
        logger.error(f"❌ Error obteniendo dispositivos: {str(e)}")
        return {"devices": [], "count": 0}


@router.get("/config")
async def get_mobile_config():
    """Obtiene configuración específica para la app móvil"""
    return {
        "api_version": settings.API_VERSION,
        "min_app_version": "1.0.0",
        "recommended_app_version": "1.0.0",
        "features": {
            "passkeys_enabled": True,
            "otp_email_enabled": True,
            "two_factor_enabled": True,
            "offline_mode_enabled": True,
            "push_notifications_enabled": True,
            "biometric_auth_enabled": True
        },
        "supabase": {
            "url": settings.SUPABASE_URL,
            "anon_key": settings.SUPABASE_ANON_KEY
        },
        "storage": {
            "max_file_size_mb": settings.MAX_FILE_SIZE_MB,
            "allowed_image_types": settings.ALLOWED_IMAGE_TYPES
        },
        "sync": {
            "interval_seconds": 30,
            "max_offline_actions": 100
        }
    }