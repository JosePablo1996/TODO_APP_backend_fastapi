# app/services/push_service.py (NUEVO)
"""
Servicio para enviar notificaciones push a dispositivos móviles
"""
import logging
import httpx
import json
from typing import Optional, List, Dict, Any
from app.services.supabase_auth_service import supabase_auth
from app.config import settings

logger = logging.getLogger(__name__)

class PushNotificationService:
    """Servicio de notificaciones push"""
    
    def __init__(self):
        self.fcm_url = "https://fcm.googleapis.com/fcm/send"
        self.fcm_server_key = settings.FCM_SERVER_KEY if hasattr(settings, 'FCM_SERVER_KEY') else None
        self.is_configured = bool(self.fcm_server_key)
        
        if self.is_configured:
            logger.info("✅ Servicio Push configurado")
        else:
            logger.info("ℹ️ Servicio Push no configurado (FCM Server Key no encontrada)")
    
    async def send_push_to_user(
        self,
        user_id: str,
        title: str,
        body: str,
        data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Envía notificación push a todos los dispositivos del usuario"""
        if not self.is_configured:
            logger.warning("⚠️ Push no configurado")
            return False
        
        try:
            # Obtener dispositivos activos del usuario
            admin_client = supabase_auth.get_admin_client()
            devices_response = admin_client.table("mobile_devices").select(
                "device_token", "platform"
            ).eq("user_id", user_id).eq("is_active", True).execute()
            
            if not devices_response.data:
                logger.debug(f"ℹ️ No hay dispositivos para usuario {user_id}")
                return False
            
            success_count = 0
            
            for device in devices_response.data:
                sent = await self._send_to_device(
                    device_token=device["device_token"],
                    platform=device.get("platform", "android"),
                    title=title,
                    body=body,
                    data=data
                )
                if sent:
                    success_count += 1
            
            logger.info(f"📱 Push enviado a {success_count}/{len(devices_response.data)} dispositivos")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"❌ Error enviando push: {str(e)}")
            return False
    
    async def _send_to_device(
        self,
        device_token: str,
        platform: str,
        title: str,
        body: str,
        data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Envía push a un dispositivo específico"""
        if not self.is_configured:
            return False
        
        try:
            # Construir payload según plataforma
            if platform == "ios":
                message = {
                    "to": device_token,
                    "notification": {
                        "title": title,
                        "body": body,
                        "sound": "default",
                        "badge": 1
                    },
                    "data": data or {},
                    "priority": "high"
                }
            else:  # android
                message = {
                    "to": device_token,
                    "data": {
                        "title": title,
                        "body": body,
                        **(data or {}),
                        "click_action": "FLUTTER_NOTIFICATION_CLICK"
                    },
                    "priority": "high"
                }
            
            headers = {
                "Authorization": f"key={self.fcm_server_key}",
                "Content-Type": "application/json"
            }
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    self.fcm_url,
                    headers=headers,
                    json=message
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success", 0) > 0:
                        return True
                    else:
                        logger.warning(f"⚠️ Push falló: {result}")
                        # Si el token expiró, desactivar dispositivo
                        if "NotRegistered" in str(result):
                            await self._deactivate_device(device_token)
                        return False
                else:
                    logger.error(f"❌ Error FCM: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error enviando push a dispositivo: {str(e)}")
            return False
    
    async def _deactivate_device(self, device_token: str):
        """Desactiva un dispositivo que ya no es válido"""
        try:
            admin_client = supabase_auth.get_admin_client()
            admin_client.table("mobile_devices").update({
                "is_active": False,
                "updated_at": "NOW()"
            }).eq("device_token", device_token).execute()
            logger.info(f"📱 Dispositivo desactivado: {device_token}")
        except Exception as e:
            logger.error(f"❌ Error desactivando dispositivo: {str(e)}")
    
    async def send_task_reminder(self, user_id: str, task_title: str, due_date: str):
        """Envía recordatorio de tarea"""
        title = "⏰ Recordatorio de Tarea"
        body = f"'{task_title}' vence pronto"
        
        await self.send_push_to_user(
            user_id=user_id,
            title=title,
            body=body,
            data={
                "type": "task_reminder",
                "task_title": task_title,
                "due_date": due_date
            }
        )
    
    async def send_task_assigned(self, user_id: str, task_title: str, assigned_by: str):
        """Envía notificación de tarea asignada"""
        title = "📋 Nueva Tarea Asignada"
        body = f"{assigned_by} te asignó '{task_title}'"
        
        await self.send_push_to_user(
            user_id=user_id,
            title=title,
            body=body,
            data={
                "type": "task_assigned",
                "task_title": task_title,
                "assigned_by": assigned_by
            }
        )
    
    async def send_security_alert(self, user_id: str, alert_type: str, details: str):
        """Envía alerta de seguridad"""
        title = "🔒 Alerta de Seguridad"
        body = f"{alert_type}: {details}"
        
        await self.send_push_to_user(
            user_id=user_id,
            title=title,
            body=body,
            data={
                "type": "security_alert",
                "alert_type": alert_type,
                "details": details
            }
        )

# Instancia global
push_service = PushNotificationService()