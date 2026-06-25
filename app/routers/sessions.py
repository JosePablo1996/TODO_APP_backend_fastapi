# app/routers/sessions.py
"""
Router para endpoints de sesiones y seguridad
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from app.dependencies import get_current_user
from app.services.session_service import session_service
from app.services.security_service import security_service, SecurityEventType
from app.models import (
    Session,
    SessionStatsResponse,
    LoginHistory,
    SecurityChange,
    RevokeAllSessionsResponse
)

router = APIRouter(prefix="/api/sessions", tags=["sessions"])
logger = logging.getLogger(__name__)


# ============================================
# ENDPOINTS DE SESIONES
# ============================================

@router.get("", response_model=List[Session])
async def get_sessions(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Obtiene todas las sesiones activas del usuario.
    
    - Retorna todas las sesiones activas
    - Las sesiones inactivas por >24h se eliminan automáticamente
    - Incluye información de dispositivo, navegador, IP y ubicación
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"📋 Obteniendo sesiones para usuario: {user_id}")
    
    try:
        sessions = await session_service.get_user_sessions(user_id)
        logger.info(f"✅ {len(sessions)} sesiones encontradas")
        return sessions
        
    except Exception as e:
        logger.error(f"Error obteniendo sesiones: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener sesiones: {str(e)}"
        )


@router.delete("/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    req: Request = None
):
    """
    Revoca una sesión específica.
    
    - Elimina la sesión del dispositivo
    - El usuario deberá iniciar sesión nuevamente en ese dispositivo
    - No se puede revocar la sesión actual (is_current=True)
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"🗑️ Revocando sesión {session_id} para usuario: {user_id}")
    
    try:
        # Verificar que la sesión existe y pertenece al usuario
        sessions = await session_service.get_user_sessions(user_id)
        session_to_revoke = next((s for s in sessions if s["id"] == session_id), None)
        
        if not session_to_revoke:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Sesión no encontrada"
            )
        
        # No permitir revocar la sesión actual
        if session_to_revoke.get("is_current", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No puedes revocar tu sesión actual desde este dispositivo"
            )
        
        success = await session_service.delete_session(session_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al revocar la sesión"
            )
        
        # ✅ Registrar evento de seguridad (con manejo de errores)
        try:
            await security_service.log_security_event(
                user_id=user_id,
                event_type="SESSION_REVOKED",
                ip_address=req.client.host if req else None,
                user_agent=req.headers.get("User-Agent"),
                details={
                    "session_id": session_id,
                    "device_name": session_to_revoke.get("device_name", "Desconocido")
                }
            )
        except Exception as log_error:
            # ✅ No interrumpir la operación si el log falla
            logger.warning(f"⚠️ No se pudo registrar evento de seguridad: {log_error}")
        
        logger.info(f"✅ Sesión {session_id} revocada exitosamente")
        
        return {
            "message": "Sesión revocada exitosamente",
            "success": True,
            "session_id": session_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error revocando sesión: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al revocar sesión: {str(e)}"
        )


@router.post("/revoke-all", response_model=RevokeAllSessionsResponse)
async def revoke_all_sessions(
    current_user: Dict[str, Any] = Depends(get_current_user),
    req: Request = None
):
    """
    Revoca todas las sesiones excepto la actual.
    
    - Cierra sesión en todos los dispositivos excepto el actual
    - Útil cuando se detecta actividad sospechosa
    - El usuario deberá iniciar sesión nuevamente en todos los dispositivos
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"🗑️ Revocando todas las sesiones para usuario: {user_id}")
    
    try:
        # Obtener conteo de sesiones antes de eliminar
        sessions = await session_service.get_user_sessions(user_id)
        total_sessions = len(sessions)
        other_sessions = [s for s in sessions if not s.get("is_current", False)]
        
        if not other_sessions:
            return RevokeAllSessionsResponse(
                revoked_count=0,
                message="No hay otras sesiones activas para revocar"
            )
        
        revoked_count = await session_service.delete_all_sessions(
            user_id=user_id,
            exclude_current=True
        )
        
        # ✅ Registrar evento de seguridad (con manejo de errores)
        try:
            await security_service.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.LOGOUT_ALL_SESSIONS,
                ip_address=req.client.host if req else None,
                user_agent=req.headers.get("User-Agent"),
                details={
                    "revoked_count": revoked_count,
                    "total_sessions": total_sessions
                }
            )
        except Exception as log_error:
            # ✅ No interrumpir la operación si el log falla
            logger.warning(f"⚠️ No se pudo registrar evento de seguridad: {log_error}")
        
        logger.info(f"✅ {revoked_count} sesiones revocadas para usuario {user_id}")
        
        return RevokeAllSessionsResponse(
            revoked_count=revoked_count,
            message=f"Se revocaron {revoked_count} sesiones correctamente"
        )
        
    except Exception as e:
        logger.error(f"Error revocando todas las sesiones: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al revocar sesiones: {str(e)}"
        )


# ============================================
# ENDPOINTS DE HISTORIAL
# ============================================

@router.get("/login-history", response_model=List[LoginHistory])
async def get_login_history(
    current_user: Dict[str, Any] = Depends(get_current_user),
    login_type: Optional[str] = Query(None, description="Filtrar por tipo de login: password, otp, passkey, 2fa"),
    status: Optional[str] = Query(None, description="Filtrar por estado: success, failed, pending"),
    date_from: Optional[str] = Query(None, description="Fecha desde (ISO format: YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="Fecha hasta (ISO format: YYYY-MM-DD)"),
    limit: int = Query(50, ge=1, le=100, description="Límite de resultados (1-100)"),
    offset: int = Query(0, ge=0, description="Desplazamiento para paginación")
):
    """
    Obtiene el historial de accesos del usuario.
    
    - Registros de todos los inicios de sesión
    - Incluye información de dispositivo, IP y ubicación
    - Soporta filtros por tipo, estado y rango de fechas
    - Paginación con limit y offset
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"📋 Obteniendo historial de accesos para usuario: {user_id}")
    logger.info(f"   Filtros: type={login_type}, status={status}, from={date_from}, to={date_to}")
    
    try:
        # Construir filtros
        filters = {}
        if login_type:
            filters["login_type"] = login_type
        if status:
            filters["status"] = status
        if date_from:
            filters["date_from"] = date_from
        if date_to:
            filters["date_to"] = date_to
        
        history = await session_service.get_login_history(
            user_id=user_id,
            filters=filters if filters else None,
            limit=limit,
            offset=offset
        )
        
        logger.info(f"✅ {len(history)} registros encontrados")
        return history
        
    except Exception as e:
        logger.error(f"Error obteniendo historial de accesos: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener historial de accesos: {str(e)}"
        )


@router.get("/security-changes", response_model=List[SecurityChange])
async def get_security_changes(
    current_user: Dict[str, Any] = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=100, description="Límite de resultados (1-100)"),
    offset: int = Query(0, ge=0, description="Desplazamiento para paginación")
):
    """
    Obtiene el historial de cambios de seguridad del usuario.
    
    - Incluye cambios de contraseña, 2FA, Passkeys, etc.
    - Registra IP y ubicación de cada cambio
    - Útil para auditoría de seguridad
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"📋 Obteniendo cambios de seguridad para usuario: {user_id}")
    
    try:
        changes = await session_service.get_security_changes(
            user_id=user_id,
            limit=limit,
            offset=offset
        )
        
        logger.info(f"✅ {len(changes)} cambios encontrados")
        return changes
        
    except Exception as e:
        logger.error(f"Error obteniendo cambios de seguridad: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener cambios de seguridad: {str(e)}"
        )


# ============================================
# ENDPOINTS DE ESTADÍSTICAS
# ============================================

@router.get("/security-stats", response_model=SessionStatsResponse)
async def get_security_stats(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Obtiene estadísticas de seguridad del usuario.
    
    El puntaje de seguridad se calcula basado en:
    - Passkey registrada (+20)
    - 2FA activado (+25)
    - Contraseña reciente (+15 si < 90 días)
    - Sesiones activas (hasta +10)
    - Dispositivos únicos (+10)
    - Historial de logins (+5)
    
    Máximo: 100 puntos.
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"📊 Obteniendo estadísticas de seguridad para usuario: {user_id}")
    
    try:
        stats = await session_service.get_security_stats(user_id)
        logger.info(f"✅ Estadísticas obtenidas: Score={stats['security_score']}%")
        return stats
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de seguridad: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener estadísticas de seguridad: {str(e)}"
        )


@router.get("/recent-activity")
async def get_recent_activity(
    current_user: Dict[str, Any] = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=50, description="Límite de resultados (1-50)")
):
    """
    Obtiene la actividad reciente del usuario.
    
    Combina:
    - Historial de inicios de sesión
    - Cambios de seguridad
    
    Ordenado por fecha descendente.
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"📋 Obteniendo actividad reciente para usuario: {user_id}")
    
    try:
        # Obtener ambos tipos de actividad
        login_history = await session_service.get_login_history(
            user_id=user_id,
            limit=limit,
            offset=0
        )
        
        security_changes = await session_service.get_security_changes(
            user_id=user_id,
            limit=limit,
            offset=0
        )
        
        # Combinar y ordenar por fecha
        combined = []
        
        for item in login_history:
            combined.append({
                "type": "login",
                "data": item,
                "timestamp": item.get("created_at")
            })
        
        for item in security_changes:
            combined.append({
                "type": "security_change",
                "data": item,
                "timestamp": item.get("created_at")
            })
        
        # Ordenar por fecha descendente
        combined.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Limitar resultados
        combined = combined[:limit]
        
        return {
            "activity": combined,
            "total": len(combined),
            "login_count": len(login_history),
            "security_change_count": len(security_changes)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo actividad reciente: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener actividad reciente: {str(e)}"
        )


@router.get("/login-history/stats")
async def get_login_history_stats(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Obtiene estadísticas del historial de accesos.
    
    - Total de accesos
    - Intentos exitosos vs fallidos
    - Distribución por tipo de login
    - Distribución por dispositivo
    - Actividad por día de la semana
    """
    user_id = current_user.get("sub")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuario no identificado"
        )
    
    logger.info(f"📊 Obteniendo estadísticas de historial para usuario: {user_id}")
    
    try:
        # Obtener todo el historial (sin límite)
        history = await session_service.get_login_history(
            user_id=user_id,
            limit=1000,
            offset=0
        )
        
        total = len(history)
        
        if total == 0:
            return {
                "total": 0,
                "success_count": 0,
                "failed_count": 0,
                "success_rate": 0,
                "by_type": {},
                "by_device": {},
                "by_day": {}
            }
        
        # Estadísticas básicas
        success_count = sum(1 for h in history if h.get("status") == "success")
        failed_count = sum(1 for h in history if h.get("status") == "failed")
        success_rate = round((success_count / total) * 100, 1) if total > 0 else 0
        
        # Distribución por tipo
        by_type = {}
        for h in history:
            login_type = h.get("login_type", "unknown")
            by_type[login_type] = by_type.get(login_type, 0) + 1
        
        # Distribución por dispositivo
        by_device = {}
        for h in history:
            device = h.get("device_type", "unknown")
            by_device[device] = by_device.get(device, 0) + 1
        
        # Distribución por día de la semana
        days = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"]
        by_day = {day: 0 for day in days}
        
        for h in history:
            created_at = h.get("created_at")
            if created_at:
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    day_index = dt.weekday()
                    by_day[days[day_index]] += 1
                except:
                    pass
        
        # Limpiar días sin actividad
        by_day = {k: v for k, v in by_day.items() if v > 0}
        
        return {
            "total": total,
            "success_count": success_count,
            "failed_count": failed_count,
            "success_rate": success_rate,
            "by_type": by_type,
            "by_device": by_device,
            "by_day": by_day
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de historial: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener estadísticas de historial: {str(e)}"
        )