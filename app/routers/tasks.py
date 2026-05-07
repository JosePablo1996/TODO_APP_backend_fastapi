# app/routers/tasks.py
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
import uuid
from app.dependencies import get_current_user
from app.services.supabase_auth_service import supabase_auth

router = APIRouter(prefix="/api/tasks", tags=["tasks"])
logger = logging.getLogger(__name__)


# ============================================
# MODELOS
# ============================================

class TaskBase(BaseModel):
    """Modelo base de tarea"""
    title: str = Field(..., min_length=1, max_length=200, description="Título de la tarea")
    description: Optional[str] = Field(None, max_length=1000, description="Descripción detallada")
    completed: bool = Field(False, description="Estado de la tarea")
    priority: Optional[str] = Field("media", description="Prioridad: baja, media, alta, urgente")
    due_date: Optional[str] = Field(None, description="Fecha de vencimiento (ISO format)")
    category: Optional[str] = Field(None, max_length=50, description="Categoría de la tarea")
    tags: Optional[List[str]] = Field(default_factory=list, description="Etiquetas de la tarea")

class TaskCreate(TaskBase):
    """Modelo para crear tarea"""
    color: Optional[str] = Field(None, description="Color de la tarea en formato hex")

class TaskUpdate(BaseModel):
    """Modelo para actualizar tarea (todos los campos opcionales)"""
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    completed: Optional[bool] = None
    priority: Optional[str] = None
    due_date: Optional[str] = None
    category: Optional[str] = Field(None, max_length=50)
    tags: Optional[List[str]] = None
    color: Optional[str] = Field(None, description="Color de la tarea en formato hex")
    deleted_at: Optional[str] = Field(None, description="Fecha de eliminación (soft delete)")
    is_favorite: Optional[bool] = Field(None, description="Marcar como favorita")
    is_archived: Optional[bool] = Field(None, description="Marcar como archivada")

class Task(TaskBase):
    """Modelo de respuesta de tarea"""
    id: str
    user_id: str
    color: Optional[str] = Field(None, description="Color de la tarea")
    is_favorite: Optional[bool] = Field(False, description="Tarea favorita")
    is_archived: Optional[bool] = Field(False, description="Tarea archivada")
    deleted_at: Optional[str] = Field(None, description="Fecha de eliminación (soft delete)")
    created_at: str
    updated_at: Optional[str] = None

class TaskStats(BaseModel):
    """Estadísticas de tareas"""
    total: int
    completed: int
    pending: int
    completed_percentage: float
    by_priority: Dict[str, int]
    by_category: Dict[str, int]
    due_today: int
    overdue: int

class BulkDeleteRequest(BaseModel):
    """Modelo para eliminación masiva"""
    task_ids: List[str] = Field(..., min_items=1, description="Lista de IDs de tareas a eliminar")


# ============================================
# FUNCIONES AUXILIARES PARA SUPABASE (SÍNCRONAS)
# ============================================

def get_tasks_table():
    """
    Obtiene la tabla de tareas de Supabase
    ✅ SINCRONO - No usa async/await
    """
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Base de datos no disponible"
        )
    
    admin_client = supabase_auth.get_admin_client()
    return admin_client.table("tasks")


def ensure_tasks_table_exists():
    """
    Verifica que la tabla de tareas existe
    ✅ SINCRONO - No usa async/await
    """
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # Intentar hacer un select limitado para verificar si la tabla existe
        response = admin_client.table("tasks").select("*").limit(1).execute()
        
        # Si no hay error, la tabla existe
        logger.info("✅ Tabla 'tasks' verificada")
        return True
        
    except Exception as e:
        error_msg = str(e)
        if "relation" in error_msg and "does not exist" in error_msg:
            logger.error("❌ La tabla 'tasks' no existe en Supabase")
            logger.error("   Por favor, crea la tabla 'tasks' con el SQL proporcionado")
            return False
        else:
            logger.error(f"Error verificando tabla: {error_msg}")
            return False


def _task_to_response(task_data: Dict[str, Any]) -> Task:
    """Convierte un diccionario de tarea a modelo Task"""
    return Task(
        id=task_data["id"],
        user_id=task_data["user_id"],
        title=task_data["title"],
        description=task_data.get("description"),
        completed=task_data.get("completed", False),
        priority=task_data.get("priority", "media"),
        due_date=task_data.get("due_date"),
        category=task_data.get("category"),
        tags=task_data.get("tags", []),
        color=task_data.get("color"),
        is_favorite=task_data.get("is_favorite", False),
        is_archived=task_data.get("is_archived", False),
        deleted_at=task_data.get("deleted_at"),
        created_at=task_data["created_at"],
        updated_at=task_data.get("updated_at")
    )


# ============================================
# ENDPOINTS DE TAREAS
# ============================================

@router.get("", response_model=List[Task])
async def get_tasks(
    current_user: Dict[str, Any] = Depends(get_current_user),
    completed: Optional[bool] = Query(None, description="Filtrar por estado"),
    priority: Optional[str] = Query(None, description="Filtrar por prioridad"),
    category: Optional[str] = Query(None, description="Filtrar por categoría"),
    search: Optional[str] = Query(None, description="Buscar en título o descripción"),
    include_deleted: Optional[bool] = Query(False, description="Incluir tareas en papelera"),
    limit: int = Query(50, ge=1, le=100, description="Límite de resultados"),
    offset: int = Query(0, ge=0, description="Desplazamiento para paginación")
):
    """
    Obtiene todas las tareas del usuario actual con filtros opcionales.
    Por defecto NO incluye tareas eliminadas (soft delete).
    Usa include_deleted=true para obtener también las de la papelera.
    """
    user_id = current_user.get("sub")
    logger.info(f"📋 Obteniendo tareas para usuario {user_id}")
    
    try:
        # ✅ SINCRONO - Sin await
        if not ensure_tasks_table_exists():
            return []
        
        tasks_table = get_tasks_table()
        
        # Construir consulta base
        query = tasks_table.select("*").eq("user_id", user_id)
        
        # ✅ SOFT DELETE: Excluir tareas eliminadas por defecto
        if not include_deleted:
            query = query.is_("deleted_at", "null")
        
        # Aplicar filtros
        if completed is not None:
            query = query.eq("completed", completed)
        
        if priority:
            query = query.eq("priority", priority)
        
        if category:
            query = query.eq("category", category)
        
        if search:
            query = query.or_(f"title.ilike.%{search}%,description.ilike.%{search}%")
        
        # Ordenar por fecha de creación (más recientes primero)
        query = query.order("created_at", desc=True)
        
        # Aplicar paginación
        query = query.range(offset, offset + limit - 1)
        
        # ✅ Ejecutar SIN await
        response = query.execute()
        
        tasks = [_task_to_response(task) for task in response.data]
        
        deleted_count = sum(1 for t in tasks if t.deleted_at is not None)
        logger.info(f"✅ {len(tasks)} tareas encontradas ({deleted_count} en papelera)")
        return tasks
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo tareas: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener tareas: {str(e)}"
        )


@router.get("/trash", response_model=List[Task])
async def get_trash_tasks(
    current_user: Dict[str, Any] = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=100, description="Límite de resultados"),
    offset: int = Query(0, ge=0, description="Desplazamiento para paginación")
):
    """
    Obtiene las tareas en la papelera (soft deleted) del usuario actual
    """
    user_id = current_user.get("sub")
    logger.info(f"🗑️📋 Obteniendo papelera para usuario {user_id}")
    
    try:
        if not ensure_tasks_table_exists():
            return []
        
        tasks_table = get_tasks_table()
        
        # Solo tareas con deleted_at no nulo
        query = tasks_table.select("*").eq("user_id", user_id).not_.is_("deleted_at", "null")
        query = query.order("deleted_at", desc=True)
        query = query.range(offset, offset + limit - 1)
        
        response = query.execute()
        
        tasks = [_task_to_response(task) for task in response.data]
        
        logger.info(f"✅ {len(tasks)} tareas en papelera")
        return tasks
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo papelera: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener papelera: {str(e)}"
        )


@router.post("", response_model=Task, status_code=status.HTTP_201_CREATED)
async def create_task(
    task: TaskCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Crea una nueva tarea para el usuario actual
    """
    user_id = current_user.get("sub")
    logger.info(f"➕ Creando tarea para usuario {user_id}")
    logger.info(f"   Título: {task.title}")
    logger.info(f"   Color: {task.color}")
    
    try:
        # ✅ SINCRONO - Sin await
        ensure_tasks_table_exists()
        tasks_table = get_tasks_table()
        
        # Preparar datos de la tarea
        now = datetime.now().isoformat()
        task_data = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "title": task.title,
            "description": task.description,
            "completed": task.completed,
            "priority": task.priority,
            "due_date": task.due_date,
            "category": task.category,
            "tags": task.tags or [],
            "color": task.color,
            "is_favorite": False,
            "is_archived": False,
            "deleted_at": None,
            "created_at": now,
            "updated_at": now
        }
        
        # ✅ Insertar SIN await
        response = tasks_table.insert(task_data).execute()
        
        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al crear la tarea"
            )
        
        created_task = response.data[0]
        
        logger.info(f"✅ Tarea creada: {created_task['id']}")
        
        return _task_to_response(created_task)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creando tarea: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al crear tarea: {str(e)}"
        )


@router.get("/{task_id}", response_model=Task)
async def get_task(
    task_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Obtiene una tarea específica por ID
    """
    user_id = current_user.get("sub")
    logger.info(f"🔍 Obteniendo tarea {task_id} para usuario {user_id}")
    
    try:
        tasks_table = get_tasks_table()
        
        # ✅ Ejecutar SIN await
        response = tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tarea no encontrada"
            )
        
        return _task_to_response(response.data[0])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo tarea: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener tarea: {str(e)}"
        )


@router.put("/{task_id}", response_model=Task)
async def update_task(
    task_id: str,
    task_update: TaskUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Actualiza una tarea existente
    """
    user_id = current_user.get("sub")
    logger.info(f"✏️ Actualizando tarea {task_id} para usuario {user_id}")
    
    try:
        tasks_table = get_tasks_table()
        
        # Verificar que la tarea existe y pertenece al usuario
        check_response = tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
        if not check_response.data or len(check_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tarea no encontrada"
            )
        
        # Preparar datos de actualización (solo campos no None)
        update_data = {}
        if task_update.title is not None:
            update_data["title"] = task_update.title
        if task_update.description is not None:
            update_data["description"] = task_update.description
        if task_update.completed is not None:
            update_data["completed"] = task_update.completed
        if task_update.priority is not None:
            update_data["priority"] = task_update.priority
        if task_update.due_date is not None:
            update_data["due_date"] = task_update.due_date
        if task_update.category is not None:
            update_data["category"] = task_update.category
        if task_update.tags is not None:
            update_data["tags"] = task_update.tags
        if task_update.color is not None:
            update_data["color"] = task_update.color
        if task_update.is_favorite is not None:
            update_data["is_favorite"] = task_update.is_favorite
        if task_update.is_archived is not None:
            update_data["is_archived"] = task_update.is_archived
        if task_update.deleted_at is not None:
            update_data["deleted_at"] = task_update.deleted_at
        
        update_data["updated_at"] = datetime.now().isoformat()
        
        if len(update_data) <= 1:  # Solo updated_at
            task_data = check_response.data[0]
            return _task_to_response(task_data)
        
        # ✅ Actualizar SIN await
        response = tasks_table.update(update_data).eq("id", task_id).execute()
        
        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al actualizar la tarea"
            )
        
        logger.info(f"✅ Tarea actualizada: {task_id}")
        
        return _task_to_response(response.data[0])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error actualizando tarea: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al actualizar tarea: {str(e)}"
        )


@router.delete("/{task_id}")
async def delete_task(
    task_id: str,
    permanent: Optional[bool] = Query(False, description="Eliminar permanentemente"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Elimina una tarea (soft delete por defecto, permanent=true para eliminación física)
    
    - **Soft delete** (permanent=false): Marca deleted_at y mueve a papelera
    - **Permanent delete** (permanent=true): Elimina físicamente de la base de datos
    """
    user_id = current_user.get("sub")
    
    try:
        tasks_table = get_tasks_table()
        
        # Verificar que la tarea existe y pertenece al usuario
        check_response = tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
        if not check_response.data or len(check_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tarea no encontrada"
            )
        
        if permanent:
            # ✅ ELIMINACIÓN PERMANENTE (borrado físico)
            logger.info(f"🗑️💀 Eliminando PERMANENTEMENTE tarea {task_id}")
            tasks_table.delete().eq("id", task_id).execute()
            
            logger.info(f"✅ Tarea eliminada permanentemente: {task_id}")
            
            return {
                "message": "Tarea eliminada permanentemente",
                "task_id": task_id,
                "success": True,
                "permanent": True
            }
        else:
            # ✅ SOFT DELETE (mover a papelera)
            logger.info(f"📦 Moviendo tarea {task_id} a papelera (soft delete)")
            
            now = datetime.now().isoformat()
            tasks_table.update({
                "deleted_at": now,
                "updated_at": now
            }).eq("id", task_id).execute()
            
            logger.info(f"✅ Tarea movida a papelera: {task_id}")
            
            return {
                "message": "Tarea movida a la papelera",
                "task_id": task_id,
                "deleted_at": now,
                "success": True,
                "permanent": False
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error eliminando tarea: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar tarea: {str(e)}"
        )


@router.post("/{task_id}/restore", response_model=Task)
async def restore_task(
    task_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Restaura una tarea de la papelera (quita deleted_at)
    """
    user_id = current_user.get("sub")
    logger.info(f"🔄 Restaurando tarea {task_id} de papelera")
    
    try:
        tasks_table = get_tasks_table()
        
        # Verificar que la tarea existe
        check_response = tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
        if not check_response.data or len(check_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tarea no encontrada"
            )
        
        # Quitar deleted_at
        now = datetime.now().isoformat()
        response = tasks_table.update({
            "deleted_at": None,
            "updated_at": now
        }).eq("id", task_id).execute()
        
        logger.info(f"✅ Tarea restaurada: {task_id}")
        
        return _task_to_response(response.data[0])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error restaurando tarea: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al restaurar tarea: {str(e)}"
        )


@router.post("/bulk/delete")
async def bulk_delete_tasks(
    request: BulkDeleteRequest,
    permanent: Optional[bool] = Query(False, description="Eliminar permanentemente"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Elimina múltiples tareas (soft delete por defecto)
    """
    user_id = current_user.get("sub")
    task_ids = request.task_ids
    logger.info(f"📦 Eliminando {len(task_ids)} tareas en bulk (permanent={permanent})")
    
    try:
        tasks_table = get_tasks_table()
        success_count = 0
        failed_count = 0
        failed_ids = []
        
        for task_id in task_ids:
            try:
                # Verificar propiedad
                check_response = tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
                
                if not check_response.data or len(check_response.data) == 0:
                    failed_count += 1
                    failed_ids.append(task_id)
                    continue
                
                if permanent:
                    tasks_table.delete().eq("id", task_id).execute()
                else:
                    now = datetime.now().isoformat()
                    tasks_table.update({
                        "deleted_at": now,
                        "updated_at": now
                    }).eq("id", task_id).execute()
                
                success_count += 1
                
            except Exception as e:
                logger.error(f"Error en bulk delete para {task_id}: {str(e)}")
                failed_count += 1
                failed_ids.append(task_id)
        
        logger.info(f"✅ Bulk delete: {success_count} éxito, {failed_count} fallos")
        
        return {
            "message": f"Eliminadas {success_count} de {len(task_ids)} tareas",
            "success_count": success_count,
            "failed_count": failed_count,
            "failed_ids": failed_ids,
            "permanent": permanent,
            "success": failed_count == 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en bulk delete: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error en eliminación masiva: {str(e)}"
        )


@router.post("/bulk/restore")
async def bulk_restore_tasks(
    request: BulkDeleteRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Restaura múltiples tareas de la papelera
    """
    user_id = current_user.get("sub")
    task_ids = request.task_ids
    logger.info(f"🔄 Restaurando {len(task_ids)} tareas en bulk")
    
    try:
        tasks_table = get_tasks_table()
        success_count = 0
        failed_count = 0
        
        for task_id in task_ids:
            try:
                check_response = tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
                
                if not check_response.data or len(check_response.data) == 0:
                    failed_count += 1
                    continue
                
                now = datetime.now().isoformat()
                tasks_table.update({
                    "deleted_at": None,
                    "updated_at": now
                }).eq("id", task_id).execute()
                
                success_count += 1
                
            except Exception as e:
                logger.error(f"Error en bulk restore para {task_id}: {str(e)}")
                failed_count += 1
        
        logger.info(f"✅ Bulk restore: {success_count} éxito, {failed_count} fallos")
        
        return {
            "message": f"Restauradas {success_count} de {len(task_ids)} tareas",
            "success_count": success_count,
            "failed_count": failed_count,
            "success": failed_count == 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en bulk restore: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error en restauración masiva: {str(e)}"
        )


@router.get("/stats/summary", response_model=TaskStats)
async def get_task_stats(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Obtiene estadísticas de tareas del usuario (solo activas, no eliminadas)
    """
    user_id = current_user.get("sub")
    logger.info(f"📊 Obteniendo estadísticas para usuario {user_id}")
    
    try:
        tasks_table = get_tasks_table()
        
        # ✅ Solo tareas activas (no eliminadas)
        response = tasks_table.select("*").eq("user_id", user_id).is_("deleted_at", "null").execute()
        
        tasks = response.data
        
        # Calcular estadísticas
        total = len(tasks)
        completed = sum(1 for t in tasks if t.get("completed", False))
        pending = total - completed
        
        # Por prioridad
        by_priority = {
            "baja": 0,
            "media": 0,
            "alta": 0,
            "urgente": 0
        }
        
        # Por categoría
        by_category = {}
        
        # Fechas
        today = datetime.now().date()
        due_today = 0
        overdue = 0
        
        for task in tasks:
            # Prioridad
            priority = task.get("priority", "media")
            if priority in by_priority:
                by_priority[priority] += 1
            else:
                by_priority[priority] = by_priority.get(priority, 0) + 1
            
            # Categoría
            category = task.get("category")
            if category:
                by_category[category] = by_category.get(category, 0) + 1
            
            # Fechas (solo tareas no completadas)
            if not task.get("completed", False) and task.get("due_date"):
                try:
                    due_date = datetime.fromisoformat(task["due_date"].replace("Z", "+00:00")).date()
                    if due_date == today:
                        due_today += 1
                    elif due_date < today:
                        overdue += 1
                except Exception:
                    pass
        
        # Calcular porcentaje
        completed_percentage = (completed / total * 100) if total > 0 else 0
        
        return TaskStats(
            total=total,
            completed=completed,
            pending=pending,
            completed_percentage=round(completed_percentage, 1),
            by_priority=by_priority,
            by_category=by_category,
            due_today=due_today,
            overdue=overdue
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener estadísticas: {str(e)}"
        )


@router.post("/{task_id}/toggle-complete", response_model=Task)
async def toggle_task_complete(
    task_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Alterna el estado completado de una tarea (marcar/desmarcar)
    """
    user_id = current_user.get("sub")
    logger.info(f"🔄 Alternando estado de tarea {task_id}")
    
    try:
        tasks_table = get_tasks_table()
        
        # Obtener la tarea actual
        response = tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tarea no encontrada"
            )
        
        current_task = response.data[0]
        new_completed = not current_task.get("completed", False)
        
        # ✅ Actualizar SIN await
        update_response = tasks_table.update({
            "completed": new_completed,
            "updated_at": datetime.now().isoformat()
        }).eq("id", task_id).execute()
        
        if not update_response.data or len(update_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al actualizar la tarea"
            )
        
        return _task_to_response(update_response.data[0])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error alternando estado: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al alternar estado: {str(e)}"
        )


@router.delete("/clear/completed")
async def clear_completed_tasks(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Elimina todas las tareas completadas del usuario (soft delete)
    """
    user_id = current_user.get("sub")
    logger.info(f"🧹 Moviendo tareas completadas a papelera para usuario {user_id}")
    
    try:
        tasks_table = get_tasks_table()
        
        # ✅ Contar SIN await
        count_response = tasks_table.select("*", count="exact").eq("user_id", user_id).eq("completed", True).is_("deleted_at", "null").execute()
        
        completed_count = count_response.count if hasattr(count_response, 'count') else 0
        
        # ✅ Soft delete en lugar de eliminar físicamente
        now = datetime.now().isoformat()
        tasks_table.update({
            "deleted_at": now,
            "updated_at": now
        }).eq("user_id", user_id).eq("completed", True).is_("deleted_at", "null").execute()
        
        logger.info(f"✅ {completed_count} tareas completadas movidas a papelera")
        
        return {
            "message": f"Se movieron {completed_count} tareas completadas a la papelera",
            "deleted_count": completed_count,
            "success": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error eliminando tareas completadas: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar tareas completadas: {str(e)}"
        )