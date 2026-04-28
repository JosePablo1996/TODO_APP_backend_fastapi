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
    pass

class TaskUpdate(BaseModel):
    """Modelo para actualizar tarea (todos los campos opcionales)"""
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    completed: Optional[bool] = None
    priority: Optional[str] = None
    due_date: Optional[str] = None
    category: Optional[str] = Field(None, max_length=50)
    tags: Optional[List[str]] = None

class Task(TaskBase):
    """Modelo de respuesta de tarea"""
    id: str
    user_id: str
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


# ============================================
# FUNCIONES AUXILIARES PARA SUPABASE
# ============================================

async def get_tasks_table():
    """
    Obtiene la tabla de tareas de Supabase
    """
    if not supabase_auth.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Base de datos no disponible"
        )
    
    admin_client = supabase_auth.get_admin_client()
    return admin_client.table("tasks")


async def ensure_tasks_table_exists():
    """
    Verifica que la tabla de tareas existe (opcional)
    En producción, deberías crear la tabla con una migración
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
    limit: int = Query(50, ge=1, le=100, description="Límite de resultados"),
    offset: int = Query(0, ge=0, description="Desplazamiento para paginación")
):
    """
    Obtiene todas las tareas del usuario actual con filtros opcionales
    """
    user_id = current_user.get("sub")
    logger.info(f"📋 Obteniendo tareas para usuario {user_id}")
    
    try:
        # Verificar que la tabla existe
        if not await ensure_tasks_table_exists():
            # Si no existe, retornar lista vacía con mensaje
            return []
        
        tasks_table = await get_tasks_table()
        
        # Construir consulta
        query = tasks_table.select("*").eq("user_id", user_id)
        
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
        
        # Ejecutar consulta
        response = await query.execute()
        
        tasks = []
        for task in response.data:
            tasks.append(Task(
                id=task["id"],
                user_id=task["user_id"],
                title=task["title"],
                description=task.get("description"),
                completed=task.get("completed", False),
                priority=task.get("priority", "media"),
                due_date=task.get("due_date"),
                category=task.get("category"),
                tags=task.get("tags", []),
                created_at=task["created_at"],
                updated_at=task.get("updated_at")
            ))
        
        logger.info(f"✅ {len(tasks)} tareas encontradas")
        return tasks
        
    except Exception as e:
        logger.error(f"Error obteniendo tareas: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener tareas: {str(e)}"
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
    
    try:
        # Verificar que la tabla existe
        await ensure_tasks_table_exists()
        
        tasks_table = await get_tasks_table()
        
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
            "created_at": now,
            "updated_at": now
        }
        
        # Insertar en la base de datos
        response = await tasks_table.insert(task_data).execute()
        
        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al crear la tarea"
            )
        
        created_task = response.data[0]
        
        logger.info(f"✅ Tarea creada: {created_task['id']}")
        
        return Task(
            id=created_task["id"],
            user_id=created_task["user_id"],
            title=created_task["title"],
            description=created_task.get("description"),
            completed=created_task.get("completed", False),
            priority=created_task.get("priority", "media"),
            due_date=created_task.get("due_date"),
            category=created_task.get("category"),
            tags=created_task.get("tags", []),
            created_at=created_task["created_at"],
            updated_at=created_task.get("updated_at")
        )
        
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
        tasks_table = await get_tasks_table()
        
        response = await tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tarea no encontrada"
            )
        
        task_data = response.data[0]
        
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
            created_at=task_data["created_at"],
            updated_at=task_data.get("updated_at")
        )
        
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
        tasks_table = await get_tasks_table()
        
        # Verificar que la tarea existe y pertenece al usuario
        check_response = await tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
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
        
        update_data["updated_at"] = datetime.now().isoformat()
        
        if not update_data:
            # Si no hay datos para actualizar, devolver la tarea actual
            return await get_task(task_id, current_user)
        
        # Actualizar en la base de datos
        response = await tasks_table.update(update_data).eq("id", task_id).execute()
        
        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al actualizar la tarea"
            )
        
        updated_task = response.data[0]
        
        logger.info(f"✅ Tarea actualizada: {task_id}")
        
        return Task(
            id=updated_task["id"],
            user_id=updated_task["user_id"],
            title=updated_task["title"],
            description=updated_task.get("description"),
            completed=updated_task.get("completed", False),
            priority=updated_task.get("priority", "media"),
            due_date=updated_task.get("due_date"),
            category=updated_task.get("category"),
            tags=updated_task.get("tags", []),
            created_at=updated_task["created_at"],
            updated_at=updated_task.get("updated_at")
        )
        
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
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Elimina una tarea
    """
    user_id = current_user.get("sub")
    logger.info(f"🗑️ Eliminando tarea {task_id} para usuario {user_id}")
    
    try:
        tasks_table = await get_tasks_table()
        
        # Verificar que la tarea existe y pertenece al usuario
        check_response = await tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
        if not check_response.data or len(check_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tarea no encontrada"
            )
        
        # Eliminar la tarea
        await tasks_table.delete().eq("id", task_id).execute()
        
        logger.info(f"✅ Tarea eliminada: {task_id}")
        
        return {
            "message": f"Tarea eliminada correctamente",
            "task_id": task_id,
            "success": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error eliminando tarea: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar tarea: {str(e)}"
        )


@router.get("/stats/summary", response_model=TaskStats)
async def get_task_stats(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Obtiene estadísticas de tareas del usuario
    """
    user_id = current_user.get("sub")
    logger.info(f"📊 Obteniendo estadísticas para usuario {user_id}")
    
    try:
        tasks_table = await get_tasks_table()
        
        # Obtener todas las tareas del usuario
        response = await tasks_table.select("*").eq("user_id", user_id).execute()
        
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
        tasks_table = await get_tasks_table()
        
        # Obtener la tarea actual
        response = await tasks_table.select("*").eq("id", task_id).eq("user_id", user_id).execute()
        
        if not response.data or len(response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tarea no encontrada"
            )
        
        current_task = response.data[0]
        new_completed = not current_task.get("completed", False)
        
        # Actualizar
        update_response = await tasks_table.update({
            "completed": new_completed,
            "updated_at": datetime.now().isoformat()
        }).eq("id", task_id).execute()
        
        if not update_response.data or len(update_response.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al actualizar la tarea"
            )
        
        updated_task = update_response.data[0]
        
        return Task(
            id=updated_task["id"],
            user_id=updated_task["user_id"],
            title=updated_task["title"],
            description=updated_task.get("description"),
            completed=updated_task.get("completed", False),
            priority=updated_task.get("priority", "media"),
            due_date=updated_task.get("due_date"),
            category=updated_task.get("category"),
            tags=updated_task.get("tags", []),
            created_at=updated_task["created_at"],
            updated_at=updated_task.get("updated_at")
        )
        
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
    Elimina todas las tareas completadas del usuario
    """
    user_id = current_user.get("sub")
    logger.info(f"🧹 Eliminando tareas completadas para usuario {user_id}")
    
    try:
        tasks_table = await get_tasks_table()
        
        # Contar cuántas tareas completadas hay
        count_response = await tasks_table.select("*", count="exact").eq("user_id", user_id).eq("completed", True).execute()
        
        completed_count = count_response.count if hasattr(count_response, 'count') else 0
        
        # Eliminar tareas completadas
        await tasks_table.delete().eq("user_id", user_id).eq("completed", True).execute()
        
        logger.info(f"✅ {completed_count} tareas completadas eliminadas")
        
        return {
            "message": f"Se eliminaron {completed_count} tareas completadas",
            "deleted_count": completed_count,
            "success": True
        }
        
    except Exception as e:
        logger.error(f"Error eliminando tareas completadas: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar tareas completadas: {str(e)}"
        )