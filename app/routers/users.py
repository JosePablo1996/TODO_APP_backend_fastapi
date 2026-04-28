# app/routers/users.py
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import logging
import httpx
from datetime import datetime
from app.dependencies import get_current_user, get_auth_token
from app.services.supabase_auth_service import supabase_auth
from app.services.supabase_service import supabase_storage
from app.config import settings

router = APIRouter(prefix="/api/users", tags=["users"])
logger = logging.getLogger(__name__)

# ============================================
# MODELOS
# ============================================
class ProfileUpdateRequest(BaseModel):
    """Solicitud para actualizar perfil"""
    full_name: Optional[str] = Field(None, min_length=1, max_length=100)
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    bio: Optional[str] = Field(None, max_length=500)
    avatar: Optional[str] = None
    banner: Optional[str] = None

class ProfileResponse(BaseModel):
    """Respuesta con información del perfil"""
    id: str
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    bio: Optional[str] = None
    avatar: Optional[str] = None
    banner: Optional[str] = None
    email_verified: bool
    created_at: Optional[str] = None
    last_sign_in_at: Optional[str] = None

class UserResponse(BaseModel):
    """Respuesta básica de usuario"""
    id: str
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None

# ============================================
# FUNCIONES AUXILIARES (CORREGIDAS)
# ============================================

async def get_user_profile_from_supabase(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Obtiene el perfil completo de un usuario desde Supabase.
    AHORA: Prioriza Auth Metadata para avatar/banner (que siempre funciona)
    y usa profiles solo para campos adicionales como bio.
    """
    try:
        # 1. PRIMERO obtener datos de Auth (SIEMPRE disponibles)
        user_data = await supabase_auth.get_user_by_id(user_id)
        
        if not user_data:
            logger.error(f"No se pudo obtener usuario de Auth para {user_id}")
            return None
        
        # Datos base desde Auth
        user_metadata = user_data.get("user_metadata", {})
        profile = {
            "id": user_id,
            "email": user_data.get("email"),
            "username": user_metadata.get("username"),
            "full_name": user_metadata.get("full_name"),
            "avatar": user_metadata.get("avatar"),  # PRIORIDAD: desde Auth
            "banner": user_metadata.get("banner"),  # PRIORIDAD: desde Auth
            "email_verified": user_data.get("email_verified", False),
            "created_at": user_data.get("created_at"),
            "last_sign_in_at": user_data.get("last_sign_in_at"),
            "bio": None  # Default
        }
        
        # 2. Intentar enriquecer con datos de tabla 'profiles' (solo bio y otros campos)
        try:
            admin_client = supabase_auth.get_admin_client()
            profile_response = admin_client.table("profiles").select("*").eq("id", user_id).execute()
            
            if profile_response.data and len(profile_response.data) > 0:
                db_profile = profile_response.data[0]
                # SOLO tomar bio y campos que NO están en Auth Metadata
                if "bio" in db_profile and db_profile["bio"]:
                    profile["bio"] = db_profile["bio"]
                
                # Si avatar/banner están en profiles Y NO en Auth, tomarlos
                if not profile.get("avatar") and "avatar" in db_profile:
                    profile["avatar"] = db_profile["avatar"]
                if not profile.get("banner") and "banner" in db_profile:
                    profile["banner"] = db_profile["banner"]
                
                logger.debug(f"Perfil enriquecido con datos de 'profiles' para {user_id}")
        except Exception as e:
            # La tabla profiles puede no existir o no tener columnas, no es crítico
            logger.debug(f"No se pudo obtener datos adicionales de 'profiles': {e}")
        
        return profile

    except Exception as e:
        logger.error(f"Error obteniendo perfil para {user_id}: {str(e)}")
        return None


async def update_user_profile_in_supabase(user_id: str, updates: Dict[str, Any]) -> bool:
    """
    Actualiza el perfil.
    AHORA: Guarda avatar/banner PRINCIPALMENTE en Auth Metadata (más confiable)
    y bio en tabla 'profiles' si existe.
    """
    try:
        admin_client = supabase_auth.get_admin_client()
        
        # Separar campos
        auth_updates = {}      # Campos que van a Auth Metadata
        profile_updates = {}   # Campos que van a tabla profiles
        
        for key, value in updates.items():
            if key in ["full_name", "username", "avatar", "banner"]:
                auth_updates[key] = value
            elif key in ["bio"]:
                profile_updates[key] = value
        
        # 1. ACTUALIZAR AUTH METADATA (PRINCIPAL - SIEMPRE FUNCIONA)
        if auth_updates:
            current_user = await supabase_auth.get_user_by_id(user_id)
            if current_user:
                current_metadata = current_user.get("user_metadata", {})
                new_metadata = {**current_metadata, **auth_updates}
                
                try:
                    admin_client.auth.admin.update_user_by_id(
                        user_id, 
                        {"user_metadata": new_metadata}
                    )
                    logger.info(f"✅ Metadata actualizada en Auth para {user_id}: {list(auth_updates.keys())}")
                except Exception as e:
                    logger.error(f"Error al actualizar Auth Metadata: {e}")
                    return False
        
        # 2. ACTUALIZAR TABLA PROFILES (OPCIONAL - SOLO BIO)
        if profile_updates:
            try:
                # Verificar si la tabla existe y tiene la columna bio
                # Intentar obtener perfil existente
                check_response = admin_client.table("profiles").select("*").eq("id", user_id).execute()
                
                if check_response.data and len(check_response.data) > 0:
                    # Actualizar existente
                    admin_client.table("profiles").update(profile_updates).eq("id", user_id).execute()
                    logger.info(f"✅ Perfil actualizado en tabla 'profiles' para {user_id}: {list(profile_updates.keys())}")
                else:
                    # Crear nuevo perfil (solo con bio)
                    new_profile = {"id": user_id, **profile_updates}
                    if "created_at" not in new_profile:
                        new_profile["created_at"] = datetime.now().isoformat()
                    
                    admin_client.table("profiles").insert(new_profile).execute()
                    logger.info(f"✅ Nuevo perfil creado en tabla 'profiles' para {user_id}")
            except Exception as e:
                # Si la tabla no existe o falla, no es crítico porque Auth ya tiene los datos
                logger.debug(f"No se pudo actualizar tabla 'profiles' (no crítico): {e}")
        
        return True

    except Exception as e:
        logger.error(f"Error general actualizando perfil para {user_id}: {str(e)}")
        return False


# ============================================
# ENDPOINTS DE PERFIL
# ============================================

@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Obtiene el perfil completo del usuario actual"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    
    if not user_id:
        logger.error("No se pudo obtener user_id del token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se pudo identificar al usuario"
        )

    logger.info(f"📋 Obteniendo perfil para usuario {user_id}")

    try:
        profile = await get_user_profile_from_supabase(user_id)
        
        if not profile:
            # Fallback básico si todo falla
            return ProfileResponse(
                id=user_id,
                email=current_user.get("email", ""),
                username=None,
                full_name=None,
                bio=None,
                avatar=None,
                banner=None,
                email_verified=current_user.get("email_verified", False),
                created_at=None,
                last_sign_in_at=None
            )

        # Formatear respuesta asegurando tipos correctos
        created_at = profile.get("created_at")
        if created_at and hasattr(created_at, "isoformat"):
            created_at = created_at.isoformat()
        
        last_sign_in = profile.get("last_sign_in_at")
        if last_sign_in and hasattr(last_sign_in, "isoformat"):
            last_sign_in = last_sign_in.isoformat()

        return ProfileResponse(
            id=profile.get("id", user_id),
            email=profile.get("email", current_user.get("email", "")),
            username=profile.get("username"),
            full_name=profile.get("full_name"),
            bio=profile.get("bio"),
            avatar=profile.get("avatar"),
            banner=profile.get("banner"),
            email_verified=profile.get("email_verified", False),
            created_at=created_at,
            last_sign_in_at=last_sign_in
        )
        
    except Exception as e:
        logger.error(f"Error obteniendo perfil: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener perfil: {str(e)}"
        )


@router.put("/profile", response_model=dict)
async def update_profile(
    request: ProfileUpdateRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Actualiza la información del perfil del usuario"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No se pudo identificar al usuario")

    logger.info(f"✏️ Actualizando perfil para usuario {user_id}")

    updates = {}
    if request.full_name is not None: updates["full_name"] = request.full_name
    if request.username is not None: updates["username"] = request.username
    if request.bio is not None: updates["bio"] = request.bio
    if request.avatar is not None: updates["avatar"] = request.avatar
    if request.banner is not None: updates["banner"] = request.banner

    if not updates:
        return {"message": "No se realizaron cambios", "updated": []}

    try:
        success = await update_user_profile_in_supabase(user_id, updates)
        
        if success:
            # Obtener perfil actualizado inmediatamente
            updated_profile = await get_user_profile_from_supabase(user_id)
            
            return {
                "message": "Perfil actualizado correctamente",
                "updated": list(updates.keys()),
                "data": {
                    "avatar": updated_profile.get("avatar") if updated_profile else None,
                    "banner": updated_profile.get("banner") if updated_profile else None,
                    "full_name": updated_profile.get("full_name") if updated_profile else None,
                    "username": updated_profile.get("username") if updated_profile else None,
                    "bio": updated_profile.get("bio") if updated_profile else None
                }
            }
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error al actualizar perfil")
            
    except Exception as e:
        logger.error(f"Error actualizando perfil: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al actualizar perfil: {str(e)}")


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Obtiene información básica del usuario actual"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    username = current_user.get("username") or current_user.get("preferred_username")
    full_name = current_user.get("full_name") or current_user.get("name")
    
    return UserResponse(
        id=user_id,
        email=current_user.get("email", ""),
        username=username,
        full_name=full_name
    )


# ============================================
# ENDPOINTS PARA AVATAR
# ============================================

@router.post("/avatar", response_model=dict)
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    token: str = Depends(get_auth_token)
):
    """Sube un avatar para el usuario actual"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No se pudo identificar al usuario")

    logger.info(f"📸 Subiendo avatar para usuario {user_id}")
    logger.info(f"   Archivo: {file.filename}, Tipo: {file.content_type}")

    allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tipo de archivo no permitido. Permitidos: {', '.join(allowed_types)}"
        )

    content = await file.read()
    max_size = 2 * 1024 * 1024
    
    if len(content) > max_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Archivo demasiado grande. Máximo 2MB."
        )

    if not supabase_storage.is_configured:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Servicio de storage no disponible")

    url = await supabase_storage.upload_file_with_user_token(
        bucket="avatars",
        user_id=user_id,
        user_token=token,
        file_content=content,
        filename=file.filename or "avatar.jpg",
        content_type=file.content_type
    )

    if not url:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error subiendo archivo a Supabase")

    logger.info(f"✅ Avatar subido: {url}")

    # Actualizar perfil con la nueva URL (esto ahora guarda en Auth Metadata)
    await update_user_profile_in_supabase(user_id, {"avatar": url})

    return {
        "message": "Avatar subido correctamente",
        "url": url,
        "success": True
    }


@router.get("/avatar", response_model=dict)
async def get_avatar_url(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Obtiene la URL del avatar del usuario"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    
    if not user_id:
        return {"avatar_url": None, "has_avatar": False}

    try:
        profile = await get_user_profile_from_supabase(user_id)
        avatar_url = profile.get("avatar") if profile else None
        
        return {
            "avatar_url": avatar_url,
            "has_avatar": avatar_url is not None
        }
    except Exception as e:
        logger.error(f"Error obteniendo avatar: {str(e)}")
        return {"avatar_url": None, "has_avatar": False, "error": str(e)}


@router.delete("/avatar", response_model=dict)
async def delete_avatar(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Elimina el avatar del usuario"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No se pudo identificar al usuario")

    logger.info(f"🗑️ Eliminando avatar para usuario {user_id}")

    try:
        profile = await get_user_profile_from_supabase(user_id)
        current_avatar = profile.get("avatar") if profile else None
        
        if current_avatar and supabase_storage.is_configured:
            await supabase_storage.delete_file("avatars", current_avatar)
        
        await update_user_profile_in_supabase(user_id, {"avatar": None})
        
        return {"message": "Avatar eliminado correctamente", "success": True}
    except Exception as e:
        logger.error(f"Error eliminando avatar: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al eliminar avatar: {str(e)}")


# ============================================
# ENDPOINTS PARA BANNER (SIMILARES)
# ============================================

@router.post("/banner", response_model=dict)
async def upload_banner(
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
    token: str = Depends(get_auth_token)
):
    """Sube un banner para el usuario actual"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No se pudo identificar al usuario")

    logger.info(f"📸 Subiendo banner para usuario {user_id}")
    logger.info(f"   Archivo: {file.filename}, Tipo: {file.content_type}")

    allowed_types = ["image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de archivo no permitido. Usa JPG, PNG, GIF o WEBP"
        )

    content = await file.read()
    max_size = 5 * 1024 * 1024
    
    if len(content) > max_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Archivo demasiado grande. Máximo 5MB."
        )

    if not supabase_storage.is_configured:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Servicio de storage no disponible")

    url = await supabase_storage.upload_file_with_user_token(
        bucket="banners",
        user_id=user_id,
        user_token=token,
        file_content=content,
        filename=file.filename or "banner.jpg",
        content_type=file.content_type
    )

    if not url:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error subiendo archivo a Supabase")

    logger.info(f"✅ Banner subido: {url}")

    await update_user_profile_in_supabase(user_id, {"banner": url})

    return {
        "message": "Banner subido correctamente",
        "url": url,
        "success": True
    }


@router.get("/banner", response_model=dict)
async def get_banner_url(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Obtiene la URL del banner del usuario"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    
    if not user_id:
        return {"banner_url": None, "has_banner": False}

    try:
        profile = await get_user_profile_from_supabase(user_id)
        banner_url = profile.get("banner") if profile else None
        
        return {
            "banner_url": banner_url,
            "has_banner": banner_url is not None
        }
    except Exception as e:
        logger.error(f"Error obteniendo banner: {str(e)}")
        return {"banner_url": None, "has_banner": False, "error": str(e)}


@router.delete("/banner", response_model=dict)
async def delete_banner(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Elimina el banner del usuario"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No se pudo identificar al usuario")

    logger.info(f"🗑️ Eliminando banner para usuario {user_id}")

    try:
        profile = await get_user_profile_from_supabase(user_id)
        current_banner = profile.get("banner") if profile else None
        
        if current_banner and supabase_storage.is_configured:
            await supabase_storage.delete_file("banners", current_banner)
        
        await update_user_profile_in_supabase(user_id, {"banner": None})
        
        return {"message": "Banner eliminado correctamente", "success": True}
    except Exception as e:
        logger.error(f"Error eliminando banner: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error al eliminar banner: {str(e)}")


# ============================================
# ENDPOINTS DE DIAGNÓSTICO
# ============================================

@router.get("/debug/supabase-status")
async def check_supabase_status(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Endpoint de diagnóstico para verificar el estado de Supabase"""
    result = await supabase_storage.test_connection()
    result["auth_available"] = supabase_auth.is_available()
    return result

@router.get("/debug/my-profile")
async def get_my_debug_profile(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Debug: Ver información completa del usuario"""
    user_id = current_user.get("sub") or current_user.get("user_id") or current_user.get("id")
    profile = await get_user_profile_from_supabase(user_id) if user_id else None
    
    return {
        "from_token": current_user,
        "from_supabase": profile,
        "user_id": user_id
    }