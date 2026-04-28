# app/routers/debug.py
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
import jwt
from app.config import settings
from app.dependencies import get_current_user, get_auth_token
from app.services.supabase_auth_service import supabase_auth
from app.services.supabase_service import supabase_storage
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/debug", tags=["debug"])
security = HTTPBearer()


# ============================================
# ENDPOINTS DE AUTENTICACIÓN CON SUPABASE
# ============================================

@router.get("/auth")
async def debug_auth(
    request: Request, 
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Endpoint para diagnosticar problemas de autenticación con Supabase
    Útil para depurar por qué el token no está siendo aceptado
    """
    token = credentials.credentials
    
    logger.info("=" * 60)
    logger.info("🔍 DEBUG AUTH ENDPOINT - SUPABASE")
    logger.info(f"Token preview: {token[:50]}...")
    
    result = {
        "config": {
            "supabase_url": settings.SUPABASE_URL,
            "supabase_configured": settings.is_supabase_configured(),
        },
        "token_info": {},
        "supabase_tests": {},
        "headers": dict(request.headers),
        "timestamp": datetime.now().isoformat()
    }
    
    # 1. Decodificar token sin verificar para ver su contenido
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        result["token_info"]["payload"] = {
            "sub": unverified.get('sub'),
            "email": unverified.get('email'),
            "exp": unverified.get('exp'),
            "iat": unverified.get('iat'),
            "aud": unverified.get('aud'),
            "iss": unverified.get('iss')
        }
        result["token_info"]["expires_at"] = unverified.get('exp')
        result["token_info"]["expires_at_datetime"] = datetime.fromtimestamp(unverified.get('exp', 0)).isoformat() if unverified.get('exp') else None
        result["token_info"]["is_expired"] = unverified.get('exp', 0) < datetime.now().timestamp()
        result["token_info"]["issuer"] = unverified.get('iss')
        result["token_info"]["subject"] = unverified.get('sub')
        result["token_info"]["email"] = unverified.get('email')
        
        # Verificar si el issuer coincide con Supabase
        expected_issuer = f"{settings.SUPABASE_URL}/auth/v1"
        result["token_info"]["issuer_match"] = unverified.get('iss') == expected_issuer
        
    except Exception as e:
        result["token_info"]["error"] = str(e)
        logger.error(f"❌ Error decodificando token: {e}")
    
    # 2. Verificar token con Supabase
    if supabase_auth.is_available():
        try:
            user_data = await supabase_auth.verify_token(token)
            
            if user_data:
                result["supabase_tests"]["verify_token"] = {
                    "status": "success",
                    "user_id": user_data.get("user_id"),
                    "email": user_data.get("email"),
                    "email_verified": user_data.get("email_verified"),
                    "username": user_data.get("username")
                }
                logger.info("✅ Token verificado con Supabase")
            else:
                result["supabase_tests"]["verify_token"] = {
                    "status": "failed",
                    "message": "Token inválido o expirado"
                }
                logger.error("❌ Token inválido para Supabase")
                
        except Exception as e:
            result["supabase_tests"]["verify_token_error"] = str(e)
            logger.error(f"❌ Error verificando token con Supabase: {e}")
    else:
        result["supabase_tests"]["verify_token"] = "Supabase no configurado"
    
    # 3. Probar conectividad básica con Supabase
    if settings.is_supabase_configured():
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Probar endpoint de health de Supabase
                response = await client.get(
                    f"{settings.SUPABASE_URL}/auth/v1/health",
                    timeout=5.0
                )
                
                result["supabase_tests"]["auth_health"] = {
                    "status": response.status_code,
                    "reachable": response.status_code in [200, 204]
                }
                
        except Exception as e:
            result["supabase_tests"]["auth_health_error"] = str(e)
            logger.error(f"❌ Error conectando a Supabase Auth: {e}")
    else:
        result["supabase_tests"]["auth_health"] = "Supabase no configurado"
    
    logger.info("=" * 60)
    return result


@router.get("/token")
async def debug_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Endpoint simplificado que solo muestra información del token
    """
    token = credentials.credentials
    
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        
        # Verificar con Supabase si está disponible
        supabase_valid = False
        if supabase_auth.is_available():
            user_data = await supabase_auth.verify_token(token)
            supabase_valid = user_data is not None
        
        return {
            "valid_format": True,
            "supabase_valid": supabase_valid,
            "subject": unverified.get('sub'),
            "email": unverified.get('email'),
            "expires_at": unverified.get('exp'),
            "expires_at_datetime": datetime.fromtimestamp(unverified.get('exp', 0)).isoformat() if unverified.get('exp') else None,
            "issued_at": unverified.get('iat'),
            "issued_at_datetime": datetime.fromtimestamp(unverified.get('iat', 0)).isoformat() if unverified.get('iat') else None,
            "issuer": unverified.get('iss'),
            "is_expired": unverified.get('exp', 0) < datetime.now().timestamp()
        }
    except Exception as e:
        return {
            "valid_format": False,
            "error": str(e)
        }


@router.get("/config")
async def debug_config():
    """
    Muestra la configuración actual (sin datos sensibles)
    """
    return {
        "supabase": {
            "configured": settings.is_supabase_configured(),
            "url": settings.SUPABASE_URL if settings.SUPABASE_URL else None,
            "buckets": {
                "avatars": settings.SUPABASE_BUCKET_AVATARS,
                "banners": settings.SUPABASE_BUCKET_BANNERS
            },
            "max_file_size_mb": settings.MAX_FILE_SIZE_MB,
            "allowed_image_types": settings.ALLOWED_IMAGE_TYPES
        },
        "smtp": {
            "configured": settings.validate_smtp_config(),
            "host": settings.SMTP_HOST,
            "port": settings.SMTP_PORT,
            "from": settings.SMTP_FROM
        },
        "frontend_url": settings.FRONTEND_URL,
        "cors_origins": settings.ALLOWED_ORIGINS,
        "api": {
            "title": settings.API_TITLE,
            "version": settings.API_VERSION,
            "log_level": settings.LOG_LEVEL
        },
        "environment": {
            "python_env": "development" if settings.LOG_LEVEL == "DEBUG" else "production"
        }
    }


@router.get("/health-check")
async def debug_health_check():
    """
    Verifica la conectividad con todos los servicios externos
    """
    import time
    
    results = {
        "supabase_auth": {"status": "unknown", "latency_ms": None},
        "supabase_storage": {"status": "unknown", "latency_ms": None},
        "timestamp": datetime.now().isoformat()
    }
    
    # Verificar Supabase Auth
    if settings.is_supabase_configured():
        try:
            start = time.time()
            
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{settings.SUPABASE_URL}/auth/v1/health",
                    timeout=5.0
                )
                
                latency = int((time.time() - start) * 1000)
                
                results["supabase_auth"] = {
                    "status": "healthy" if response.status_code in [200, 204] else "unhealthy",
                    "latency_ms": latency,
                    "status_code": response.status_code,
                    "url": f"{settings.SUPABASE_URL}/auth/v1/health"
                }
        except Exception as e:
            results["supabase_auth"] = {
                "status": "error",
                "error": str(e)
            }
    else:
        results["supabase_auth"] = {
            "status": "not_configured"
        }
    
    # Verificar Supabase Storage
    if settings.is_supabase_configured():
        try:
            start = time.time()
            
            headers = {
                "Authorization": f"Bearer {settings.SUPABASE_SERVICE_KEY}",
                "apikey": settings.SUPABASE_SERVICE_KEY
            }
            
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(
                    f"{settings.SUPABASE_URL}/storage/v1/bucket",
                    headers=headers,
                    timeout=5.0
                )
                
                latency = int((time.time() - start) * 1000)
                
                results["supabase_storage"] = {
                    "status": "healthy" if response.status_code in [200, 401] else "unhealthy",
                    "latency_ms": latency,
                    "status_code": response.status_code,
                    "url": f"{settings.SUPABASE_URL}/storage/v1/bucket"
                }
        except Exception as e:
            results["supabase_storage"] = {
                "status": "error",
                "error": str(e)
            }
    else:
        results["supabase_storage"] = {
            "status": "not_configured"
        }
    
    return results


# ============================================
# ENDPOINTS DE USUARIO PARA DEBUG
# ============================================

@router.get("/user/me")
async def debug_my_info(
    current_user: dict = Depends(get_current_user)
):
    """
    Muestra información del usuario autenticado (debug)
    """
    return {
        "user_id": current_user.get("sub"),
        "email": current_user.get("email"),
        "username": current_user.get("username"),
        "email_verified": current_user.get("email_verified"),
        "user_metadata": current_user.get("user_metadata", {}),
        "raw_token_data": {k: v for k, v in current_user.items() if k not in ["user_metadata"]}
    }


@router.get("/user/permissions")
async def debug_my_permissions(
    current_user: dict = Depends(get_current_user)
):
    """
    Muestra los permisos/roles del usuario (debug)
    """
    roles = current_user.get("user_metadata", {}).get("roles", [])
    
    return {
        "user_id": current_user.get("sub"),
        "email": current_user.get("email"),
        "roles": roles,
        "is_admin": "admin" in roles,
        "permissions": {
            "can_create_tasks": True,
            "can_edit_tasks": True,
            "can_delete_tasks": True,
            "can_upload_files": True,
            "can_manage_users": "admin" in roles
        }
    }


# ============================================
# ENDPOINTS DE DIAGNÓSTICO DE STORAGE
# ============================================

@router.get("/storage/status")
async def debug_storage_status():
    """
    Verifica el estado del servicio de storage
    """
    if not supabase_storage.is_configured:
        return {
            "status": "unconfigured",
            "message": "Supabase Storage no está configurado",
            "buckets": []
        }
    
    result = await supabase_storage.test_connection()
    return result


@router.get("/storage/buckets")
async def debug_storage_buckets():
    """
    Lista los buckets disponibles en Supabase Storage
    """
    if not supabase_storage.is_configured:
        return {
            "status": "unconfigured",
            "buckets": []
        }
    
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
                    "status": "success",
                    "buckets": buckets,
                    "count": len(buckets)
                }
            else:
                return {
                    "status": "error",
                    "error": f"HTTP {response.status_code}: {response.text}"
                }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# ============================================
# ENDPOINTS DE DIAGNÓSTICO GENERAL
# ============================================

@router.get("/all")
async def debug_all(
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint que agrupa toda la información de debug
    """
    return {
        "config": await debug_config(),
        "health": await debug_health_check(),
        "user": await debug_my_info(current_user),
        "permissions": await debug_my_permissions(current_user),
        "storage": await debug_storage_status(),
        "timestamp": datetime.now().isoformat()
    }


@router.get("/environment")
async def debug_environment():
    """
    Muestra variables de entorno (sin datos sensibles)
    """
    import os
    
    safe_vars = [
        "SUPABASE_URL",
        "SUPABASE_BUCKET_AVATARS",
        "SUPABASE_BUCKET_BANNERS",
        "FRONTEND_URL",
        "API_TITLE",
        "API_VERSION",
        "LOG_LEVEL",
        "SMTP_HOST",
        "SMTP_PORT",
        "MAX_FILE_SIZE_MB"
    ]
    
    env_vars = {}
    for var in safe_vars:
        env_vars[var] = os.getenv(var, settings.__dict__.get(var, "not set"))
    
    return {
        "environment": env_vars,
        "python_version": __import__("sys").version,
        "platform": __import__("platform").platform()
    }