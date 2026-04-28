"""
Punto de entrada principal de la API FastAPI
"""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
import time
from datetime import datetime
from contextlib import asynccontextmanager
import sys
import os

from app.config import settings
from app.models import HealthResponse
from app.routers import auth, users, storage, tasks, debug, webauthn
from app.utils.helpers import get_client_ip

# ============================================
# CONFIGURACIÓN DE LOGGING
# ============================================

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ],
        force=False
    )

logger = logging.getLogger(__name__)
logger.propagate = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manejador de eventos de inicio y cierre de la aplicación"""
    # Startup
    print("=" * 60)
    print(f"Iniciando {settings.API_TITLE} v{settings.API_VERSION}")
    print(f"Frontend URL: {settings.FRONTEND_URL}")
    print("-" * 60)
    
    # Mostrar estado de Supabase
    if settings.is_supabase_configured():
        print(f"✅ Supabase Auth: CONFIGURADO")
        print(f"   URL: {settings.SUPABASE_URL}")
        print(f"   Storage Buckets: {settings.SUPABASE_BUCKET_AVATARS}, {settings.SUPABASE_BUCKET_BANNERS}")
    else:
        print("❌ Supabase Auth: NO CONFIGURADO")
        print("   ⚠️  La autenticación no funcionará sin Supabase")
    
    # Mostrar estado de WebAuthn
    try:
        from app.services.webauthn_service import webauthn_service
        print(f"🔐 WebAuthn: CONFIGURADO (RP ID: {webauthn_service.rp_id})")
    except Exception as e:
        print(f"⚠️ WebAuthn: Error en configuración - {str(e)}")
    
    # Mostrar estado de SMTP
    if settings.validate_smtp_config():
        print(f"✅ SMTP: CONFIGURADO ({settings.SMTP_HOST}:{settings.SMTP_PORT})")
    else:
        print("⚠️ SMTP: NO CONFIGURADO (emails personalizados no funcionarán)")
    
    # Mostrar configuración CORS
    print(f"🌍 CORS Origins permitidos: {settings.ALLOWED_ORIGINS}")
    
    # Listar routers disponibles
    routers_disponibles = ["auth", "users", "storage", "tasks", "debug", "webauthn"]
    print(f"📡 Routers cargados: {', '.join(routers_disponibles)}")
    print("=" * 60)
    
    yield
    
    # Shutdown
    print("🛑 API detenida")


# Crear aplicación FastAPI
app = FastAPI(
    title=settings.API_TITLE,
    description=settings.API_DESCRIPTION,
    version=settings.API_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# ============================================
# CONFIGURACIÓN CORS
# ============================================

# Asegurar que ALLOWED_ORIGINS incluya localhost:5173
cors_origins = settings.ALLOWED_ORIGINS

# Verificar y agregar localhost:5173 si no está presente
if "http://localhost:5173" not in cors_origins:
    cors_origins.append("http://localhost:5173")
    logger.info("✅ Agregado http://localhost:5173 a CORS origins")

if "http://localhost:3000" not in cors_origins:
    cors_origins.append("http://localhost:3000")
    logger.info("✅ Agregado http://localhost:3000 a CORS origins")

# Configurar CORS con todas las opciones necesarias para WebAuthn
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Accept",
        "Origin",
        "X-Requested-With",
        "X-Session-ID",
        "X-CSRF-Token"
    ],
    expose_headers=["X-Process-Time"],
    max_age=86400,  # 24 horas de caché para preflight requests
)

logger.info(f"🌍 CORS configurado con origins: {cors_origins}")


# Middleware para logging de requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    client_ip = get_client_ip(request)
    method = request.method
    url = request.url.path
    
    try:
        response = await call_next(request)
    except Exception as e:
        logger.error(f"Error procesando {method} {url}: {str(e)}")
        raise
    
    process_time = time.time() - start_time
    
    # Log solo para endpoints de API
    if url.startswith("/api/") or url.startswith("/debug/"):
        logger.info(f"{client_ip} - {method} {url} - {response.status_code} - {process_time:.3f}s")
    
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Middleware para headers de seguridad
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Configuración CSP específica para WebAuthn
    if not response.headers.get("Content-Security-Policy"):
        path = request.url.path
        
        if path.startswith("/docs") or path.startswith("/redoc") or path == "/":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-src 'self';"
            )
        else:
            # Para WebAuthn, permitir conexiones al origen actual
            response.headers["Content-Security-Policy"] = "default-src 'self'"
    
    return response


# Manejadores de errores
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.warning(f"HTTP {exc.status_code}: {exc.detail} - {request.method} {request.url.path}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status_code": exc.status_code,
            "path": request.url.path,
            "method": request.method,
            "timestamp": datetime.now().isoformat()
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(f"Error de validación en {request.method} {request.url.path}: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Error de validación en los datos enviados",
            "status_code": 422,
            "errors": exc.errors(),
            "path": request.url.path,
            "method": request.method,
            "timestamp": datetime.now().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Error no controlado en {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Error interno del servidor",
            "status_code": 500,
            "path": request.url.path,
            "method": request.method,
            "timestamp": datetime.now().isoformat()
        }
    )


# ============================================
# INCLUIR TODOS LOS ROUTERS
# ============================================

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(storage.router)
app.include_router(tasks.router)
app.include_router(debug.router)
app.include_router(webauthn.router)

logger.info("✅ Todos los routers han sido registrados correctamente")
logger.info("   - auth: Autenticación con Supabase")
logger.info("   - users: Gestión de usuarios")
logger.info("   - storage: Almacenamiento de archivos")
logger.info("   - tasks: Gestión de tareas")
logger.info("   - debug: Diagnóstico")
logger.info("   - webauthn: Passkeys / WebAuthn")


# ============================================
# ENDPOINTS RAÍZ
# ============================================

@app.get("/", tags=["root"])
async def root():
    return {
        "message": f"Bienvenido a {settings.API_TITLE}",
        "version": settings.API_VERSION,
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/api/health",
        "info": "/api/info",
        "debug": "/debug",
        "endpoints": {
            "auth": "/api/auth/*",
            "users": "/api/users/*",
            "storage": "/api/storage/*",
            "tasks": "/api/tasks/*",
            "debug": "/debug/*",
            "webauthn": "/api/webauthn/*"
        },
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/health", tags=["health"])
async def health_check():
    """Health check de la API"""
    import httpx
    
    supabase_status = {
        "configured": settings.is_supabase_configured(),
        "auth_available": False,
        "storage_available": False
    }
    
    webauthn_status = {
        "configured": False,
        "rp_id": None,
        "error": None
    }
    
    # Verificar Supabase Auth
    if settings.is_supabase_configured():
        try:
            from app.services.supabase_auth_service import supabase_auth
            supabase_status["auth_available"] = supabase_auth.is_available()
        except Exception as e:
            supabase_status["auth_available"] = False
            supabase_status["auth_error"] = str(e)
        
        # Verificar Supabase Storage
        try:
            from app.services.supabase_service import supabase_storage
            supabase_status["storage_available"] = supabase_storage.is_configured
        except Exception as e:
            supabase_status["storage_available"] = False
            supabase_status["storage_error"] = str(e)
    
    # Verificar WebAuthn
    try:
        from app.services.webauthn_service import webauthn_service
        webauthn_status["configured"] = True
        webauthn_status["rp_id"] = webauthn_service.rp_id
        webauthn_status["origin"] = webauthn_service.origin
    except Exception as e:
        webauthn_status["error"] = str(e)
    
    return {
        "status": "healthy",
        "service": settings.API_TITLE,
        "version": settings.API_VERSION,
        "timestamp": datetime.now().isoformat(),
        "cors": {
            "allowed_origins": cors_origins,
            "credentials_allowed": True
        },
        "checks": {
            "supabase": supabase_status,
            "webauthn": webauthn_status,
            "smtp": {
                "configured": settings.validate_smtp_config()
            }
        }
    }


@app.get("/api/info", tags=["info"])
async def api_info():
    """Información detallada de la API"""
    # Obtener información de WebAuthn
    webauthn_info = {
        "configured": False,
        "rp_id": None,
        "rp_name": None,
        "origin": None
    }
    
    try:
        from app.services.webauthn_service import webauthn_service
        webauthn_info["configured"] = True
        webauthn_info["rp_id"] = webauthn_service.rp_id
        webauthn_info["rp_name"] = webauthn_service.rp_name
        webauthn_info["origin"] = webauthn_service.origin
    except Exception as e:
        webauthn_info["error"] = str(e)
    
    return {
        "name": settings.API_TITLE,
        "version": settings.API_VERSION,
        "description": settings.API_DESCRIPTION,
        "frontend_url": settings.FRONTEND_URL,
        "supabase_configured": settings.is_supabase_configured(),
        "cors_allowed_origins": cors_origins,
        "webauthn": webauthn_info,
        "endpoints": {
            "auth": {
                "register": "/api/auth/register",
                "login": "/api/auth/login",
                "refresh": "/api/auth/refresh",
                "logout": "/api/auth/logout",
                "forgot_password": "/api/auth/forgot-password",
                "reset_password": "/api/auth/reset-password"
            },
            "users": {
                "profile": "/api/users/profile",
                "me": "/api/users/me",
                "avatar": "/api/users/avatar",
                "banner": "/api/users/banner"
            },
            "webauthn": {
                "register_begin": "/api/webauthn/register/begin",
                "register_complete": "/api/webauthn/register/complete",
                "login_begin": "/api/webauthn/login/begin",
                "login_complete": "/api/webauthn/login/complete",
                "list_credentials": "/api/webauthn/credentials",
                "delete_credential": "/api/webauthn/credentials/{credential_id}"
            }
        },
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/routers", tags=["debug"])
async def list_routers():
    """Lista todos los routers registrados"""
    routes = []
    for route in app.routes:
        if hasattr(route, "methods"):
            routes.append({
                "path": route.path,
                "methods": list(route.methods),
                "name": route.name
            })
    
    return {
        "total_routes": len(routes),
        "routes": routes,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/debug", tags=["debug"])
async def debug_welcome():
    """Página de bienvenida para los endpoints de debug"""
    return {
        "message": "🔧 Endpoints de diagnóstico disponibles",
        "endpoints": {
            "auth_debug": "/api/auth/debug/check",
            "routers": "/api/routers",
            "health": "/api/health",
            "supabase_status": "/api/users/debug/supabase-status",
            "webauthn_status": "/api/webauthn/credentials"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=settings.LOG_LEVEL.lower()
    )