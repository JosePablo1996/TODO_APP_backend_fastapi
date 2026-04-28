# app/services/version_service.py (NUEVO)
"""
Servicio para manejar versiones de la app y migraciones
"""
import logging
from typing import Optional, Dict, Any
from app.services.supabase_auth_service import supabase_auth

logger = logging.getLogger(__name__)

class VersionService:
    """Controla compatibilidad de versiones de la app"""
    
    MINIMUM_APP_VERSION = "1.0.0"
    CURRENT_API_VERSION = "2.2.0"
    
    # Historial de cambios y migraciones
    CHANGELOG = {
        "1.0.0": {
            "features": ["auth", "tasks", "profile"],
            "required": True
        },
        "1.1.0": {
            "features": ["passkeys", "biometric_auth"],
            "required": False
        },
        "1.2.0": {
            "features": ["offline_mode"],
            "required": False
        }
    }
    
    @classmethod
    def is_version_supported(cls, app_version: str) -> bool:
        """Verifica si la versión de la app es compatible"""
        # Comparar versiones
        try:
            from packaging import version
            return version.parse(app_version) >= version.parse(cls.MINIMUM_APP_VERSION)
        except ImportError:
            # Comparación simple si packaging no está instalado
            app_parts = [int(x) for x in app_version.split(".")]
            min_parts = [int(x) for x in cls.MINIMUM_APP_VERSION.split(".")]
            
            for app, min_v in zip(app_parts, min_parts):
                if app > min_v:
                    return True
                elif app < min_v:
                    return False
            return len(app_parts) >= len(min_parts)
    
    @classmethod
    def get_migration_path(cls, from_version: str) -> list:
        """Obtiene las migraciones necesarias entre versiones"""
        migrations = []
        
        for version, info in cls.CHANGELOG.items():
            if version > from_version:
                migrations.append({
                    "version": version,
                    "features": info["features"],
                    "required": info["required"]
                })
        
        return migrations
    
    @classmethod
    def check_force_update(cls, app_version: str) -> Dict[str, Any]:
        """Determina si la app necesita actualización forzosa"""
        supported = cls.is_version_supported(app_version)
        
        response = {
            "force_update": not supported,
            "current_app_version": app_version,
            "minimum_required": cls.MINIMUM_APP_VERSION,
            "latest_available": list(cls.CHANGELOG.keys())[-1] if cls.CHANGELOG else "1.0.0",
            "message": None
        }
        
        if not supported:
            response["message"] = f"Tu versión ({app_version}) ya no es compatible. Actualiza a la versión {cls.MINIMUM_APP_VERSION} o superior."
        
        return response

# Instancia global
version_service = VersionService()