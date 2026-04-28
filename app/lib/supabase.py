# app/lib/supabase.py
from supabase import create_client, Client
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class SupabaseClient:
    """Cliente de Supabase para el backend"""
    
    def __init__(self):
        self.url = settings.SUPABASE_URL
        self.key = settings.SUPABASE_SERVICE_KEY
        self.client: Client = None
        
        if self.url and self.key:
            try:
                self.client = create_client(self.url, self.key)
                logger.info("✅ Cliente de Supabase inicializado correctamente")
            except Exception as e:
                logger.error(f"❌ Error inicializando Supabase: {str(e)}")
                self.client = None
        else:
            logger.info("ℹ️ Supabase no configurado - funciones de storage deshabilitadas")
    
    def get_client(self) -> Client:
        """Retorna el cliente de Supabase"""
        if not self.client:
            raise Exception("Supabase no está configurado")
        return self.client
    
    def is_configured(self) -> bool:
        """Verifica si Supabase está configurado"""
        return self.client is not None

# Instancia global
supabase_client = SupabaseClient()