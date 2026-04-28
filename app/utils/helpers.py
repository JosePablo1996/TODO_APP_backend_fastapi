import random
import string
import json
from typing import Any, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def generate_random_string(length: int = 10) -> str:
    """
    Genera una cadena aleatoria de longitud específica
    
    Args:
        length: Longitud de la cadena
    
    Returns:
        Cadena aleatoria
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def format_response(
    success: bool,
    message: str,
    data: Optional[Dict[str, Any]] = None,
    status_code: int = 200
) -> Dict[str, Any]:
    """
    Formatea una respuesta estándar para la API
    
    Args:
        success: Indica si la operación fue exitosa
        message: Mensaje descriptivo
        data: Datos adicionales (opcional)
        status_code: Código HTTP (solo informativo)
    
    Returns:
        Diccionario formateado
    """
    response = {
        "success": success,
        "message": message,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if data:
        response["data"] = data
    
    return response

def parse_json_safe(json_str: str, default: Any = None) -> Any:
    """
    Parsea JSON de forma segura sin lanzar excepciones
    
    Args:
        json_str: Cadena JSON a parsear
        default: Valor por defecto si hay error
    
    Returns:
        Objeto parseado o valor por defecto
    """
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"Error parseando JSON: {str(e)}")
        return default

def mask_email(email: str) -> str:
    """
    Oculta parcialmente un email para mostrar (ej: j***@gmail.com)
    
    Args:
        email: Email a enmascarar
    
    Returns:
        Email enmascarado
    """
    if not email or "@" not in email:
        return email
    
    local, domain = email.split("@", 1)
    
    if len(local) <= 2:
        masked_local = local[0] + "*" * len(local[1:])
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    
    return f"{masked_local}@{domain}"

def format_datetime(dt: datetime, format: str = "%d/%m/%Y %H:%M") -> str:
    """
    Formatea una fecha/hora de forma consistente
    
    Args:
        dt: Objeto datetime
        format: Formato deseado
    
    Returns:
        Fecha formateada
    """
    if not dt:
        return ""
    
    return dt.strftime(format)

def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Trunca un texto a una longitud máxima
    
    Args:
        text: Texto a truncar
        max_length: Longitud máxima
        suffix: Sufijo a añadir
    
    Returns:
        Texto truncado
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def get_client_ip(request) -> str:
    """
    Obtiene la IP del cliente desde la request
    
    Args:
        request: Objeto Request de FastAPI
    
    Returns:
        Dirección IP
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host if request.client else "0.0.0.0"

def is_ajax_request(request) -> bool:
    """
    Verifica si la petición es AJAX
    
    Args:
        request: Objeto Request de FastAPI
    
    Returns:
        True si es AJAX
    """
    requested_with = request.headers.get("X-Requested-With")
    return requested_with == "XMLHttpRequest"

def convert_to_bool(value: Any) -> bool:
    """
    Convierte varios tipos a booleano de forma segura
    
    Args:
        value: Valor a convertir
    
    Returns:
        Booleano resultante
    """
    if isinstance(value, bool):
        return value
    
    if isinstance(value, str):
        return value.lower() in ("true", "yes", "1", "on")
    
    if isinstance(value, (int, float)):
        return value != 0
    
    return bool(value)