import re
from typing import Tuple, List, Optional

def validate_password(password: str, min_length: int = 8) -> Tuple[bool, Optional[str], List[str]]:
    """
    Valida la fortaleza de una contraseña
    
    Args:
        password: Contraseña a validar
        min_length: Longitud mínima requerida
    
    Returns:
        Tuple (es_válida, mensaje_error, lista_requisitos_cumplidos)
    """
    requirements = []
    errors = []
    
    # Verificar longitud mínima
    if len(password) >= min_length:
        requirements.append("longitud")
    else:
        errors.append(f"Mínimo {min_length} caracteres")
    
    # Verificar minúsculas
    if re.search(r"[a-z]", password):
        requirements.append("minuscula")
    else:
        errors.append("Al menos una minúscula")
    
    # Verificar mayúsculas
    if re.search(r"[A-Z]", password):
        requirements.append("mayuscula")
    else:
        errors.append("Al menos una mayúscula")
    
    # Verificar números
    if re.search(r"[0-9]", password):
        requirements.append("numero")
    else:
        errors.append("Al menos un número")
    
    # Verificar símbolos especiales
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        requirements.append("simbolo")
    else:
        errors.append("Al menos un símbolo especial")
    
    is_valid = len(errors) == 0
    
    # Mensaje de error combinado
    error_msg = ". ".join(errors) if errors else None
    
    return is_valid, error_msg, requirements

def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Valida que un email tenga formato correcto
    
    Args:
        email: Email a validar
    
    Returns:
        Tuple (es_válido, mensaje_error)
    """
    # Patrón básico de email
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    
    if not email:
        return False, "El email no puede estar vacío"
    
    if len(email) > 254:  # Longitud máxima estándar
        return False, "El email es demasiado largo"
    
    if not re.match(pattern, email):
        return False, "Formato de email inválido"
    
    # Verificar dominios comunes (opcional)
    domain = email.split("@")[1].lower()
    blocked_domains = ["tempmail.com", "mailinator.com"]
    
    if domain in blocked_domains:
        return False, "Dominio de email no permitido"
    
    return True, None

def validate_username(username: str) -> Tuple[bool, Optional[str]]:
    """
    Valida que un nombre de usuario sea válido
    
    Args:
        username: Nombre de usuario a validar
    
    Returns:
        Tuple (es_válido, mensaje_error)
    """
    if not username:
        return False, "El usuario no puede estar vacío"
    
    if len(username) < 3:
        return False, "Mínimo 3 caracteres"
    
    if len(username) > 50:
        return False, "Máximo 50 caracteres"
    
    # Solo letras, números, guiones y guiones bajos
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return False, "Solo letras, números, guiones y guiones bajos"
    
    # Verificar que no comience con número (opcional)
    if username[0].isdigit():
        return False, "El nombre de usuario no puede comenzar con un número"
    
    return True, None

def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Valida que una URL sea válida
    
    Args:
        url: URL a validar
    
    Returns:
        Tuple (es_válida, mensaje_error)
    """
    if not url:
        return False, "La URL no puede estar vacía"
    
    # Patrón básico de URL
    pattern = r"^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$"
    
    if not re.match(pattern, url):
        return False, "Formato de URL inválido"
    
    return True, None

def sanitize_input(text: str) -> str:
    """
    Sanitiza texto para prevenir inyecciones
    
    Args:
        text: Texto a sanitizar
    
    Returns:
        Texto sanitizado
    """
    if not text:
        return ""
    
    # Eliminar caracteres potencialmente peligrosos
    text = re.sub(r"[<>\"']", "", text)
    
    # Limitar longitud
    if len(text) > 1000:
        text = text[:1000]
    
    return text.strip()

def calculate_password_strength(password: str) -> Dict[str, any]:
    """
    Calcula la fortaleza de una contraseña y devuelve métricas
    
    Args:
        password: Contraseña a evaluar
    
    Returns:
        Diccionario con métricas de fortaleza
    """
    score = 0
    max_score = 100
    
    if not password:
        return {
            "score": 0,
            "strength": "Muy débil",
            "color": "red-500",
            "requirements": []
        }
    
    requirements = []
    
    # Longitud (hasta 30 puntos)
    length_score = min(len(password) * 2, 30)
    score += length_score
    
    if len(password) >= 8:
        requirements.append("✓ 8+ caracteres")
    
    # Variedad de caracteres
    if re.search(r"[a-z]", password):
        score += 10
        requirements.append("✓ minúsculas")
    
    if re.search(r"[A-Z]", password):
        score += 10
        requirements.append("✓ mayúsculas")
    
    if re.search(r"[0-9]", password):
        score += 10
        requirements.append("✓ números")
    
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        score += 20
        requirements.append("✓ símbolos")
    
    # Bonus por combinaciones
    if (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password) and 
        re.search(r"[0-9]", password) and re.search(r"[!@#$%^&*]", password)):
        score += 20
        requirements.append("✓ combinación completa")
    
    # Determinar nivel de fortaleza
    if score < 30:
        strength = "Muy débil"
        color = "red-500"
    elif score < 50:
        strength = "Débil"
        color = "orange-500"
    elif score < 70:
        strength = "Media"
        color = "yellow-500"
    elif score < 90:
        strength = "Buena"
        color = "blue-500"
    else:
        strength = "Excelente"
        color = "green-500"
    
    return {
        "score": min(score, max_score),
        "strength": strength,
        "color": color,
        "requirements": requirements
    }