# app/services/two_factor_service.py
import pyotp
import qrcode
from qrcode.image.svg import SvgImage
import io
import base64
import secrets
import hashlib
from typing import List, Tuple, Dict
from datetime import datetime, timedelta

class TwoFactorService:
    """Servicio para manejar autenticación de dos factores"""
    
    def __init__(self):
        self.issuer_name = "TodoApp"
    
    def generate_secret(self, email: str) -> Tuple[str, str, str]:
        """
        Genera un secreto TOTP y su código QR en formato SVG
        Retorna: (secret, qr_code_svg_base64, provisioning_uri)
        """
        # Generar secreto
        secret = pyotp.random_base32()
        
        # Crear URI de provisionamiento
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=email,
            issuer_name=self.issuer_name
        )
        
        # Generar QR en formato SVG (NO requiere Pillow)
        img = qrcode.make(provisioning_uri, image_factory=SvgImage)
        
        # Convertir SVG a string
        stream = io.BytesIO()
        img.save(stream)
        svg_string = stream.getvalue().decode('utf-8')
        
        # Convertir a base64 para enviar al frontend
        svg_base64 = base64.b64encode(svg_string.encode('utf-8')).decode('utf-8')
        
        return secret, svg_base64, provisioning_uri
    
    def verify_code(self, secret: str, code: str) -> bool:
        """Verifica si el código TOTP es válido"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code)
        except Exception:
            return False
    
    def generate_recovery_codes(self, count: int = 10) -> List[Dict[str, str]]:
        """Genera códigos de respaldo"""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            formatted = f"{code[:4]}-{code[4:]}"
            hashed = hashlib.sha256(formatted.encode()).hexdigest()
            codes.append({"code": formatted, "hash": hashed})
        return codes
    
    def verify_recovery_code(self, stored_hashes: List[str], code: str) -> bool:
        """Verifica si un código de respaldo es válido"""
        hashed = hashlib.sha256(code.encode()).hexdigest()
        return hashed in stored_hashes

# Instancia global
two_factor_service = TwoFactorService()

# Cache temporal para setups en progreso
two_factor_setup_cache: Dict[str, Dict] = {}