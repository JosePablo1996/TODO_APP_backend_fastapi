# app/models.py
"""
Modelos Pydantic para la API
"""
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime


# ============================================
# MODELOS DE AUTENTICACIÓN
# ============================================

class ForgotPasswordRequest(BaseModel):
    """
    Solicitud de olvido de contraseña.
    ✅ Soporta detección de plataforma: web o mobile
    """
    email: EmailStr = Field(..., description="Email del usuario", example="usuario@ejemplo.com")
    platform: Optional[str] = Field(
        'web', 
        description="Plataforma desde la que se solicita: 'web' o 'mobile'",
        example="mobile",
        pattern="^(web|mobile)$"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "usuario@ejemplo.com",
                "platform": "web"
            }
        }
    )


class ResetPasswordRequest(BaseModel):
    """Solicitud de reseteo de contraseña con token"""
    token: str = Field(..., description="Token de reseteo recibido por email", min_length=32)
    new_password: str = Field(
        ..., 
        description="Nueva contraseña",
        min_length=8,
        example="NuevaPass123!"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "abc123...xyz",
                "new_password": "NuevaPass123!"
            }
        }
    )


class LoginRequest(BaseModel):
    """Solicitud de login"""
    email: EmailStr = Field(..., description="Email del usuario", example="usuario@ejemplo.com")
    password: str = Field(..., description="Contraseña", example="********")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "usuario@ejemplo.com",
                "password": "MiPassword123"
            }
        }
    )


class RefreshTokenRequest(BaseModel):
    """Solicitud de refresh token"""
    refresh_token: str = Field(..., description="Refresh token para obtener nuevo access token")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "refresh_token": "eyJhbGc..."
            }
        }
    )


class RegisterRequest(BaseModel):
    """Solicitud de registro de usuario"""
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_]+$")
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=8)


class RegisterResponse(BaseModel):
    """Respuesta de registro exitoso"""
    success: bool
    message: str
    user_id: str
    email: str
    username: str
    requires_email_verification: bool = True
    

class LoginResponse(BaseModel):
    """Respuesta de login exitoso"""
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    user: Optional[Dict[str, Any]] = None
    # ✅ Campos adicionales para 2FA (autenticación de dos factores)
    requires_2fa: Optional[bool] = None
    message: Optional[str] = None
    user_id: Optional[str] = None
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIs...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
                "token_type": "bearer",
                "expires_in": 3600,
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "email": "usuario@ejemplo.com",
                    "username": "usuario",
                    "full_name": "Usuario Ejemplo",
                    "email_verified": True
                }
            }
        }
    )


class RefreshTokenResponse(BaseModel):
    """Respuesta de refresh token"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class ForgotPasswordResponse(BaseModel):
    """Respuesta de solicitud de recuperación"""
    message: str


class ResetPasswordResponse(BaseModel):
    """Respuesta de reseteo de contraseña"""
    message: str


class LogoutResponse(BaseModel):
    """Respuesta de logout"""
    message: str


class ChangePasswordRequest(BaseModel):
    """Solicitud de cambio de contraseña"""
    current_password: str
    new_password: str = Field(..., min_length=1)


class ChangePasswordResponse(BaseModel):
    """Respuesta de cambio de contraseña"""
    message: str
    sessions_closed: bool = True


class DebugCheckResponse(BaseModel):
    """Respuesta de diagnóstico"""
    supabase_configured: bool
    message: str


# ============================================
# MODELOS DE TOKEN
# ============================================

class TokenResponse(BaseModel):
    """Respuesta de token de Supabase"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    
    model_config = ConfigDict(from_attributes=True)


class UserInfoResponse(BaseModel):
    """Información del usuario obtenida del token"""
    sub: str
    email: Optional[str] = None
    email_verified: bool = False
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    username: Optional[str] = None
    roles: List[str] = []
    
    model_config = ConfigDict(from_attributes=True)


class PasswordResetToken(BaseModel):
    """Modelo para token de reseteo de contraseña (para almacenamiento local)"""
    token: str
    user_id: str
    email: str
    expires_at: float
    created_at: float = Field(default_factory=lambda: datetime.now().timestamp())
    
    @property
    def is_expired(self) -> bool:
        """Verifica si el token ha expirado"""
        from time import time
        return time() > self.expires_at
    
    @property
    def expires_at_datetime(self) -> datetime:
        """Convierte expires_at a datetime"""
        return datetime.fromtimestamp(self.expires_at)
    
    @property
    def created_at_datetime(self) -> datetime:
        """Convierte created_at a datetime"""
        return datetime.fromtimestamp(self.created_at)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "abc123def456",
                "user_id": "12345678-1234-1234-1234-123456789012",
                "email": "usuario@ejemplo.com",
                "expires_at": 1678901234.567,
                "created_at": 1678897634.567
            }
        }
    )


# ============================================
# MODELOS DE RESPUESTA ESTÁNDAR
# ============================================

class StandardResponse(BaseModel):
    """Respuesta estándar de la API"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "message": "Operación exitosa",
                "data": {"key": "value"},
                "timestamp": "2024-01-01T00:00:00"
            }
        }
    )


class ErrorResponse(BaseModel):
    """Respuesta de error de la API"""
    detail: str
    status_code: int
    path: Optional[str] = None
    method: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detail": "Token inválido o expirado",
                "status_code": 400,
                "path": "/api/users/profile",
                "method": "GET",
                "timestamp": "2024-01-01T00:00:00"
            }
        }
    )


class VerifyTokenResponse(BaseModel):
    """Respuesta de verificación de token"""
    valid: bool
    email: Optional[str] = None
    message: Optional[str] = None
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "valid": True,
                "email": "usuario@ejemplo.com",
                "message": "Token válido"
            }
        }
    )


# ============================================
# MODELOS DE HEALTH CHECK
# ============================================

class HealthResponse(BaseModel):
    """Respuesta del health check"""
    status: str
    service: str
    version: str
    timestamp: str
    checks: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "service": "Todo App API",
                "version": "2.0.0",
                "timestamp": "2024-01-01T00:00:00",
                "checks": {
                    "supabase": {
                        "configured": True,
                        "auth_available": True,
                        "storage_available": True
                    },
                    "smtp": {"configured": True}
                }
            }
        }
    )


# ============================================
# MODELOS DE PERFIL DE USUARIO
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
# MODELOS DE TAREAS
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
# MODELOS DE WEBAUTHN / PASSKEYS
# ============================================

class WebAuthnRegistrationBeginRequest(BaseModel):
    """Solicitud para iniciar registro de passkey"""
    device_name: Optional[str] = Field(None, max_length=100, description="Nombre del dispositivo")
    device_type: Optional[str] = Field(None, description="Tipo de dispositivo (mobile, desktop, etc)")


class WebAuthnRegistrationBeginResponse(BaseModel):
    """Respuesta para iniciar registro de passkey"""
    challenge: str
    user_id: str
    username: str
    display_name: str
    rp_id: str
    rp_name: str
    attestation: str = "none"
    pub_key_cred_params: List[Dict[str, Any]] = [
        {"type": "public-key", "alg": -7},   # ES256
        {"type": "public-key", "alg": -257}  # RS256
    ]


class WebAuthnRegistrationCompleteRequest(BaseModel):
    """Solicitud para completar registro de passkey"""
    credential_id: str
    client_data_json: str
    attestation_object: str
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    challenge: str


class WebAuthnRegistrationCompleteResponse(BaseModel):
    """Respuesta para completar registro de passkey"""
    success: bool
    credential_id: str
    message: str


class WebAuthnLoginBeginRequest(BaseModel):
    """Solicitud para iniciar login con passkey"""
    email: Optional[str] = Field(None, description="Email del usuario (opcional, para identificar usuario)")


class WebAuthnLoginBeginResponse(BaseModel):
    """Respuesta para iniciar login con passkey"""
    challenge: str
    rp_id: str
    allow_credentials: Optional[List[Dict[str, Any]]] = None
    timeout: int = 60000


class WebAuthnLoginCompleteRequest(BaseModel):
    """Solicitud para completar login con passkey"""
    credential_id: str
    client_data_json: str
    authenticator_data: str
    signature: str
    user_handle: Optional[str] = None
    challenge: str


class WebAuthnLoginCompleteResponse(BaseModel):
    """Respuesta para completar login con passkey"""
    success: bool
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    user: Optional[Dict[str, Any]] = None
    message: str


class WebAuthnCredentialResponse(BaseModel):
    """Modelo de credencial para respuesta"""
    id: str
    credential_id: str
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    created_at: datetime
    last_used: Optional[datetime] = None


class WebAuthnDeleteRequest(BaseModel):
    """Solicitud para eliminar una passkey"""
    credential_id: str


# ============================================
# MODELOS PARA OTP (CÓDIGO POR EMAIL)
# ============================================

class OtpSendRequest(BaseModel):
    """Solicitud para enviar código OTP por email"""
    email: EmailStr = Field(..., description="Email del usuario", example="usuario@ejemplo.com")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "usuario@ejemplo.com"
            }
        }
    )


class OtpSendResponse(BaseModel):
    """Respuesta al enviar código OTP"""
    message: str = Field(..., description="Mensaje de confirmación")
    expires_in: int = Field(..., description="Tiempo de expiración en segundos", example=900)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Código enviado exitosamente. Revisa tu correo electrónico.",
                "expires_in": 900
            }
        }
    )


class OtpVerifyRequest(BaseModel):
    """Solicitud para verificar código OTP"""
    email: EmailStr = Field(..., description="Email del usuario", example="usuario@ejemplo.com")
    token: str = Field(
        ..., 
        min_length=6, 
        max_length=6, 
        description="Código de 6 dígitos recibido por email",
        pattern="^[0-9]{6}$",
        example="123456"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "usuario@ejemplo.com",
                "token": "123456"
            }
        }
    )


class OtpVerifyResponse(BaseModel):
    """Respuesta al verificar código OTP (inicio de sesión exitoso)"""
    access_token: str = Field(..., description="Token de acceso JWT")
    refresh_token: str = Field(..., description="Token de refresco JWT")
    token_type: str = Field(default="bearer", description="Tipo de token")
    expires_in: int = Field(..., description="Tiempo de expiración del access token en segundos", example=3600)
    user: Dict[str, Any] = Field(..., description="Información del usuario autenticado")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIs...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
                "token_type": "bearer",
                "expires_in": 3600,
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "email": "usuario@ejemplo.com",
                    "username": "usuario",
                    "full_name": "Usuario Ejemplo",
                    "email_verified": True
                }
            }
        }
    )


# ============================================
# ✅ NUEVOS MODELOS PARA 2FA (TOTP)
# ============================================

class TwoFactorSetupRequest(BaseModel):
    """Solicitud para activar 2FA"""
    password: str = Field(..., description="Contraseña actual para verificar")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "password": "MiPassword123"
            }
        }
    )


class TwoFactorSetupResponse(BaseModel):
    """Respuesta al iniciar configuración 2FA"""
    secret: str = Field(..., description="Secreto TOTP")
    qr_code: str = Field(..., description="Código QR en formato SVG base64")
    provisioning_uri: str = Field(..., description="URI para aplicaciones de autenticación")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "secret": "JBSWY3DPEHPK3PXP",
                "qr_code": "data:image/svg+xml;base64,PHN2Zy...",
                "provisioning_uri": "otpauth://totp/TodoApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TodoApp"
            }
        }
    )


class TwoFactorEnableRequest(BaseModel):
    """Solicitud para confirmar activación de 2FA"""
    code: str = Field(
        ..., 
        min_length=6, 
        max_length=6, 
        description="Código TOTP de 6 dígitos",
        pattern="^[0-9]{6}$",
        example="123456"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "code": "123456"
            }
        }
    )


class TwoFactorEnableResponse(BaseModel):
    """Respuesta al activar 2FA"""
    message: str = Field(..., description="Mensaje de confirmación")
    recovery_codes: List[str] = Field(..., description="Códigos de respaldo (10 códigos)")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "2FA activado exitosamente",
                "recovery_codes": ["ABCD-1234", "EFGH-5678", "IJKL-9012"]
            }
        }
    )


class TwoFactorVerifyRequest(BaseModel):
    """Solicitud para verificar código 2FA durante login"""
    email: EmailStr = Field(..., description="Email del usuario")
    password: str = Field(..., description="Contraseña del usuario")
    code: str = Field(
        ..., 
        min_length=6, 
        max_length=6, 
        description="Código TOTP de 6 dígitos",
        pattern="^[0-9]{6}$",
        example="123456"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "usuario@ejemplo.com",
                "password": "MiPassword123",
                "code": "123456"
            }
        }
    )


class TwoFactorVerifyResponse(BaseModel):
    """Respuesta al verificar 2FA durante login"""
    access_token: str
    refresh_token: str
    expires_in: int
    user: Dict[str, Any]


class TwoFactorDisableRequest(BaseModel):
    """Solicitud para desactivar 2FA"""
    password: str = Field(..., description="Contraseña actual del usuario")
    code: str = Field(
        ..., 
        min_length=6, 
        max_length=6, 
        description="Código TOTP de 6 dígitos",
        pattern="^[0-9]{6}$",
        example="123456"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "password": "MiPassword123",
                "code": "123456"
            }
        }
    )


class TwoFactorStatusResponse(BaseModel):
    """Respuesta del estado de 2FA"""
    enabled: bool = Field(..., description="Indica si 2FA está activado")
    has_recovery_codes: bool = Field(default=False, description="Indica si tiene códigos de respaldo")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "enabled": True,
                "has_recovery_codes": True
            }
        }
    )


# ============================================
# EXPORTAR TODOS LOS MODELOS
# ============================================

__all__ = [
    # Autenticación
    "ForgotPasswordRequest",
    "ResetPasswordRequest",
    "LoginRequest",
    "RefreshTokenRequest",
    "RegisterRequest",
    "RegisterResponse",
    "LoginResponse",
    "RefreshTokenResponse",
    "ForgotPasswordResponse",
    "ResetPasswordResponse",
    "LogoutResponse",
    "ChangePasswordRequest",
    "ChangePasswordResponse",
    "DebugCheckResponse",
    # Token
    "TokenResponse",
    "UserInfoResponse",
    "PasswordResetToken",
    "VerifyTokenResponse",
    # Respuestas estándar
    "StandardResponse",
    "ErrorResponse",
    "HealthResponse",
    # Perfil de usuario
    "ProfileUpdateRequest",
    "ProfileResponse",
    "UserResponse",
    # Tareas
    "TaskBase",
    "TaskCreate",
    "TaskUpdate",
    "Task",
    "TaskStats",
    # WebAuthn / Passkeys
    "WebAuthnRegistrationBeginRequest",
    "WebAuthnRegistrationBeginResponse",
    "WebAuthnRegistrationCompleteRequest",
    "WebAuthnRegistrationCompleteResponse",
    "WebAuthnLoginBeginRequest",
    "WebAuthnLoginBeginResponse",
    "WebAuthnLoginCompleteRequest",
    "WebAuthnLoginCompleteResponse",
    "WebAuthnCredentialResponse",
    "WebAuthnDeleteRequest",
    # OTP
    "OtpSendRequest",
    "OtpSendResponse",
    "OtpVerifyRequest",
    "OtpVerifyResponse",
    # 2FA (TOTP)
    "TwoFactorSetupRequest",
    "TwoFactorSetupResponse",
    "TwoFactorEnableRequest",
    "TwoFactorEnableResponse",
    "TwoFactorVerifyRequest",
    "TwoFactorVerifyResponse",
    "TwoFactorDisableRequest",
    "TwoFactorStatusResponse",
]

# ============================================
# ✅ NUEVO: RESET DE CONTRASEÑA POR CÓDIGO OTP
# ============================================

class ResetPasswordOtpRequest(BaseModel):
    """Solicitud para reset de contraseña con código OTP"""
    email: EmailStr = Field(..., description="Email del usuario")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "usuario@ejemplo.com"
            }
        }
    )

class ResetPasswordOtpVerifyRequest(BaseModel):
    """Verifica código OTP y cambia contraseña"""
    email: EmailStr = Field(..., description="Email del usuario")
    code: str = Field(..., min_length=6, max_length=6, pattern="^[0-9]{6}$", description="Código de 6 dígitos")
    new_password: str = Field(..., min_length=8, description="Nueva contraseña")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "usuario@ejemplo.com",
                "code": "123456",
                "new_password": "NuevaPass123!"
            }
        }
    )

class ResetPasswordOtpResponse(BaseModel):
    """Respuesta del reset de contraseña"""
    message: str
    success: bool = True


# ============================================
# EXPORTAR TODOS LOS MODELOS
# ============================================

__all__ = [
    # Autenticación
    "ForgotPasswordRequest",
    "ResetPasswordRequest",
    "LoginRequest",
    "RefreshTokenRequest",
    "RegisterRequest",
    "RegisterResponse",
    "LoginResponse",
    "RefreshTokenResponse",
    "ForgotPasswordResponse",
    "ResetPasswordResponse",
    "LogoutResponse",
    "ChangePasswordRequest",
    "ChangePasswordResponse",
    "DebugCheckResponse",
    # Token
    "TokenResponse",
    "UserInfoResponse",
    "PasswordResetToken",
    "VerifyTokenResponse",
    # Respuestas estándar
    "StandardResponse",
    "ErrorResponse",
    "HealthResponse",
    # Perfil de usuario
    "ProfileUpdateRequest",
    "ProfileResponse",
    "UserResponse",
    # Tareas
    "TaskBase",
    "TaskCreate",
    "TaskUpdate",
    "Task",
    "TaskStats",
    # WebAuthn / Passkeys
    "WebAuthnRegistrationBeginRequest",
    "WebAuthnRegistrationBeginResponse",
    "WebAuthnRegistrationCompleteRequest",
    "WebAuthnRegistrationCompleteResponse",
    "WebAuthnLoginBeginRequest",
    "WebAuthnLoginBeginResponse",
    "WebAuthnLoginCompleteRequest",
    "WebAuthnLoginCompleteResponse",
    "WebAuthnCredentialResponse",
    "WebAuthnDeleteRequest",
    # OTP
    "OtpSendRequest",
    "OtpSendResponse",
    "OtpVerifyRequest",
    "OtpVerifyResponse",
    # 2FA (TOTP)
    "TwoFactorSetupRequest",
    "TwoFactorSetupResponse",
    "TwoFactorEnableRequest",
    "TwoFactorEnableResponse",
    "TwoFactorVerifyRequest",
    "TwoFactorVerifyResponse",
    "TwoFactorDisableRequest",
    "TwoFactorStatusResponse",
    # ✅ NUEVOS: Reset de contraseña por código OTP
    "ResetPasswordOtpRequest",
    "ResetPasswordOtpVerifyRequest",
    "ResetPasswordOtpResponse",
]