# 🚀 TodoApp API

API RESTful para aplicación de tareas con autenticación mediante Supabase Auth y soporte para passkeys (WebAuthn).

---

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Tecnologías](#-tecnologías)
- [Requisitos Previos](#-requisitos-previos)
- [Instalación y Configuración](#-instalación-y-configuración)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Variables de Entorno](#-variables-de-entorno)
- [Endpoints de la API](#-endpoints-de-la-api)
  - [Autenticación](#autenticación)
  - [Usuarios](#usuarios)
  - [Tareas](#tareas)
  - [Almacenamiento](#almacenamiento)
  - [WebAuthn / Passkeys](#webauthn--passkeys)
  - [Diagnóstico](#diagnóstico)
  - [Raíz](#raíz)
- [Modelos de Datos](#-modelos-de-datos)
- [Supabase Configuración](#-supabase-configuración)
- [WebAuthn / Passkeys](#-webauthn--passkeys-1)
- [Ejemplos de Uso](#-ejemplos-de-uso)
- [Códigos de Estado HTTP](#-códigos-de-estado-http)
- [Manejo de Errores](#-manejo-de-errores)
- [Diagnóstico](#-diagnóstico)
- [Desarrollador](#-desarrollador)

---

## ✨ Características

| Característica | Descripción |
|----------------|-------------|
| 🔐 **Autenticación con Supabase** | Registro, login, refresh tokens y recuperación de contraseña con verificación de email |
| 🔑 **Passkeys / WebAuthn** | Autenticación sin contraseña con biometría (Windows Hello, Touch ID, Face ID) |
| 📝 **Gestión de tareas** | CRUD completo con filtros por estado, prioridad, categoría y búsqueda |
| 👤 **Perfil de usuario** | Avatar, banner, nombre completo, biografía y configuración personal |
| 📁 **Almacenamiento en Supabase** | Subida y gestión de archivos en buckets públicos (avatars, banners) |
| 📧 **Emails personalizados** | Bienvenida y notificaciones con plantillas HTML personalizables |
| 🔍 **Diagnóstico integrado** | Endpoints para verificar configuración, tokens y conectividad con servicios |
| 🛡️ **Seguridad** | CORS configurable, validación de tokens JWT, sanitización de datos y rate limiting |
| 📊 **Estadísticas** | Métricas de tareas: totales, completadas, por prioridad, categoría y fechas |

---

## 🛠️ Tecnologías

| Tecnología | Versión | Descripción |
|------------|---------|-------------|
| **FastAPI** | 0.115.12 | Framework web moderno y rápido para construir APIs |
| **Uvicorn** | 0.34.0 | Servidor ASGI para ejecutar la API en producción |
| **Supabase** | 2.5.0 | Backend como servicio (Auth + Storage + Base de datos) |
| **WebAuthn** | 2.1.0 | Implementación de passkeys para autenticación sin contraseña |
| **Pydantic** | 2.12.5 | Validación de datos, serialización y modelos |
| **Pydantic Settings** | 2.8.1 | Manejo de variables de entorno con tipado |
| **PyJWT** | 2.10.1 | Creación y verificación de tokens JWT |
| **Cryptography** | 44.0.2 | Operaciones criptográficas seguras |
| **Jinja2** | 3.1.4 | Plantillas HTML para emails personalizados |
| **Loguru** | 0.7.3 | Logging avanzado con colores y rotación |
| **Python** | 3.14+ | Lenguaje de programación base |
| **Python-JOSE** | 3.3.0 | Manejo de JWT con algoritmos criptográficos |
| **Email-Validator** | 2.2.0 | Validación de emails con verificación de MX |
| **Python-Multipart** | 0.0.20 | Soporte para subida de archivos multipart |

---

## 📦 Requisitos Previos

Antes de comenzar, asegúrate de tener instalado:

- **Python 3.14 o superior** - [Descargar Python](https://www.python.org/downloads/)
- **Supabase** - Cuenta activa y proyecto creado
- **SMTP** - Servidor de correo (opcional, para emails personalizados)
- **Git** - Para clonar el repositorio (opcional)

---

## ⚙️ Instalación y Configuración

### 1. Clonar el repositorio
```bash
git clone https://github.com/jpablo981/todoapp-api.git
cd todoapp-api

2. Crear entorno virtual (recomendado)

# Windows
python -m venv venv
venv\Scripts\activate

# Linux / Mac
python3 -m venv venv
source venv/bin/activate

3. Instalar dependencias

pip install --upgrade pip
pip install -r requirements.txt

4. Configurar variables de entorno

Crea un archivo .env en la raíz del proyecto:

# ============================================
# SUPABASE CONFIGURATION
# ============================================
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_SERVICE_KEY=tu_service_role_key
SUPABASE_ANON_KEY=tu_anon_key

# ============================================
# STORAGE CONFIGURATION
# ============================================
SUPABASE_BUCKET_AVATARS=avatars
SUPABASE_BUCKET_BANNERS=banners
MAX_FILE_SIZE_MB=10
ALLOWED_IMAGE_TYPES=["image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"]

# ============================================
# SMTP EMAIL CONFIGURATION (opcional)
# ============================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu_email@gmail.com
SMTP_PASSWORD=tu_contraseña_app
SMTP_FROM=tu_email@gmail.com

# ============================================
# FRONTEND CONFIGURATION
# ============================================
FRONTEND_URL=http://localhost:5173

# ============================================
# TOKEN CONFIGURATION
# ============================================
TOKEN_EXPIRE_HOURS=1
JWT_ALGORITHM=HS256

# ============================================
# SECURITY CONFIGURATION
# ============================================
SECRET_KEY=tu_clave_secreta_segura_de_al_menos_32_caracteres

# ============================================
# LOGGING CONFIGURATION
# ============================================
LOG_LEVEL=INFO

# ============================================
# CORS CONFIGURATION
# ============================================
ALLOWED_ORIGINS=["http://localhost:5173", "http://localhost:8000"]

# ============================================
# API CONFIGURATION
# ============================================
API_TITLE=Todo App API
API_DESCRIPTION=API para la aplicación de tareas con Supabase Auth
API_VERSION=2.0.0

5. Configurar Supabase
Crear tablas en Supabase SQL Editor:

Tabla tasks:

CREATE TABLE tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    completed BOOLEAN DEFAULT FALSE,
    priority TEXT DEFAULT 'media',
    due_date TIMESTAMP WITH TIME ZONE,
    category TEXT,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Índices para mejor rendimiento
CREATE INDEX idx_tasks_user_id ON tasks(user_id);
CREATE INDEX idx_tasks_completed ON tasks(completed);
CREATE INDEX idx_tasks_priority ON tasks(priority);
CREATE INDEX idx_tasks_due_date ON tasks(due_date);

Tabla profiles (opcional - para biografía):

CREATE TABLE profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    bio TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

Tabla user_passkeys (para WebAuthn):

CREATE TABLE user_passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    device_name TEXT,
    device_type TEXT,
    last_used TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Índices
CREATE INDEX idx_passkeys_user_id ON user_passkeys(user_id);
CREATE INDEX idx_passkeys_credential_id ON user_passkeys(credential_id);

Crear buckets en Supabase Storage:

    1.Ve a Storage en tu proyecto Supabase

    Crea los buckets:

        . avatars (público)

        . banners (público)

    2.Configurar políticas de acceso:

    3.Configurar políticas de acceso:

-- Política para avatars (lectura pública)
CREATE POLICY "avatars_public_select" ON storage.objects
    FOR SELECT USING (bucket_id = 'avatars');

-- Política para subida con autenticación
CREATE POLICY "avatars_authenticated_insert" ON storage.objects
    FOR INSERT WITH CHECK (bucket_id = 'avatars' AND auth.role() = 'authenticated');

-- Política para banners (lectura pública)
CREATE POLICY "banners_public_select" ON storage.objects
    FOR SELECT USING (bucket_id = 'banners');

-- Política para subida con autenticación
CREATE POLICY "banners_authenticated_insert" ON storage.objects
    FOR INSERT WITH CHECK (bucket_id = 'banners' AND auth.role() = 'authenticated');

6. Iniciar la API

python run.py
# o
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

7. Verificar funcionamiento

Abre tu navegador en: http://localhost:8000/docs

📁 Estructura del Proyecto

TODO_APP_backend_fastapi/
│
├── app/                               # Código principal
│   ├── __init__.py
│   ├── main.py                        # Punto de entrada principal
│   ├── config.py                      # Configuración y variables de entorno
│   ├── models.py                      # Modelos Pydantic
│   ├── dependencies.py                # Dependencias de autenticación
│   │
│   ├── routers/                       # Endpoints de la API
│   │   ├── __init__.py
│   │   ├── auth.py                    # Autenticación (registro, login, etc.)
│   │   ├── users.py                   # Perfil de usuario
│   │   ├── tasks.py                   # Gestión de tareas
│   │   ├── storage.py                 # Almacenamiento de archivos
│   │   ├── webauthn.py                # Passkeys / WebAuthn
│   │   └── debug.py                   # Endpoints de diagnóstico
│   │
│   ├── services/                      # Servicios de negocio
│   │   ├── __init__.py
│   │   ├── supabase_auth_service.py   # Cliente Supabase Auth
│   │   ├── supabase_service.py        # Cliente Supabase Storage
│   │   ├── email_service.py           # Envío de emails
│   │   └── webauthn_service.py        # Lógica de WebAuthn
│   │
│   └── utils/                         # Utilidades
│       ├── __init__.py
│       ├── helpers.py                 # Funciones auxiliares
│       ├── token_manager.py           # Gestión de tokens
│       └── validators.py              # Validadores de datos
│
├── templates/                         # Plantillas HTML para emails
│   ├── welcome_email.html
│   └── password_changed.html
│
├── run.py                             # Script de inicio
├── requirements.txt                   # Dependencias del proyecto
├── .env                               # Variables de entorno (no subir a git)
├── .env.example                       # Ejemplo de variables de entorno
└── README.md                          # Este archivo

📊 Modelos de Datos
Task (Tarea)

{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440001",
  "title": "Completar documentación",
  "description": "Escribir el README de la API",
  "completed": false,
  "priority": "alta",
  "due_date": "2026-04-15T10:00:00Z",
  "category": "trabajo",
  "tags": ["documentación", "fastapi"],
  "created_at": "2026-04-01T08:00:00Z",
  "updated_at": "2026-04-01T08:00:00Z"
}

User Profile (Perfil de Usuario)

{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "email": "john@example.com",
  "username": "johndoe",
  "full_name": "John Doe",
  "bio": "Desarrollador fullstack apasionado por FastAPI",
  "avatar": "https://xyz.supabase.co/storage/v1/object/public/avatars/user123/avatar.jpg",
  "banner": "https://xyz.supabase.co/storage/v1/object/public/banners/user123/banner.jpg",
  "email_verified": true,
  "created_at": "2026-01-01T00:00:00Z",
  "last_sign_in_at": "2026-04-01T08:00:00Z"
}

Task Stats (Estadísticas)

{
  "total": 25,
  "completed": 15,
  "pending": 10,
  "completed_percentage": 60.0,
  "by_priority": {
    "baja": 5,
    "media": 12,
    "alta": 6,
    "urgente": 2
  },
  "by_category": {
    "trabajo": 10,
    "personal": 8,
    "estudio": 7
  },
  "due_today": 3,
  "overdue": 2
}

Login Response

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "email": "john@example.com",
    "username": "johndoe",
    "full_name": "John Doe",
    "email_verified": true
  }
}

Error Response

{
  "detail": "Credenciales inválidas",
  "status_code": 401,
  "path": "/api/auth/login",
  "method": "POST",
  "timestamp": "2026-04-01T08:00:00Z"
}

🗄️ Supabase Configuración
Políticas de Seguridad (RLS)
Tabla tasks

-- Habilitar RLS
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;

-- Política: Usuarios pueden ver sus propias tareas
CREATE POLICY "users_view_own_tasks" ON tasks
    FOR SELECT USING (auth.uid() = user_id);

-- Política: Usuarios pueden insertar sus propias tareas
CREATE POLICY "users_insert_own_tasks" ON tasks
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Política: Usuarios pueden actualizar sus propias tareas
CREATE POLICY "users_update_own_tasks" ON tasks
    FOR UPDATE USING (auth.uid() = user_id);

-- Política: Usuarios pueden eliminar sus propias tareas
CREATE POLICY "users_delete_own_tasks" ON tasks
    FOR DELETE USING (auth.uid() = user_id);
	
Tabla user_passkeys

-- Habilitar RLS
ALTER TABLE user_passkeys ENABLE ROW LEVEL SECURITY;

-- Política: Usuarios pueden ver sus propias passkeys
CREATE POLICY "users_view_own_passkeys" ON user_passkeys
    FOR SELECT USING (auth.uid() = user_id);

-- Política: Usuarios pueden insertar sus propias passkeys
CREATE POLICY "users_insert_own_passkeys" ON user_passkeys
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Política: Usuarios pueden eliminar sus propias passkeys
CREATE POLICY "users_delete_own_passkeys" ON user_passkeys
    FOR DELETE USING (auth.uid() = user_id);

Buckets de Storage
Bucket	Uso	Permisos	                                             Tamaño Máximo
avatars	Imágenes de perfil	Público lectura, autenticado escritura	      2 MB
banners	Imágenes de portada	Público lectura, autenticado escritura	      5 MB

Formatos permitidos:

    JPEG/JPG

    PNG

    GIF

    WebP

🔑 WebAuthn / Passkeys
¿Qué son las passkeys?

Las passkeys son un estándar moderno de autenticación que permite iniciar sesión sin contraseña usando:

    Biometría (huella dactilar, reconocimiento facial)

    PIN del dispositivo

    Llaves de seguridad físicas (YubiKey, etc.)

📝 Ejemplos de Uso
1. Registro de usuario

curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "full_name": "John Doe",
    "password": "SecurePass123!"
  }'
  
 Respuesta:
 
 {
  "success": true,
  "message": "Usuario registrado exitosamente. Revisa tu email para confirmar tu cuenta.",
  "user_id": "550e8400-e29b-41d4-a716-446655440001",
  "email": "john@example.com",
  "username": "johndoe",
  "requires_email_verification": true
}

2. Inicio de sesión

curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'

Respuesta:

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "email": "john@example.com",
    "username": "johndoe",
    "full_name": "John Doe",
    "email_verified": true
  }
}

3. Crear tarea

curl -X POST http://localhost:8000/api/tasks \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Completar documentación",
    "description": "Escribir el README de la API",
    "priority": "alta",
    "category": "trabajo",
    "tags": ["documentación", "fastapi"]
  }'
  
4. Listar tareas con filtros

curl -X GET "http://localhost:8000/api/tasks?completed=false&priority=alta&limit=10" \
  -H "Authorization: Bearer TU_ACCESS_TOKEN"
  
5. Subir avatar

curl -X POST http://localhost:8000/api/users/avatar \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -F "file=@/ruta/a/avatar.jpg"
  
6. Registrar passkey (inicio)

curl -X POST http://localhost:8000/api/webauthn/register/begin \
  -H "Authorization: Bearer TU_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "iPhone 15 Pro",
    "device_type": "mobile"
  }'

7. Iniciar login con passkey

curl -X POST http://localhost:8000/api/webauthn/login/begin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }'

8. Obtener estadísticas de tareas

curl -X GET http://localhost:8000/api/tasks/stats/summary \
  -H "Authorization: Bearer TU_ACCESS_TOKEN"
  
9. Health check completo

curl http://localhost:8000/api/health

Respuesta:

{
  "status": "healthy",
  "service": "Todo App API",
  "version": "2.0.0",
  "timestamp": "2026-04-01T08:00:00Z",
  "cors": {
    "allowed_origins": ["http://localhost:5173", "http://localhost:8000"],
    "credentials_allowed": true
  },
  "checks": {
    "supabase": {
      "configured": true,
      "auth_available": true,
      "storage_available": true
    },
    "webauthn": {
      "configured": true,
      "rp_id": "localhost",
      "origin": "http://localhost:5173"
    },
    "smtp": {
      "configured": true
    }
  }
}

10. Diagnóstico de autenticación

curl -X GET http://localhost:8000/debug/auth \
  -H "Authorization: Bearer TU_ACCESS_TOKEN"
  
🧪 Manejo de Errores

La API utiliza un formato consistente para todos los errores:

{
  "detail": "Mensaje descriptivo del error",
  "status_code": 401,
  "path": "/api/auth/login",
  "method": "POST",
  "timestamp": "2026-04-01T08:00:00Z"
}

🧪 Diagnóstico
Endpoints útiles para debug

1. Verificar configuración actual:

curl http://localhost:8000/debug/config

2. Verificar token actual:

curl -H "Authorization: Bearer TU_TOKEN" http://localhost:8000/debug/token

3. Verificar estado de Supabase:

curl -H "Authorization: Bearer TU_TOKEN" http://localhost:8000/api/users/debug/supabase-status

4. Verificar conectividad con servicios externos:

curl http://localhost:8000/debug/health-check

5. Verificar estado de WebAuthn:

curl http://localhost:8000/api/webauthn/health

📝 Notas Importantes
Seguridad

    .Nunca subas el archivo .env a control de versiones
	
    .La SECRET_KEY debe ser única y segura (mínimo 32 caracteres)

    .Usa contraseñas de aplicación para Gmail, no tu contraseña personal

    .En producción, configura HTTPS obligatorio
	
Rendimiento

    .El modo desarrollo (--reload) es solo para desarrollo local

    .En producción usa workers: uvicorn app.main:app --workers 4

    .Considera usar Redis para almacenar sesiones en producción

WebAuthn

    .Las passkeys requieren HTTPS en producción (excepto localhost)

    .El RP ID debe coincidir con el dominio de tu aplicación

    .Los desafíos expiran después de 5 minutos
	
👨‍💻 Desarrollador

José Pablo Miranda Quintanilla

    📧 Email: pabloquintanilla988@gmail.com

    🐙 GitHub: https://github.com/JosePablo1996
	
📄 Licencia

Este proyecto es de uso privado. Todos los derechos reservados.

 Agradecimientos

    .FastAPI - Por su excelente framework y documentación

    .Supabase - Por su increíble backend como servicio open-source

    .WebAuthn - Por hacer posible la autenticación sin contraseña

    .Python Community - Por las bibliotecas que hacen esto posible
	
📚 Recursos Adicionales

    .FastAPI Documentation

    .Supabase Documentation

    .WebAuthn Guide

    .JWT.io

    .Python Official Site
	
Última actualización: Abril 2026
Versión: 2.0.0
Estado: ✅ Producción Ready

