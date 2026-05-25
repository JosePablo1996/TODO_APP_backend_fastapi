# app/services/email_service.py
"""
Servicio de email personalizado.
✅ Soporta SendGrid API REST (puerto 443/HTTPS) para Render.
✅ FASE 2: Advertencias de expiración de contraseña.
"""
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Template
from app.config import settings
import logging
from pathlib import Path
import datetime

logger = logging.getLogger(__name__)


class EmailService:
    """Servicio para envío de correos electrónicos personalizados"""
    
    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.smtp_from = settings.SMTP_FROM
        
        # ✅ Detectar si es SendGrid (usar API REST en lugar de SMTP)
        self._is_sendgrid = "sendgrid" in self.smtp_host.lower()
        self._sendgrid_api_key = self.smtp_password if self._is_sendgrid else None
        
        self._configured = all([
            self.smtp_host, 
            self.smtp_port, 
            self.smtp_user, 
            self.smtp_password, 
            self.smtp_from
        ])
        
        if self._is_sendgrid:
            logger.info("✅ SendGrid detectado - usando API REST (HTTPS)")
        elif self._configured:
            logger.info(f"✅ SMTP configurado: {self.smtp_host}:{self.smtp_port}")
        
        if not self._configured:
            logger.warning("⚠️ Configuración SMTP incompleta. Los emails personalizados no se enviarán.")
    
    def _get_template(self, template_name: str) -> Template:
        """Carga una plantilla HTML del directorio templates"""
        template_path = Path(f"templates/{template_name}")
        
        try:
            if template_path.exists():
                with open(template_path, "r", encoding="utf-8") as f:
                    template_content = f.read()
                return Template(template_content)
            else:
                logger.debug(f"Plantilla {template_name} no encontrada, usando template por defecto")
                return None
        except Exception as e:
            logger.error(f"Error cargando plantilla {template_name}: {str(e)}")
            return None
    
    async def _send_email_http(self, to_email: str, subject: str, html_content: str) -> bool:
        """
        ✅ NUEVO: Envía email usando la API REST de SendGrid (HTTPS).
        Funciona en Render sin restricciones de SMTP.
        """
        if not self._sendgrid_api_key:
            logger.error("❌ API Key de SendGrid no configurada")
            return False
        
        try:
            url = "https://api.sendgrid.com/v3/mail/send"
            
            headers = {
                "Authorization": f"Bearer {self._sendgrid_api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "personalizations": [
                    {
                        "to": [{"email": to_email}],
                        "subject": subject
                    }
                ],
                "from": {"email": self.smtp_from, "name": "TodoApp"},
                "content": [
                    {
                        "type": "text/html",
                        "value": html_content
                    }
                ]
            }
            
            logger.info(f"📧 Enviando email vía SendGrid API a {to_email}: {subject}")
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, headers=headers, json=payload)
                
                if response.status_code in [200, 201, 202]:
                    logger.info(f"✅ Email enviado a {to_email} (SendGrid API)")
                    return True
                else:
                    logger.error(f"❌ SendGrid API error: {response.status_code} - {response.text}")
                    return False
                    
        except httpx.TimeoutException:
            logger.error(f"⏰ Timeout enviando email vía SendGrid API a {to_email}")
            return False
        except Exception as e:
            logger.error(f"❌ Error enviando email vía SendGrid API: {str(e)}")
            return False
    
    def _send_email_smtp(self, to_email: str, subject: str, html_content: str) -> bool:
        """
        Método interno para enviar email vía SMTP.
        Solo funciona en desarrollo local (Render bloquea SMTP).
        """
        import smtplib
        
        if not self._configured:
            logger.error("❌ SMTP no configurado. No se puede enviar el email.")
            return False
        
        try:
            msg = MIMEMultipart()
            msg["From"] = self.smtp_from
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(html_content, "html"))
            
            logger.info(f"📧 Conectando a {self.smtp_host}:{self.smtp_port}...")
            
            if self.smtp_port == 465:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=30)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
                server.starttls()
            
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"✅ Email enviado a {to_email} (SMTP)")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error SMTP: {str(e)}")
            return False
    
    async def send_email(self, to_email: str, subject: str, body: str, html_body: str = None) -> bool:
        """
        Método genérico para enviar emails.
        ✅ Usa SendGrid API si está configurado, sino usa SMTP.
        """
        if not self._configured:
            logger.warning(f"⚠️ SMTP no configurado - no se envía email a {to_email}")
            return False
        
        try:
            logger.info(f"📧 Enviando email a {to_email}: {subject}")
            
            if not html_body:
                html_body = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>{subject}</title>
                </head>
                <body>
                    <div style="max-width:600px; margin:0 auto; padding:20px; font-family:Arial;">
                        <p>{body.replace(chr(10), '<br>')}</p>
                    </div>
                </body>
                </html>
                """
            
            # ✅ Usar API REST de SendGrid si está disponible
            if self._is_sendgrid:
                return await self._send_email_http(to_email, subject, html_body)
            else:
                return self._send_email_smtp(to_email, subject, html_body)
            
        except Exception as e:
            logger.error(f"❌ Error enviando email: {str(e)}")
            return False
    
    # ============================================
    # MÉTODOS EXISTENTES
    # ============================================
    
    async def send_welcome_email(self, to_email: str, nombre: str = None) -> bool:
        if not self._configured:
            return False
        
        try:
            nombre_usuario = nombre or to_email.split('@')[0]
            template = self._get_template("welcome_email.html")
            
            if template:
                html_content = template.render(nombre=nombre_usuario, frontend_url=settings.FRONTEND_URL)
            else:
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head><meta charset="UTF-8"></head>
                <body style="font-family:Arial; text-align:center;">
                    <h1>🎉 ¡Bienvenido a TodoApp!</h1>
                    <h2>Hola {nombre_usuario},</h2>
                    <p>¡Tu cuenta ha sido creada exitosamente!</p>
                    <a href="{settings.FRONTEND_URL}/login" style="background:#10B981; color:white; padding:12px 24px; text-decoration:none; border-radius:8px;">Iniciar sesión</a>
                </body>
                </html>
                """
            
            return await self.send_email(to_email=to_email, subject="🎉 Bienvenido a TodoApp", body="", html_body=html_content)
            
        except Exception as e:
            logger.error(f"❌ Error enviando email de bienvenida: {str(e)}")
            return False
    
    async def send_password_changed_notification(self, to_email: str, nombre: str = None, detalles: dict = None) -> bool:
        if not self._configured:
            return False
        
        try:
            nombre_usuario = nombre or to_email.split('@')[0]
            fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body style="font-family:Arial; text-align:center;">
                <h1>🔐 Contraseña Actualizada</h1>
                <h2>Hola {nombre_usuario},</h2>
                <p>Tu contraseña ha sido cambiada exitosamente.</p>
                <p>📅 {fecha}</p>
                <a href="{settings.FRONTEND_URL}/login" style="background:#10B981; color:white; padding:12px 24px; text-decoration:none; border-radius:8px;">Ir a TodoApp</a>
                <p style="color:#666; font-size:12px;">Si no realizaste este cambio, contacta soporte.</p>
            </body>
            </html>
            """
            
            return await self.send_email(to_email=to_email, subject="🔐 Contraseña actualizada - TodoApp", body="", html_body=html_content)
            
        except Exception as e:
            logger.error(f"❌ Error enviando notificación: {str(e)}")
            return False
    
    async def send_test_email(self, to_email: str) -> bool:
        fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="font-family:Arial; text-align:center;">
            <h1>📧 Email de Prueba</h1>
            <p>✅ Configuración funcionando correctamente!</p>
            <p>{fecha}</p>
        </body>
        </html>
        """
        return await self.send_email(to_email=to_email, subject="📧 TodoApp - Email de Prueba", body="", html_body=html_content)
    
    async def send_password_recovery_email(self, to_email: str, recovery_link: str) -> bool:
        if not self._configured:
            return False
        
        try:
            fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8"></head>
            <body style="font-family:Arial; text-align:center;">
                <h1>🔑 Recuperación de Contraseña</h1>
                <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
                <a href="{recovery_link}" style="background:#10B981; color:white; padding:12px 24px; text-decoration:none; border-radius:8px;">Restablecer Contraseña</a>
                <p>⚠️ Este enlace expirará en 1 hora</p>
                <p>📅 {fecha}</p>
            </body>
            </html>
            """
            return await self.send_email(to_email=to_email, subject="🔑 Recuperación de Contraseña - TodoApp", body="", html_body=html_content)
        except Exception as e:
            logger.error(f"❌ Error enviando email de recuperación: {str(e)}")
            return False
    
    # ============================================
    # ✅ NUEVO FASE 2: ADVERTENCIA DE EXPIRACIÓN DE CONTRASEÑA
    # ============================================
    
    async def send_password_expiry_warning(self, to_email: str, name: str, days_remaining: int) -> bool:
        """
        Envía advertencia de expiración de contraseña por email.
        ✅ FASE 2: Notificaciones automáticas cuando la contraseña está por expirar.
        
        Args:
            to_email: Email del destinatario
            name: Nombre del usuario
            days_remaining: Días restantes para la expiración
        
        Returns:
            True si el email se envió correctamente, False en caso contrario
        """
        if not self._configured:
            logger.warning(f"⚠️ Email no configurado - no se puede enviar advertencia a {to_email}")
            return False
        
        if not settings.should_send_password_expiry_warnings:
            logger.info(f"📧 Advertencias de expiración desactivadas - no se envía a {to_email}")
            return False
        
        try:
            subject = f"⚠️ Tu contraseña expirará en {days_remaining} días - TodoApp"
            
            # Determinar el mensaje según los días restantes
            if days_remaining <= 3:
                urgency_class = "urgent"
                urgency_color = "#DC2626"
                urgency_message = "¡ATENCIÓN! Tu contraseña expirará muy pronto."
            elif days_remaining <= 7:
                urgency_class = "warning"
                urgency_color = "#F59E0B"
                urgency_message = f"Tu contraseña expirará en {days_remaining} días."
            else:
                urgency_class = "info"
                urgency_color = "#3B82F6"
                urgency_message = f"Recuerda que tu contraseña expirará en {days_remaining} días."
            
            html_content = f"""
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Advertencia de expiración - TodoApp</title>
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                        background: #f4f4f4;
                        padding: 20px;
                        margin: 0;
                    }}
                    .container {{
                        max-width: 560px;
                        margin: 0 auto;
                        background: white;
                        border-radius: 24px;
                        overflow: hidden;
                        box-shadow: 0 20px 35px -10px rgba(0,0,0,0.1);
                    }}
                    .header {{
                        background: linear-gradient(135deg, #F59E0B 0%, #DC2626 100%);
                        padding: 32px 24px;
                        text-align: center;
                    }}
                    .header h1 {{
                        color: white;
                        margin: 0;
                        font-size: 28px;
                        font-weight: 700;
                    }}
                    .header p {{
                        color: rgba(255,255,255,0.85);
                        margin: 8px 0 0;
                        font-size: 14px;
                    }}
                    .content {{
                        padding: 32px 28px;
                        text-align: center;
                    }}
                    .greeting {{
                        font-size: 18px;
                        color: #333;
                        margin-bottom: 16px;
                    }}
                    .days-box {{
                        background: linear-gradient(135deg, #{'DC2626' if days_remaining <= 3 else 'F59E0B' if days_remaining <= 7 else '3B82F6'}20, #{'DC2626' if days_remaining <= 3 else 'F59E0B' if days_remaining <= 7 else '3B82F6'}10);
                        border-radius: 20px;
                        padding: 24px;
                        margin: 24px 0;
                        border: 2px solid {urgency_color};
                    }}
                    .days-number {{
                        font-size: 64px;
                        font-weight: bold;
                        color: {urgency_color};
                        line-height: 1;
                    }}
                    .days-label {{
                        font-size: 16px;
                        color: #666;
                        margin-top: 8px;
                    }}
                    .message {{
                        font-size: 16px;
                        color: {urgency_color};
                        font-weight: 600;
                        margin-top: 16px;
                    }}
                    .button {{
                        display: inline-block;
                        background: {urgency_color};
                        color: white;
                        padding: 14px 28px;
                        border-radius: 30px;
                        text-decoration: none;
                        font-weight: 600;
                        margin: 24px 0 16px;
                        transition: background 0.3s ease;
                    }}
                    .button:hover {{
                        background: {'#B91C1C' if days_remaining <= 3 else '#D97706' if days_remaining <= 7 else '#2563EB'};
                    }}
                    .info-box {{
                        background: #f8f9fa;
                        border-radius: 12px;
                        padding: 16px;
                        margin: 20px 0;
                        text-align: left;
                    }}
                    .info-item {{
                        margin-bottom: 8px;
                        font-size: 13px;
                        color: #555;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }}
                    .info-icon {{
                        font-size: 18px;
                    }}
                    .footer {{
                        background: #f8f9fa;
                        padding: 20px;
                        text-align: center;
                        color: #999;
                        font-size: 12px;
                        border-top: 1px solid #eee;
                    }}
                    @media only screen and (max-width: 600px) {{
                        .days-number {{ font-size: 48px; }}
                        .content {{ padding: 24px 20px; }}
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>TodoApp</h1>
                        <p>Advertencia de expiración</p>
                    </div>
                    <div class="content">
                        <div class="greeting">
                            Hola <strong>{name}</strong>,
                        </div>
                        
                        <div class="days-box">
                            <div class="days-number">{days_remaining}</div>
                            <div class="days-label">día{'s' if days_remaining != 1 else ''} restante{'s' if days_remaining != 1 else ''}</div>
                            <div class="message">{urgency_message}</div>
                        </div>
                        
                        <p style="color: #555; line-height: 1.6;">
                            Te recomendamos cambiar tu contraseña lo antes posible para mantener la seguridad de tu cuenta.
                        </p>
                        
                        <a href="{settings.FRONTEND_URL}/settings" class="button">
                            🔐 Cambiar contraseña ahora
                        </a>
                        
                        <div class="info-box">
                            <div class="info-item">
                                <span class="info-icon">🔒</span>
                                <span>Las contraseñas expiran automáticamente por seguridad</span>
                            </div>
                            <div class="info-item">
                                <span class="info-icon">⏰</span>
                                <span>Después de la expiración, deberás cambiar tu contraseña para acceder</span>
                            </div>
                            <div class="info-item">
                                <span class="info-icon">🛡️</span>
                                <span>Recibirás otra notificación cuando expire</span>
                            </div>
                        </div>
                        
                        <p style="color: #888; font-size: 13px; margin-top: 20px;">
                            Si no deseas cambiar tu contraseña ahora, ignora este mensaje.
                            Tu cuenta seguirá funcionando hasta la fecha de expiración.
                        </p>
                    </div>
                    <div class="footer">
                        <p>TodoApp - Organiza tu día, alcanza tus metas</p>
                        <p style="margin-top: 8px;">© 2026 TodoApp. Todos los derechos reservados.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
TodoApp - Advertencia de expiración de contraseña

Hola {name},

⚠️ Tu contraseña expirará en {days_remaining} día{'s' if days_remaining != 1 else ''}.

{urgency_message}

Para mantener la seguridad de tu cuenta, te recomendamos cambiar tu contraseña lo antes posible.

¿Cómo cambiar tu contraseña?
1. Inicia sesión en TodoApp
2. Ve a Configuración > Seguridad
3. Selecciona "Cambiar contraseña"

Si no deseas cambiar tu contraseña ahora, ignora este mensaje.
Tu cuenta seguirá funcionando hasta la fecha de expiración.

---
TodoApp - Organiza tu día, alcanza tus metas
"""
            
            return await self.send_email(
                to_email=to_email,
                subject=subject,
                body=text_content,
                html_body=html_content
            )
            
        except Exception as e:
            logger.error(f"❌ Error enviando advertencia de expiración a {to_email}: {str(e)}")
            return False
    
    def is_configured(self) -> bool:
        return self._configured


# Instancia única
email_service = EmailService()