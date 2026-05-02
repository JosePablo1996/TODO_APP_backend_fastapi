# app/services/email_service.py
"""
Servicio de email personalizado.
✅ Soporta SendGrid API REST (puerto 443/HTTPS) para Render.
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
    # MÉTODOS EXISTENTES (sin cambios)
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
    
    def is_configured(self) -> bool:
        return self._configured


# Instancia única
email_service = EmailService()