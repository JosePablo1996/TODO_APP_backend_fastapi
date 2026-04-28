# app/services/email_service.py
"""
Servicio de email personalizado
Nota: La recuperación de contraseña ahora la maneja Supabase Auth automáticamente
Este servicio solo se usa para emails personalizados como bienvenida y notificaciones
"""
import smtplib
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
        
        self._configured = all([
            self.smtp_host, 
            self.smtp_port, 
            self.smtp_user, 
            self.smtp_password, 
            self.smtp_from
        ])
        
        if not self._configured:
            logger.warning("⚠️ Configuración SMTP incompleta. Los emails personalizados no se enviarán.")
            logger.warning("   Los emails de recuperación los maneja Supabase automáticamente.")
    
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
    
    def _send_email(self, to_email: str, subject: str, html_content: str) -> bool:
        """
        Método interno para enviar email
        """
        if not self._configured:
            logger.error("❌ SMTP no configurado. No se puede enviar el email.")
            return False
        
        try:
            msg = MIMEMultipart()
            msg["From"] = self.smtp_from
            msg["To"] = to_email
            msg["Subject"] = subject
            
            msg.attach(MIMEText(html_content, "html"))
            
            server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
            server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"✅ Email enviado a {to_email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"❌ Error de autenticación SMTP: {str(e)}")
            logger.error("   Verifica tu usuario y contraseña de Gmail (debe ser una contraseña de aplicación)")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"❌ Error SMTP: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"❌ Error inesperado enviando email: {str(e)}")
            return False
    
    # ============================================
    # ✅ NUEVO MÉTODO GENÉRICO PARA ENVIAR EMAILS
    # ============================================
    
    async def send_email(self, to_email: str, subject: str, body: str, html_body: str = None) -> bool:
        """
        Método genérico para enviar emails con contenido HTML personalizado
        
        Args:
            to_email: Email del destinatario
            subject: Asunto del email
            body: Versión en texto plano del email (fallback)
            html_body: Versión HTML del email (opcional, si no se proporciona usa body)
        """
        if not self._configured:
            logger.warning(f"⚠️ SMTP no configurado - no se envía email a {to_email}")
            return False
        
        try:
            logger.info(f"📧 Enviando email a {to_email}: {subject}")
            
            # Si no se proporciona HTML, usar el texto plano envuelto en HTML básico
            if not html_body:
                html_body = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>{subject}</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .content {{ background: #f9fafb; padding: 20px; border-radius: 8px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="content">
                            <p>{body.replace(chr(10), '<br>')}</p>
                        </div>
                    </div>
                </body>
                </html>
                """
            
            return self._send_email(
                to_email=to_email,
                subject=subject,
                html_content=html_body
            )
            
        except Exception as e:
            logger.error(f"❌ Error enviando email genérico: {str(e)}")
            return False
    
    # ============================================
    # MÉTODOS EXISTENTES (sin cambios)
    # ============================================
    
    async def send_welcome_email(self, to_email: str, nombre: str = None) -> bool:
        """
        Envía email de bienvenida cuando un usuario se registra
        
        Args:
            to_email: Email del destinatario
            nombre: Nombre del usuario para personalizar el saludo
        """
        if not self._configured:
            logger.warning("⚠️ SMTP no configurado - no se envía email de bienvenida")
            return False
        
        try:
            logger.info(f"📧 Enviando email de bienvenida a {to_email}")
            
            nombre_usuario = nombre or to_email.split('@')[0]
            
            # Intentar usar plantilla personalizada
            template = self._get_template("welcome_email.html")
            
            if template:
                html_content = template.render(
                    nombre=nombre_usuario,
                    frontend_url=settings.FRONTEND_URL
                )
            else:
                # Template por defecto
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                        .header {{ background: #4F46E5; color: white; padding: 20px; text-align: center; }}
                        .content {{ padding: 20px; }}
                        .button {{ display: inline-block; background: #4F46E5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; }}
                        .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🎉 ¡Bienvenido a TodoApp!</h1>
                        </div>
                        <div class="content">
                            <h2>Hola {nombre_usuario},</h2>
                            <p>¡Tu cuenta ha sido creada exitosamente!</p>
                            <p>Ya puedes empezar a organizar tus tareas y ser más productivo.</p>
                            <p style="text-align: center;">
                                <a href="{settings.FRONTEND_URL}/login" class="button">Iniciar sesión</a>
                            </p>
                            <p>Si no creaste esta cuenta, por favor ignora este email.</p>
                        </div>
                        <div class="footer">
                            <p>TodoApp - Organiza tus tareas de manera eficiente</p>
                        </div>
                    </div>
                </body>
                </html>
                """
            
            return self._send_email(
                to_email=to_email,
                subject="🎉 Bienvenido a TodoApp",
                html_content=html_content
            )
            
        except Exception as e:
            logger.error(f"❌ Error enviando email de bienvenida: {str(e)}")
            return False
    
    async def send_password_changed_notification(self, to_email: str, nombre: str = None, detalles: dict = None) -> bool:
        """
        Envía notificación de que la contraseña fue cambiada exitosamente
        
        Args:
            to_email: Email del destinatario
            nombre: Nombre del usuario
            detalles: Detalles adicionales (fecha, dispositivo, ubicación)
        """
        if not self._configured:
            logger.warning("⚠️ SMTP no configurado - no se envía notificación de cambio de contraseña")
            return False
        
        try:
            logger.info(f"📧 Enviando notificación de cambio de contraseña a {to_email}")
            
            nombre_usuario = nombre or to_email.split('@')[0]
            fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            fecha_corta = datetime.datetime.now().strftime("%d/%m/%Y")
            hora = datetime.datetime.now().strftime("%H:%M:%S")
            
            # Obtener detalles adicionales o usar valores por defecto
            dispositivo = detalles.get('dispositivo', 'Navegador web') if detalles else 'Navegador web'
            ubicacion = detalles.get('ubicacion', 'Ubicación desconocida') if detalles else 'Ubicación desconocida'
            ip = detalles.get('ip', 'IP no registrada') if detalles else 'IP no registrada'
            
            # Intentar usar plantilla personalizada
            template = self._get_template("password_changed.html")
            
            if template:
                html_content = template.render(
                    nombre=nombre_usuario,
                    frontend_url=settings.FRONTEND_URL,
                    fecha=fecha,
                    fecha_corta=fecha_corta,
                    hora=hora,
                    dispositivo=dispositivo,
                    ubicacion=ubicacion,
                    ip=ip
                )
            else:
                # Template por defecto mejorado
                html_content = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Contraseña Actualizada - TodoApp</title>
                    <style>
                        body {{
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                            line-height: 1.6;
                            color: #1f2937;
                            background-color: #f3f4f6;
                            margin: 0;
                            padding: 0;
                        }}
                        .container {{
                            max-width: 560px;
                            margin: 40px auto;
                            background: #ffffff;
                            border-radius: 16px;
                            overflow: hidden;
                            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
                        }}
                        .header {{
                            background: linear-gradient(135deg, #10B981 0%, #059669 100%);
                            color: white;
                            padding: 32px 24px;
                            text-align: center;
                        }}
                        .header h1 {{
                            margin: 0;
                            font-size: 24px;
                            font-weight: 600;
                        }}
                        .header p {{
                            margin: 8px 0 0;
                            opacity: 0.9;
                            font-size: 14px;
                        }}
                        .content {{
                            padding: 32px 24px;
                        }}
                        .info-box {{
                            background: #f0fdf4;
                            border-left: 4px solid #10B981;
                            padding: 16px;
                            margin: 20px 0;
                            border-radius: 8px;
                        }}
                        .warning-box {{
                            background: #fef3c7;
                            border-left: 4px solid #f59e0b;
                            padding: 16px;
                            margin: 20px 0;
                            border-radius: 8px;
                        }}
                        .detail-row {{
                            display: flex;
                            justify-content: space-between;
                            padding: 8px 0;
                            border-bottom: 1px solid #e5e7eb;
                        }}
                        .detail-label {{
                            font-weight: 600;
                            color: #4b5563;
                        }}
                        .detail-value {{
                            color: #1f2937;
                            font-family: monospace;
                        }}
                        .button {{
                            display: inline-block;
                            background: linear-gradient(135deg, #10B981 0%, #059669 100%);
                            color: white;
                            padding: 12px 28px;
                            text-decoration: none;
                            border-radius: 8px;
                            font-weight: 500;
                            margin: 16px 0;
                            transition: transform 0.2s, box-shadow 0.2s;
                        }}
                        .button:hover {{
                            transform: translateY(-1px);
                            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
                        }}
                        .footer {{
                            text-align: center;
                            padding: 24px;
                            font-size: 12px;
                            color: #9ca3af;
                            border-top: 1px solid #e5e7eb;
                            background: #f9fafb;
                        }}
                        .footer a {{
                            color: #10B981;
                            text-decoration: none;
                        }}
                        .success-icon {{
                            font-size: 48px;
                            margin-bottom: 16px;
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <div class="success-icon">🔐</div>
                            <h1>Contraseña Actualizada</h1>
                            <p>{fecha_corta} • {hora}</p>
                        </div>
                        <div class="content">
                            <h2>Hola {nombre_usuario},</h2>
                            <p>Tu contraseña ha sido cambiada exitosamente.</p>
                            
                            <div class="info-box">
                                <strong>📋 Detalles del cambio:</strong>
                                <div class="detail-row">
                                    <span class="detail-label">Fecha y hora:</span>
                                    <span class="detail-value">{fecha}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Dispositivo:</span>
                                    <span class="detail-value">{dispositivo}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Ubicación:</span>
                                    <span class="detail-value">{ubicacion}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Dirección IP:</span>
                                    <span class="detail-value">{ip}</span>
                                </div>
                            </div>
                            
                            <div class="warning-box">
                                <strong>⚠️ ¿No realizaste este cambio?</strong>
                                <p style="margin: 8px 0 0 0;">Si no solicitaste este cambio, alguien más podría haber accedido a tu cuenta. Por favor:</p>
                                <ul style="margin: 8px 0 0 20px;">
                                    <li>Restablece tu contraseña inmediatamente</li>
                                    <li>Contacta a nuestro equipo de soporte</li>
                                    <li>Revisa tu actividad reciente en la cuenta</li>
                                </ul>
                            </div>
                            
                            <div style="text-align: center;">
                                <a href="{settings.FRONTEND_URL}/login" class="button">Ir a TodoApp</a>
                            </div>
                            
                            <p style="font-size: 14px; color: #6b7280; margin-top: 24px;">
                                Si fuiste tú quien realizó este cambio, no necesitas hacer nada más. Tu cuenta está segura.
                            </p>
                        </div>
                        <div class="footer">
                            <p><strong>TodoApp</strong> - Protegiendo tu cuenta</p>
                            <p>
                                <a href="{settings.FRONTEND_URL}/soporte">Soporte</a> • 
                                <a href="{settings.FRONTEND_URL}/security">Centro de Seguridad</a>
                            </p>
                            <p>© 2026 TodoApp. Todos los derechos reservados.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
            
            return self._send_email(
                to_email=to_email,
                subject="🔐 Tu contraseña ha sido actualizada - TodoApp",
                html_content=html_content
            )
            
        except Exception as e:
            logger.error(f"❌ Error enviando notificación de cambio de contraseña: {str(e)}")
            return False
    
    async def send_test_email(self, to_email: str) -> bool:
        """
        Envía un email de prueba para verificar la configuración SMTP
        
        Args:
            to_email: Email de destino para la prueba
        """
        logger.info("📧 Enviando email de prueba...")
        
        fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #4F46E5; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .success {{ background: #D1FAE5; color: #065F46; padding: 15px; border-radius: 5px; }}
                .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📧 Email de Prueba</h1>
                </div>
                <div class="content">
                    <div class="success">
                        <p>✅ ¡Configuración SMTP funcionando correctamente!</p>
                    </div>
                    <p>Este es un email de prueba enviado desde TodoApp.</p>
                    <p>Si recibiste este email, significa que la configuración de correo está correcta.</p>
                    <p><strong>Fecha y hora:</strong> {fecha}</p>
                </div>
                <div class="footer">
                    <p>TodoApp - Sistema de Tareas</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return self._send_email(
            to_email=to_email,
            subject="📧 TodoApp - Email de Prueba",
            html_content=html_content
        )
    
    async def send_password_recovery_email(self, to_email: str, recovery_link: str) -> bool:
        """
        Envía un email personalizado para recuperación de contraseña (alternativo al de Supabase)
        
        Args:
            to_email: Email del destinatario
            recovery_link: Enlace de recuperación personalizado
        """
        if not self._configured:
            logger.warning("⚠️ SMTP no configurado - no se envía email de recuperación")
            return False
        
        try:
            logger.info(f"📧 Enviando email de recuperación a {to_email}")
            
            fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: #F59E0B; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; }}
                    .button {{ display: inline-block; background: #F59E0B; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; }}
                    .warning {{ background: #FEF3C7; border-left: 4px solid #F59E0B; padding: 15px; margin: 20px 0; }}
                    .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔑 Recuperación de Contraseña</h1>
                    </div>
                    <div class="content">
                        <p>Hemos recibido una solicitud para restablecer tu contraseña.</p>
                        
                        <p style="text-align: center;">
                            <a href="{recovery_link}" class="button">Restablecer Contraseña</a>
                        </p>
                        
                        <div class="warning">
                            <p><strong>⚠️ Este enlace expirará en 1 hora</strong></p>
                            <p>Si no solicitaste este cambio, ignora este email y tu contraseña permanecerá igual.</p>
                        </div>
                        
                        <p><strong>📅 Fecha de solicitud:</strong> {fecha}</p>
                    </div>
                    <div class="footer">
                        <p>TodoApp - Seguridad de tu cuenta</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            return self._send_email(
                to_email=to_email,
                subject="🔑 Recuperación de Contraseña - TodoApp",
                html_content=html_content
            )
            
        except Exception as e:
            logger.error(f"❌ Error enviando email de recuperación: {str(e)}")
            return False
    
    def is_configured(self) -> bool:
        """Verifica si el servicio está configurado correctamente"""
        return self._configured


# Instancia única
email_service = EmailService()