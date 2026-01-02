#!/bin/bash
#
# Privacy Server - Create User Script
# Versión: 2.0
# 
# Crea usuario en: Linux, Email, Nextcloud, Matrix
# Copia archivo VPN a Nextcloud del usuario
# Envía email con todas las credenciales
#

set -euo pipefail

#==========================================
# COLORES Y FUNCIONES
#==========================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

#==========================================
# VERIFICACIONES
#==========================================
[[ $EUID -ne 0 ]] && log_error "Este script debe ejecutarse como root"

CONFIG_FILE="/etc/privacy_server/config.env"
[[ ! -f "$CONFIG_FILE" ]] && log_error "Config file no encontrado. Ejecuta privacy_server_installer.sh primero"

source "$CONFIG_FILE"

CRED_DIR="/etc/privacy_server/credentials"
mkdir -p "$CRED_DIR/users"
chmod 700 "$CRED_DIR"

#==========================================
# BANNER
#==========================================
clear
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           PRIVACY SERVER - CREAR NUEVO USUARIO            ║
║                                                           ║
║  Se creará el usuario en:                                 ║
║  • Sistema Linux                                          ║
║  • Buzón de correo (IMAP/SMTP)                            ║
║  • Nextcloud                                              ║
║  • Matrix Synapse                                         ║
║                                                           ║
║  Se enviará email con todas las credenciales              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo ""

#==========================================
# SOLICITAR DATOS DEL USUARIO
#==========================================
while true; do
    read -p "Nombre de usuario (solo letras minúsculas y números): " USERNAME
    USERNAME=$(echo "$USERNAME" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
    
    if [[ -z "$USERNAME" ]]; then
        log_error "El nombre de usuario no puede estar vacío"
    fi
    
    # Verificar si el usuario ya existe
    if id "$USERNAME" &>/dev/null; then
        log_warn "El usuario $USERNAME ya existe en el sistema"
        read -p "¿Deseas continuar de todas formas? (y/n): " continue_existing
        [[ "$continue_existing" != "y" ]] && continue
    fi
    
    # Validar longitud
    if [[ ${#USERNAME} -lt 3 ]]; then
        log_warn "El nombre de usuario debe tener al menos 3 caracteres"
        continue
    fi
    
    break
done

read -p "Email personal del usuario (para recibir credenciales): " USER_EMAIL
[[ -z "$USER_EMAIL" ]] && log_error "El email es obligatorio"

# Validar formato de email básico
if ! echo "$USER_EMAIL" | grep -qE '^[^@]+@[^@]+\.[^@]+$'; then
    log_error "Formato de email inválido"
fi

#==========================================
# GENERAR CONTRASEÑA
#==========================================
USER_PASSWORD=$(openssl rand -base64 16 | tr -d '/+=' | cut -c1-16)

log_info ""
log_info "Contraseña generada: ${GREEN}$USER_PASSWORD${NC}"
log_info ""
read -p "¿Aceptar esta contraseña? (y/n) [y]: " accept_password
accept_password=${accept_password:-y}

if [[ "$accept_password" != "y" ]]; then
    read -sp "Introduce tu propia contraseña: " USER_PASSWORD
    echo ""
    [[ -z "$USER_PASSWORD" ]] && log_error "La contraseña no puede estar vacía"
fi

#==========================================
# CONFIRMACIÓN
#==========================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}RESUMEN${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo "Usuario:           $USERNAME"
echo "Email personal:    $USER_EMAIL"
echo "Email servidor:    $USERNAME@$DOMAIN"
echo "Contraseña:        $USER_PASSWORD"
echo "Matrix ID:         @$USERNAME:$DOMAIN"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""
read -p "¿Crear este usuario? (y/n): " confirm
[[ "$confirm" != "y" ]] && log_error "Creación cancelada por el usuario"

#==========================================
# CREAR USUARIO LINUX
#==========================================
log_info "Creando usuario Linux..."

if id "$USERNAME" &>/dev/null; then
    log_warn "Usuario Linux ya existe, actualizando contraseña..."
    echo "$USERNAME:$USER_PASSWORD" | chpasswd
else
    # Crear usuario con home directory
    useradd -m -s /bin/bash "$USERNAME"
    echo "$USERNAME:$USER_PASSWORD" | chpasswd
    
    # Añadir a grupo mail
    usermod -a -G mail "$USERNAME"
fi

log_info "✓ Usuario Linux creado/actualizado"

#==========================================
# CONFIGURAR BUZÓN DE CORREO
#==========================================
log_info "Configurando buzón de correo..."

# Crear buzón si no existe
if [[ ! -f "/var/mail/$USERNAME" ]]; then
    touch "/var/mail/$USERNAME"
    chown "$USERNAME:mail" "/var/mail/$USERNAME"
    chmod 660 "/var/mail/$USERNAME"
fi

# Crear estructura de directorios de mail
USER_HOME=$(eval echo "~$USERNAME")
mkdir -p "$USER_HOME/mail"
chown -R "$USERNAME:$USERNAME" "$USER_HOME/mail"
chmod 700 "$USER_HOME/mail"

# Crear subdirectorios de mail (Dovecot los creará automáticamente, pero los pre-creamos)
for folder in .Sent .Trash .Drafts .Spam; do
    mkdir -p "$USER_HOME/mail/$folder"
    chown "$USERNAME:$USERNAME" "$USER_HOME/mail/$folder"
done

log_info "✓ Buzón de correo configurado"

#==========================================
# CREAR USUARIO NEXTCLOUD
#==========================================
log_info "Creando usuario en Nextcloud..."

# Verificar que Nextcloud esté instalado
if [[ ! -f /var/www/nextcloud/occ ]]; then
    log_warn "Nextcloud no encontrado, saltando..."
else
    # Verificar si usuario ya existe
    if sudo -u apache php /var/www/nextcloud/occ user:info "$USERNAME" &>/dev/null; then
        log_warn "Usuario Nextcloud ya existe, reseteando contraseña..."
        export OC_PASS="$USER_PASSWORD"
        sudo -u apache php /var/www/nextcloud/occ user:resetpassword --password-from-env "$USERNAME"
    else
        # Crear usuario
        export OC_PASS="$USER_PASSWORD"
        sudo -u apache php /var/www/nextcloud/occ user:add \
            --password-from-env \
            --display-name="$USERNAME" \
            --group="users" \
            "$USERNAME" 2>/dev/null
    fi
    
    # Configurar email del usuario
    sudo -u apache php /var/www/nextcloud/occ user:setting "$USERNAME" settings email "$USER_EMAIL"
    
    log_info "✓ Usuario Nextcloud creado"
    
    # Copiar archivo VPN a la carpeta del usuario en Nextcloud
    log_info "Copiando archivo de configuración VPN a Nextcloud..."
    
    VPN_FILE="/etc/openvpn/client/${DOMAIN%%.*}.ovpn"
    if [[ -f "$VPN_FILE" ]]; then
        USER_DATA_DIR="/home/data/$USERNAME/files"
        
        # Esperar a que Nextcloud cree el directorio del usuario
        sleep 2
        
        if [[ ! -d "$USER_DATA_DIR" ]]; then
            # Forzar creación del directorio
            mkdir -p "$USER_DATA_DIR"
            chown -R apache:apache "/home/data/$USERNAME"
        fi
        
        # Copiar archivo VPN
        cp "$VPN_FILE" "$USER_DATA_DIR/VPN_Config.ovpn"
        chown apache:apache "$USER_DATA_DIR/VPN_Config.ovpn"
        chmod 644 "$USER_DATA_DIR/VPN_Config.ovpn"
        
        # Actualizar cache de Nextcloud
        sudo -u apache php /var/www/nextcloud/occ files:scan "$USERNAME" >/dev/null 2>&1
        
        log_info "✓ Archivo VPN copiado a Nextcloud del usuario"
    else
        log_warn "Archivo VPN no encontrado en $VPN_FILE"
    fi
fi

#==========================================
# CREAR USUARIO MATRIX
#==========================================
log_info "Creando usuario en Matrix..."

if ! command -v register_new_matrix_user &>/dev/null; then
    log_warn "Matrix Synapse no encontrado, saltando..."
else
    # Verificar si el usuario ya existe (intentar crear y capturar error)
    if register_new_matrix_user \
        -u "$USERNAME" \
        -p "$USER_PASSWORD" \
        --no-admin \
        -c /etc/synapse/homeserver.yaml 2>&1 | grep -q "User ID already taken"; then
        log_warn "Usuario Matrix ya existe"
    else
        log_info "✓ Usuario Matrix creado"
    fi
fi

#==========================================
# GUARDAR CREDENCIALES
#==========================================
log_info "Guardando credenciales..."

CRED_FILE="$CRED_DIR/users/${USERNAME}.txt"

cat > "$CRED_FILE" << EOCRED
========================================
CREDENCIALES - $USERNAME
========================================
Generado: $(date)

USUARIO: $USERNAME
CONTRASEÑA: $USER_PASSWORD
EMAIL PERSONAL: $USER_EMAIL

========================================
ACCESO AL SISTEMA
========================================
Usuario Linux: $USERNAME
Contraseña: $USER_PASSWORD

========================================
EMAIL
========================================
Email: $USERNAME@$DOMAIN

Configuración IMAP:
  Servidor: mail.$DOMAIN
  Puerto: 993
  Seguridad: SSL/TLS
  Usuario: $USERNAME
  Contraseña: $USER_PASSWORD

Configuración SMTP:
  Servidor: mail.$DOMAIN
  Puerto: 587
  Seguridad: STARTTLS
  Usuario: $USERNAME
  Contraseña: $USER_PASSWORD

========================================
NEXTCLOUD
========================================
URL: https://cloud.$DOMAIN
Usuario: $USERNAME
Contraseña: $USER_PASSWORD

Archivo VPN disponible en Nextcloud:
  VPN_Config.ovpn

========================================
MATRIX (ELEMENT)
========================================
Homeserver: https://$DOMAIN:8448
Usuario: @$USERNAME:$DOMAIN
Contraseña: $USER_PASSWORD

Cliente recomendado:
  https://element.io

========================================
VPN (OpenVPN)
========================================
Archivo de configuración:
  Descargar VPN_Config.ovpn desde Nextcloud

Uso:
  1. Descargar archivo desde Nextcloud
  2. Importar en cliente OpenVPN
  3. Usuario: $USERNAME
  4. Contraseña: $USER_PASSWORD

========================================
EOCRED

chmod 600 "$CRED_FILE"

log_info "✓ Credenciales guardadas en $CRED_FILE"

#==========================================
# ENVIAR EMAIL CON CREDENCIALES
#==========================================
log_info "Enviando email con credenciales a $USER_EMAIL..."

(
echo "From: postmaster@$DOMAIN"
echo "To: $USER_EMAIL"
echo "Subject: Bienvenido a $DOMAIN - Tus Credenciales"
echo "Content-Type: text/html; charset=UTF-8"
echo ""
cat << EOHTML
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .content { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2c3e50; margin-top: 30px; border-left: 4px solid #3498db; padding-left: 15px; }
        .creds { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 15px 0; font-family: monospace; }
        .password { background: #ffe6e6; padding: 10px; border-left: 4px solid #e74c3c; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        td { padding: 10px; border: 1px solid #ddd; }
        .highlight { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .warning { background: #ffe6e6; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #e74c3c; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 2px solid #ecf0f1; color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
<div class="container">
<div class="content">
    <h1>🎉 Bienvenido a $DOMAIN</h1>
    
    <p>Hola <strong>$USERNAME</strong>,</p>
    
    <p>Tu cuenta ha sido creada exitosamente en nuestro servidor de privacidad. Tienes acceso a todos los siguientes servicios:</p>
    
    <div class="warning">
        <strong>⚠️ IMPORTANTE:</strong> Este email contiene tus contraseñas. Guárdalo de forma segura y elimínalo después de configurar tus dispositivos.
    </div>
    
    <h2>🔐 Credenciales de Acceso</h2>
    <div class="password">
        <strong>Usuario:</strong> $USERNAME<br>
        <strong>Contraseña:</strong> <span style="font-size: 18px; font-family: monospace;">$USER_PASSWORD</span>
    </div>
    
    <h2>📧 Email</h2>
    <p>Tu dirección de email: <strong>$USERNAME@$DOMAIN</strong></p>
    
    <table>
        <tr style="background: #ecf0f1;">
            <td><strong>Protocolo</strong></td>
            <td><strong>Servidor</strong></td>
            <td><strong>Puerto</strong></td>
            <td><strong>Seguridad</strong></td>
        </tr>
        <tr>
            <td>IMAP (Recibir)</td>
            <td>mail.$DOMAIN</td>
            <td>993</td>
            <td>SSL/TLS</td>
        </tr>
        <tr>
            <td>SMTP (Enviar)</td>
            <td>mail.$DOMAIN</td>
            <td>587</td>
            <td>STARTTLS</td>
        </tr>
    </table>
    
    <div class="highlight">
        <strong>💡 Clientes de email recomendados:</strong><br>
        • Thunderbird (Windows, Mac, Linux)<br>
        • Apple Mail (Mac, iOS)<br>
        • K-9 Mail (Android)<br>
        • Outlook (Windows, Mac)
    </div>
    
    <h2>☁️ Nextcloud (Almacenamiento en la Nube)</h2>
    <p><strong>URL:</strong> <a href="https://cloud.$DOMAIN">https://cloud.$DOMAIN</a></p>
    
    <div class="creds">
        Usuario: $USERNAME<br>
        Contraseña: $USER_PASSWORD
    </div>
    
    <p><strong>En Nextcloud encontrarás:</strong></p>
    <ul>
        <li>📁 Tu espacio de almacenamiento personal</li>
        <li>🔐 Archivo <code>VPN_Config.ovpn</code> para conectarte a la VPN</li>
        <li>📅 Calendario (instala la app Calendar)</li>
        <li>👥 Contactos (instala la app Contacts)</li>
    </ul>
    
    <h2>💬 Matrix (Mensajería Segura)</h2>
    <p><strong>Cliente recomendado:</strong> <a href="https://element.io">Element</a> (disponible para todas las plataformas)</p>
    
    <table>
        <tr style="background: #ecf0f1;">
            <td><strong>Configuración</strong></td>
            <td><strong>Valor</strong></td>
        </tr>
        <tr>
            <td>Homeserver</td>
            <td>https://$DOMAIN:8448</td>
        </tr>
        <tr>
            <td>Usuario Matrix</td>
            <td>@$USERNAME:$DOMAIN</td>
        </tr>
        <tr>
            <td>Contraseña</td>
            <td>$USER_PASSWORD</td>
        </tr>
    </table>
    
    <h2>🔒 VPN (OpenVPN)</h2>
    <p><strong>Cómo conectarte a la VPN:</strong></p>
    <ol>
        <li>Accede a Nextcloud: <a href="https://cloud.$DOMAIN">https://cloud.$DOMAIN</a></li>
        <li>Descarga el archivo <code>VPN_Config.ovpn</code></li>
        <li>Instala el cliente OpenVPN:
            <ul>
                <li>Windows/Mac: <a href="https://openvpn.net/client/">OpenVPN Connect</a></li>
                <li>Linux: <code>sudo apt install openvpn</code> o <code>dnf install openvpn</code></li>
                <li>Android/iOS: OpenVPN Connect (desde Play Store / App Store)</li>
            </ul>
        </li>
        <li>Importa el archivo <code>VPN_Config.ovpn</code></li>
        <li>Conecta usando:
            <div class="creds">
                Usuario: $USERNAME<br>
                Contraseña: $USER_PASSWORD
            </div>
        </li>
    </ol>
    
    <h2>📱 Resumen Rápido</h2>
    <table>
        <tr style="background: #ecf0f1;">
            <td><strong>Servicio</strong></td>
            <td><strong>URL / Servidor</strong></td>
        </tr>
        <tr>
            <td>Email</td>
            <td>$USERNAME@$DOMAIN</td>
        </tr>
        <tr>
            <td>Nextcloud</td>
            <td><a href="https://cloud.$DOMAIN">https://cloud.$DOMAIN</a></td>
        </tr>
        <tr>
            <td>Matrix</td>
            <td>@$USERNAME:$DOMAIN (https://$DOMAIN:8448)</td>
        </tr>
        <tr>
            <td>VPN</td>
            <td>Archivo en Nextcloud</td>
        </tr>
    </table>
    
    <div class="highlight">
        <strong>🆘 ¿Necesitas ayuda?</strong><br>
        Contacta al administrador: <a href="mailto:$ADMIN_EMAIL">$ADMIN_EMAIL</a>
    </div>
    
    <div class="footer">
        <p><strong>Seguridad:</strong></p>
        <ul>
            <li>Cambia tu contraseña después del primer acceso</li>
            <li>Habilita autenticación de dos factores (2FA) en Nextcloud</li>
            <li>No compartas tus credenciales</li>
            <li>Usa siempre la VPN cuando te conectes desde redes públicas</li>
        </ul>
        <p style="margin-top: 20px;">Cuenta creada: $(date)</p>
    </div>
</div>
</div>
</body>
</html>
EOHTML
) | /usr/sbin/sendmail -t

if [[ $? -eq 0 ]]; then
    log_info "✓ Email enviado correctamente a $USER_EMAIL"
else
    log_warn "Hubo un problema enviando el email"
    log_warn "Las credenciales están guardadas en: $CRED_FILE"
fi

#==========================================
# RESUMEN FINAL
#==========================================
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}║          ✅  USUARIO CREADO EXITOSAMENTE                   ║${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Usuario:           $USERNAME"
echo "Email servidor:    $USERNAME@$DOMAIN"
echo "Email personal:    $USER_EMAIL"
echo "Contraseña:        $USER_PASSWORD"
echo "Matrix ID:         @$USERNAME:$DOMAIN"
echo ""
echo "Servicios configurados:"
echo "  ✅ Sistema Linux"
echo "  ✅ Buzón de correo (IMAP/SMTP)"
echo "  ✅ Nextcloud (con archivo VPN)"
echo "  ✅ Matrix Synapse"
echo ""
echo "Credenciales guardadas en:"
echo "  $CRED_FILE"
echo ""
echo "Email con instrucciones enviado a:"
echo "  $USER_EMAIL"
echo ""

exit 0
