#!/bin/bash
#
# Privacy Server - Delete User Script
# Versión: 1.0
# 
# Elimina usuario de: Linux, Email, Nextcloud, Matrix
# Opción de hacer backup antes de eliminar
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

#==========================================
# BANNER
#==========================================
clear
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           PRIVACY SERVER - ELIMINAR USUARIO               ║
║                                                           ║
║  Se eliminará el usuario de:                              ║
║  • Sistema Linux                                          ║
║  • Buzón de correo (IMAP/SMTP)                            ║
║  • Nextcloud                                              ║
║  • Matrix Synapse                                         ║
║                                                           ║
║  ⚠️  ESTA OPERACIÓN NO SE PUEDE DESHACER                  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo ""
sleep 1

#==========================================
# LISTAR USUARIOS DISPONIBLES
#==========================================
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo -e "${BLUE}USUARIOS EN EL SISTEMA${NC}"
echo -e "${BLUE}═══════════════════════════════════════${NC}"
echo ""

# Obtener usuarios del sistema (UID >= 1000, excluyendo nobody)
SYSTEM_USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)

if [[ -z "$SYSTEM_USERS" ]]; then
    log_error "No hay usuarios del sistema para eliminar"
fi

echo "Usuarios disponibles:"
echo "$SYSTEM_USERS" | nl
echo ""

#==========================================
# SOLICITAR USUARIO A ELIMINAR
#==========================================
set +e  # Desactiva exit on error

USERNAME=""
while [[ -z "$USERNAME" ]]; do
    read -p "Nombre del usuario a eliminar: " input_username
    USERNAME=$(echo "$input_username" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')
    
    if [[ -z "$USERNAME" ]]; then
        log_warn "El nombre de usuario no puede estar vacío"
        continue
    fi
    
    # Verificar si el usuario existe
    if ! id "$USERNAME" >/dev/null 2>&1; then
        log_warn "El usuario $USERNAME NO existe en el sistema"
        read -p "¿Deseas intentar con otro usuario? (y/n): " retry
        if [[ "$retry" == "y" ]]; then
            USERNAME=""
            continue
        else
            log_error "Operación cancelada"
        fi
    fi
    
    # Verificar que no sea root ni usuarios del sistema
    USER_UID=$(id -u "$USERNAME")
    if [[ $USER_UID -lt 1000 ]]; then
        log_error "No se puede eliminar un usuario del sistema (UID < 1000)"
    fi
done

set -e

#==========================================
# VERIFICAR QUÉ SERVICIOS TIENE EL USUARIO
#==========================================
echo ""
log_info "Verificando servicios del usuario $USERNAME..."
echo ""

SERVICES_FOUND=()

# Linux
if id "$USERNAME" &>/dev/null; then
    SERVICES_FOUND+=("Sistema Linux")
fi

# Email
if [[ -f "/var/mail/$USERNAME" ]]; then
    SERVICES_FOUND+=("Buzón de correo")
fi

# Nextcloud
if [[ -f /var/www/nextcloud/occ ]]; then
    if sudo -u apache php /var/www/nextcloud/occ user:info "$USERNAME" &>/dev/null; then
        SERVICES_FOUND+=("Nextcloud")
    fi
fi

# Matrix
if command -v sqlite3 &>/dev/null && [[ -f /etc/synapse/homeserver.db ]]; then
    MATRIX_USER=$(sqlite3 /etc/synapse/homeserver.db "SELECT name FROM users WHERE name='@$USERNAME:$DOMAIN';" 2>/dev/null || echo "")
    if [[ -n "$MATRIX_USER" ]]; then
        SERVICES_FOUND+=("Matrix Synapse")
    fi
fi

if [[ ${#SERVICES_FOUND[@]} -eq 0 ]]; then
    log_error "El usuario $USERNAME no tiene servicios configurados"
fi

echo "Servicios encontrados para $USERNAME:"
for service in "${SERVICES_FOUND[@]}"; do
    echo "  ✓ $service"
done
echo ""

#==========================================
# PREGUNTAR POR BACKUP
#==========================================
BACKUP_DIR="/backup/deleted_users/$(date +%Y%m%d_%H%M%S)_${USERNAME}"

echo -e "${YELLOW}═══════════════════════════════════════${NC}"
echo -e "${YELLOW}BACKUP ANTES DE ELIMINAR${NC}"
echo -e "${YELLOW}═══════════════════════════════════════${NC}"
echo ""
read -p "¿Deseas hacer backup de los datos del usuario antes de eliminar? (y/n) [y]: " do_backup
do_backup=${do_backup:-y}

#==========================================
# CONFIRMACIÓN FINAL
#==========================================
echo ""
echo -e "${RED}═══════════════════════════════════════${NC}"
echo -e "${RED}⚠️  CONFIRMACIÓN FINAL${NC}"
echo -e "${RED}═══════════════════════════════════════${NC}"
echo ""
echo "Se eliminará el usuario: ${RED}$USERNAME${NC}"
echo "Servicios afectados:"
for service in "${SERVICES_FOUND[@]}"; do
    echo "  • $service"
done
echo ""
if [[ "$do_backup" == "y" ]]; then
    echo "Se creará backup en: $BACKUP_DIR"
else
    echo -e "${RED}NO se creará backup${NC}"
fi
echo ""
echo -e "${RED}Esta operación NO SE PUEDE DESHACER${NC}"
echo ""
read -p "Escribe 'ELIMINAR' para confirmar: " confirmation

if [[ "$confirmation" != "ELIMINAR" ]]; then
    log_error "Operación cancelada por el usuario"
fi

#==========================================
# CREAR BACKUP SI SE SOLICITÓ
#==========================================
if [[ "$do_backup" == "y" ]]; then
    log_info "Creando backup..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup home directory
    if [[ -d "/home/$USERNAME" ]]; then
        log_info "  → Backup de /home/$USERNAME"
        tar -czf "$BACKUP_DIR/home.tar.gz" -C /home "$USERNAME" 2>/dev/null || log_warn "Error en backup de home"
    fi
    
    # Backup mailbox
    if [[ -f "/var/mail/$USERNAME" ]]; then
        log_info "  → Backup de buzón de correo"
        cp "/var/mail/$USERNAME" "$BACKUP_DIR/mailbox" 2>/dev/null || log_warn "Error en backup de mailbox"
    fi
    
    # Backup Nextcloud data
    if [[ -d "/home/data/$USERNAME" ]]; then
        log_info "  → Backup de datos Nextcloud"
        tar -czf "$BACKUP_DIR/nextcloud_data.tar.gz" -C /home/data "$USERNAME" 2>/dev/null || log_warn "Error en backup de Nextcloud"
    fi
    
    # Backup credenciales
    if [[ -f "$CRED_DIR/users/${USERNAME}.txt" ]]; then
        log_info "  → Backup de credenciales"
        cp "$CRED_DIR/users/${USERNAME}.txt" "$BACKUP_DIR/credentials.txt" 2>/dev/null || log_warn "Error en backup de credenciales"
    fi
    
    # Crear resumen del backup
    cat > "$BACKUP_DIR/BACKUP_INFO.txt" << EOINFO
========================================
BACKUP USUARIO ELIMINADO
========================================
Usuario: $USERNAME
Fecha backup: $(date)
Fecha eliminación: $(date)
Dominio: $DOMAIN

Servicios que tenía:
$(printf '  - %s\n' "${SERVICES_FOUND[@]}")

Contenido del backup:
$(ls -lh "$BACKUP_DIR" | tail -n +2)

========================================
EOINFO
    
    chmod -R 600 "$BACKUP_DIR"
    log_info "✓ Backup completado en $BACKUP_DIR"
    echo ""
fi

#==========================================
# ELIMINAR DE NEXTCLOUD
#==========================================
if [[ -f /var/www/nextcloud/occ ]]; then
    if sudo -u apache php /var/www/nextcloud/occ user:info "$USERNAME" &>/dev/null; then
        log_info "Eliminando usuario de Nextcloud..."
        
        # Eliminar usuario (esto elimina automáticamente sus datos)
        sudo -u apache php /var/www/nextcloud/occ user:delete "$USERNAME" &>/dev/null
        
        log_info "✓ Usuario eliminado de Nextcloud"
    fi
fi

#==========================================
# ELIMINAR DE MATRIX
#==========================================
if command -v sqlite3 &>/dev/null && [[ -f /etc/synapse/homeserver.db ]]; then
    MATRIX_USER=$(sqlite3 /etc/synapse/homeserver.db "SELECT name FROM users WHERE name='@$USERNAME:$DOMAIN';" 2>/dev/null || echo "")
    
    if [[ -n "$MATRIX_USER" ]]; then
        log_info "Eliminando usuario de Matrix Synapse..."
        
        # Matrix no tiene comando directo para eliminar usuarios, hay que hacerlo via API o SQL
        # Usamos SQL directamente (más seguro sería usar la API admin, pero requiere token)
        
        # Desactivar usuario (método más seguro que eliminación directa)
        curl -X POST "https://localhost:8448/_synapse/admin/v1/deactivate/@$USERNAME:$DOMAIN" \
            -H "Authorization: Bearer $MASTER_PASSWORD" \
            -H "Content-Type: application/json" \
            -d '{"erase": true}' &>/dev/null || {
            
            log_warn "No se pudo desactivar via API, intentando via SQL..."
            
            # Backup de la base de datos antes de modificar
            cp /etc/synapse/homeserver.db /etc/synapse/homeserver.db.bak.$(date +%s)
            
            # Eliminar usuario de la base de datos
            sqlite3 /etc/synapse/homeserver.db << EOSQL
DELETE FROM users WHERE name='@$USERNAME:$DOMAIN';
DELETE FROM access_tokens WHERE user_id='@$USERNAME:$DOMAIN';
DELETE FROM user_filters WHERE user_id='@$USERNAME:$DOMAIN';
DELETE FROM profiles WHERE user_id='@$USERNAME:$DOMAIN';
EOSQL
        }
        
        log_info "✓ Usuario eliminado/desactivado en Matrix"
    fi
fi

#==========================================
# ELIMINAR BUZÓN DE CORREO
#==========================================
if [[ -f "/var/mail/$USERNAME" ]]; then
    log_info "Eliminando buzón de correo..."
    rm -f "/var/mail/$USERNAME"
    log_info "✓ Buzón de correo eliminado"
fi

# Eliminar directorio de mail en home
USER_HOME=$(eval echo "~$USERNAME" 2>/dev/null || echo "/home/$USERNAME")
if [[ -d "$USER_HOME/mail" ]]; then
    rm -rf "$USER_HOME/mail"
fi

#==========================================
# ELIMINAR USUARIO LINUX
#==========================================
log_info "Eliminando usuario del sistema Linux..."

# Eliminar usuario y su home directory
userdel -r "$USERNAME" 2>/dev/null || {
    log_warn "Error al eliminar con -r, intentando sin eliminar home..."
    userdel "$USERNAME" 2>/dev/null || log_warn "Error eliminando usuario Linux"
}

# Asegurar que el home se eliminó
if [[ -d "/home/$USERNAME" ]]; then
    log_warn "Home directory aún existe, eliminando manualmente..."
    rm -rf "/home/$USERNAME"
fi

log_info "✓ Usuario Linux eliminado"

#==========================================
# ELIMINAR DATOS DE NEXTCLOUD
#==========================================
if [[ -d "/home/data/$USERNAME" ]]; then
    log_info "Eliminando datos de Nextcloud..."
    rm -rf "/home/data/$USERNAME"
    log_info "✓ Datos de Nextcloud eliminados"
fi

#==========================================
# ELIMINAR ARCHIVO DE CREDENCIALES
#==========================================
if [[ -f "$CRED_DIR/users/${USERNAME}.txt" ]]; then
    log_info "Eliminando archivo de credenciales..."
    rm -f "$CRED_DIR/users/${USERNAME}.txt"
    log_info "✓ Archivo de credenciales eliminado"
fi

#==========================================
# RESUMEN FINAL
#==========================================
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}║          ✅  USUARIO ELIMINADO EXITOSAMENTE                ║${NC}"
echo -e "${GREEN}║                                                           ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Usuario eliminado:     $USERNAME"
echo ""
echo "Servicios eliminados:"
for service in "${SERVICES_FOUND[@]}"; do
    echo "  ✓ $service"
done
echo ""

if [[ "$do_backup" == "y" ]]; then
    echo "Backup guardado en:"
    echo "  $BACKUP_DIR"
    echo ""
    echo "Para restaurar el backup (si es necesario):"
    echo "  1. Ejecuta create_user.sh para recrear el usuario"
    echo "  2. Restaura manualmente los datos desde $BACKUP_DIR"
    echo ""
fi

echo "Resumen de eliminación guardado en:"
echo "  /var/log/privacy_server_deletions.log"

# Log de la eliminación
cat >> /var/log/privacy_server_deletions.log << EOLOG
========================================
USUARIO ELIMINADO
========================================
Fecha: $(date)
Usuario: $USERNAME
Dominio: $DOMAIN
Backup: $([[ "$do_backup" == "y" ]] && echo "$BACKUP_DIR" || echo "NO")
Servicios eliminados: $(printf '%s, ' "${SERVICES_FOUND[@]}" | sed 's/, $//')

========================================

EOLOG

exit 0
