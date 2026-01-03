#!/bin/bash
#
# Privacy Server - Instalador Completo
# Versión: 2.0
# Compatible: AlmaLinux 10
# 
# Instala: Sistema Base + OpenVPN + Email + Nextcloud + Matrix
# SSH: Puerto 12999, solo root con RSA key
#
# Uso: ./privacy_server_installer.sh
#

set -euo pipefail

#==========================================
# COLORES Y FUNCIONES DE LOG
#==========================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOGFILE="/var/log/privacy_server_install.log"
exec > >(tee -a "$LOGFILE") 2>&1

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    exit 1
}

log_section() {
    echo ""
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
}

#==========================================
# VERIFICACIONES INICIALES
#==========================================
[[ $EUID -ne 0 ]] && log_error "Este script debe ejecutarse como root"

if [[ ! -f /etc/almalinux-release ]]; then
    log_warn "Este script está diseñado para AlmaLinux 10"
    read -p "¿Continuar de todas formas? (y/n): " continue_anyway
    [[ "$continue_anyway" != "y" ]] && exit 0
fi

#==========================================
# CONFIGURACIÓN GLOBAL
#==========================================
CONFIG_DIR="/etc/privacy_server"
CONFIG_FILE="$CONFIG_DIR/config.env"
CRED_DIR="$CONFIG_DIR/credentials"

mkdir -p "$CONFIG_DIR"
mkdir -p "$CRED_DIR"
chmod 700 "$CONFIG_DIR"
chmod 700 "$CRED_DIR"

#==========================================
# BANNER
#==========================================
clear
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║          PRIVACY SERVER - INSTALADOR COMPLETO             ║
║                                                           ║
║  Instalará:                                               ║
║  • Sistema Base (firewall, red, SSH)                      ║
║  • OpenVPN (VPN con autenticación PAM)                    ║
║  • Email (Postfix, Dovecot, DKIM, SpamAssassin)           ║
║  • Nextcloud (Cloud storage)                              ║
║  • Matrix Synapse + Coturn (Mensajería)                   ║
║                                                           ║
║  Compatible: AlmaLinux 10                                 ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo ""
read -p "Presione Enter para continuar..."

#==========================================
# RECOPILACIÓN DE CONFIGURACIÓN
#==========================================
log_section "CONFIGURACIÓN INICIAL"

# Dominio
read -p "Dominio principal (ej: privacidad.xyz): " DOMAIN
DOMAIN=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]' | xargs)
[[ -z "$DOMAIN" ]] && log_error "El dominio es obligatorio"

# Email administrativo
read -p "Email administrativo (para Let's Encrypt y notificaciones): " ADMIN_EMAIL
[[ -z "$ADMIN_EMAIL" ]] && log_error "El email administrativo es obligatorio"

# Detectar IP pública
log_info "Detectando IP pública..."
DETECTED_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "")
if [[ -n "$DETECTED_IP" ]]; then
    read -p "IP pública detectada: $DETECTED_IP - ¿Es correcta? (y/n) [y]: " ip_correct
    ip_correct=${ip_correct:-y}
    if [[ "$ip_correct" == "y" ]]; then
        PRIMARY_IP="$DETECTED_IP"
    else
        read -p "Introduce IP pública principal: " PRIMARY_IP
    fi
else
    read -p "IP pública principal: " PRIMARY_IP
fi
[[ -z "$PRIMARY_IP" ]] && log_error "La IP principal es obligatoria"

# Detectar interfaz de red
log_info "Detectando interfaz de red..."
DETECTED_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [[ -n "$DETECTED_INTERFACE" ]]; then
    echo ""
    echo "Interfaz detectada: $DETECTED_INTERFACE"
    ip addr show "$DETECTED_INTERFACE" | grep -E "inet |link/"
    echo ""
    read -p "¿Es correcta esta interfaz? (y/n) [y]: " interface_correct
    interface_correct=${interface_correct:-y}
    if [[ "$interface_correct" == "y" ]]; then
        INTERFACE="$DETECTED_INTERFACE"
    else
        echo "Interfaces disponibles:"
        ip link show | grep -E "^[0-9]+" | awk '{print $2}' | sed 's/://'
        read -p "Introduce nombre de interfaz: " INTERFACE
    fi
else
    echo "Interfaces disponibles:"
    ip link show | grep -E "^[0-9]+" | awk '{print $2}' | sed 's/://'
    read -p "Introduce nombre de interfaz: " INTERFACE
fi
[[ -z "$INTERFACE" ]] && log_error "La interfaz de red es obligatoria"

# Zona horaria
echo ""
echo "Zonas horarias comunes:"
echo "  America/Bogota"
echo "  America/Mexico_City"
echo "  America/New_York"
echo "  Europe/Madrid"
read -p "Zona horaria [America/Bogota]: " TIMEZONE
TIMEZONE=${TIMEZONE:-America/Bogota}

# Nombre organización para certificados OpenVPN
read -p "Nombre de organización (para certificados VPN): " ORG_NAME
[[ -z "$ORG_NAME" ]] && ORG_NAME="Privacy Server"

# Generar contraseña maestra
log_info "Generando contraseña maestra para servicios..."
MASTER_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)
echo ""
echo -e "${YELLOW}Contraseña maestra generada:${NC} ${GREEN}$MASTER_PASSWORD${NC}"
echo ""
echo "Esta contraseña se usará para:"
echo "  - MySQL root"
echo "  - Nextcloud admin"
echo "  - Matrix admin"
echo ""
read -p "¿Aceptar esta contraseña? (y/n) [y]: " accept_password
accept_password=${accept_password:-y}

if [[ "$accept_password" != "y" ]]; then
    read -p "Introduce tu propia contraseña: " MASTER_PASSWORD
    [[ -z "$MASTER_PASSWORD" ]] && log_error "La contraseña no puede estar vacía"
fi

#==========================================
# RESUMEN DE CONFIGURACIÓN
#==========================================
log_section "RESUMEN DE CONFIGURACIÓN"

cat << EOSUMMARY
Dominio:              $DOMAIN
Email admin:          $ADMIN_EMAIL
IP pública:           $PRIMARY_IP
Interfaz de red:      $INTERFACE
Zona horaria:         $TIMEZONE
Organización VPN:     $ORG_NAME
Contraseña maestra:   $MASTER_PASSWORD

Subdominios que se usarán:
  - mail.$DOMAIN    (Email)
  - cloud.$DOMAIN   (Nextcloud)
  - vpn.$DOMAIN     (OpenVPN)
  - stun.$DOMAIN    (TURN/STUN)

Puerto SSH:           12999 (solo root con RSA key)

EOSUMMARY

echo ""
read -p "¿Toda la configuración es correcta? (y/n): " confirm_config
[[ "$confirm_config" != "y" ]] && log_error "Instalación cancelada por el usuario"

# Guardar configuración
cat > "$CONFIG_FILE" << EOCONFIG
# Privacy Server Configuration
# Generado: $(date)

export DOMAIN="$DOMAIN"
export ADMIN_EMAIL="$ADMIN_EMAIL"
export PRIMARY_IP="$PRIMARY_IP"
export INTERFACE="$INTERFACE"
export TIMEZONE="$TIMEZONE"
export ORG_NAME="$ORG_NAME"
export MASTER_PASSWORD="$MASTER_PASSWORD"
export SSH_PORT="12999"
EOCONFIG

chmod 600 "$CONFIG_FILE"
source "$CONFIG_FILE"

log_info "Configuración guardada en $CONFIG_FILE"

#==========================================
# FASE 1: SISTEMA BASE
#==========================================
log_section "FASE 1: SISTEMA BASE"

log_info "Actualizando sistema..."
dnf update -y

log_info "Instalando paquetes base..."
dnf install -y \
    nano wget git curl \
    chrony \
    iptables-services \
    policycoreutils-python-utils \
    openssl tar unzip sqlite \
    expect

log_info "Configurando zona horaria..."
timedatectl set-timezone "$TIMEZONE"

log_info "Configurando chrony (NTP)..."
systemctl enable chronyd
systemctl start chronyd

log_info "Configurando /etc/hosts..."
cat >> /etc/hosts << EOHOSTS
$PRIMARY_IP $DOMAIN mail.$DOMAIN cloud.$DOMAIN vpn.$DOMAIN stun.$DOMAIN
EOHOSTS

log_info "Configurando red estática..."
nmcli con delete public-net 2>/dev/null || true
nmcli con add con-name public-net \
    ifname "$INTERFACE" \
    type ethernet \
    ipv4.method 'manual' \
    ipv4.addresses "$PRIMARY_IP/24" \
    ipv4.gateway "$(echo $PRIMARY_IP | cut -d. -f1-3).1" \
    ipv4.dns "8.8.8.8,8.8.4.4" \
    ipv6.method 'auto'

nmcli con up public-net

log_info "Configurando SELinux en modo permissive..."
setenforce 0 2>/dev/null || true
sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config

log_info "Configurando firewall (iptables)..."
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true
systemctl mask firewalld 2>/dev/null || true

systemctl enable iptables ip6tables

# Limpiar reglas
iptables -F
iptables -X
iptables -t nat -F
ip6tables -F
ip6tables -X

# Políticas por defecto
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

# Estados establecidos
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# HTTP/HTTPS
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT

# Email
for port in 25 465 587 110 995 143 993; do
    iptables -A INPUT -p tcp -m tcp --dport $port -j ACCEPT
done

# SSH en puerto custom
iptables -A INPUT -p tcp -m tcp --dport 12999 -j ACCEPT

# OpenVPN
iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
iptables -A INPUT -i tun0 -j ACCEPT

# TURN/STUN
iptables -A INPUT -p udp -m udp --dport 3478:3479 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 3478:3479 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 49152:65535 -j ACCEPT

# Matrix federation
iptables -A INPUT -p tcp -m tcp --dport 8448 -j ACCEPT

# ICMP
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# FORWARD para VPN
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o "$INTERFACE" -j ACCEPT
iptables -A FORWARD -i "$INTERFACE" -o tun0 -j ACCEPT

# NAT para VPN
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$INTERFACE" -j MASQUERADE

# IPv6 básico
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
ip6tables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
ip6tables -A INPUT -p tcp -m tcp --dport 12999 -j ACCEPT
ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP

# Guardar reglas
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables

systemctl start iptables ip6tables

log_info "Habilitando IP forwarding..."
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

log_info "Configurando SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Cambiar puerto SSH
sed -i "s/^#Port 22/Port 12999/" /etc/ssh/sshd_config
sed -i "s/^Port 22/Port 12999/" /etc/ssh/sshd_config

# Solo root login (sin password, solo key)
sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

# Solo autenticación por clave pública
sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Asegurar directiva PasswordAuthentication
if ! grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
fi

log_warn "IMPORTANTE: SSH configurado en puerto 12999, solo root con clave RSA"
log_warn "NO reinicies sshd hasta verificar que tu clave RSA funciona"

log_info "Sistema base configurado correctamente"

#==========================================
# FASE 2: CERTIFICADOS SSL
#==========================================
log_section "FASE 2: CERTIFICADOS SSL (Let's Encrypt)"

log_info "Instalando certbot..."
dnf install -y certbot

log_info "Obteniendo certificados SSL..."
log_warn "Asegúrate de que los registros DNS A estén configurados:"
log_warn "  $DOMAIN -> $PRIMARY_IP"
log_warn "  mail.$DOMAIN -> $PRIMARY_IP"
log_warn "  cloud.$DOMAIN -> $PRIMARY_IP"
log_warn "  vpn.$DOMAIN -> $PRIMARY_IP"
log_warn "  stun.$DOMAIN -> $PRIMARY_IP"
echo ""
read -p "¿DNS configurado correctamente? (y/n): " dns_ready
if [[ "$dns_ready" != "y" ]]; then
    log_error "Configura DNS primero y vuelve a ejecutar el script"
fi

certbot certonly --standalone \
    --non-interactive \
    --agree-tos \
    -m "$ADMIN_EMAIL" \
    -d "$DOMAIN" \
    -d "mail.$DOMAIN" \
    -d "cloud.$DOMAIN" \
    -d "vpn.$DOMAIN" \
    -d "stun.$DOMAIN"

if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
    log_error "Error obteniendo certificados SSL"
fi

log_info "Certificados SSL obtenidos correctamente"

#==========================================
# FASE 3: OPENVPN
#==========================================
log_section "FASE 3: OpenVPN"

log_info "Instalando OpenVPN..."
dnf install -y openvpn

log_info "Descargando Easy-RSA..."
cd /etc/openvpn
EASYRSA_VERSION="3.1.7"
wget -q "https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz"
tar -xzf "EasyRSA-${EASYRSA_VERSION}.tgz"
mv "EasyRSA-${EASYRSA_VERSION}" easy-rsa
rm "EasyRSA-${EASYRSA_VERSION}.tgz"

cd /etc/openvpn/easy-rsa

log_info "Configurando Easy-RSA..."
cat > vars << EOVARS
set_var EASYRSA "\$PWD"
set_var EASYRSA_PKI "\$EASYRSA/pki"
set_var EASYRSA_DN "cn_only"
set_var EASYRSA_REQ_COUNTRY "CO"
set_var EASYRSA_REQ_PROVINCE "Magdalena"
set_var EASYRSA_REQ_CITY "SantaMarta"
set_var EASYRSA_REQ_ORG "$ORG_NAME"
set_var EASYRSA_REQ_EMAIL "$ADMIN_EMAIL"
set_var EASYRSA_REQ_OU "$ORG_NAME"
set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_ALGO rsa
set_var EASYRSA_CA_EXPIRE 7500
set_var EASYRSA_CERT_EXPIRE 365
set_var EASYRSA_DIGEST "sha256"
EOVARS

log_info "Inicializando PKI..."
./easyrsa init-pki

log_info "Generando CA (Certificate Authority)..."
EASYRSA_BATCH=1 EASYRSA_REQ_CN="$DOMAIN" ./easyrsa build-ca nopass

log_info "Generando certificado del servidor OpenVPN..."
./easyrsa gen-req vpn-server nopass
EASYRSA_BATCH=1 ./easyrsa sign-req server vpn-server

log_info "Generando parámetros Diffie-Hellman..."
./easyrsa gen-dh

log_info "Copiando certificados al directorio del servidor..."
mkdir -p /etc/openvpn/server
cp pki/ca.crt /etc/openvpn/server/
cp pki/dh.pem /etc/openvpn/server/
cp pki/private/vpn-server.key /etc/openvpn/server/
cp pki/issued/vpn-server.crt /etc/openvpn/server/

log_info "Generando certificado de cliente genérico..."
./easyrsa gen-req client-template nopass
EASYRSA_BATCH=1 ./easyrsa sign-req client client-template

mkdir -p /etc/openvpn/client
cp pki/ca.crt /etc/openvpn/client/
cp pki/issued/client-template.crt /etc/openvpn/client/
cp pki/private/client-template.key /etc/openvpn/client/

log_info "Creando configuración del servidor OpenVPN..."
cat > /etc/openvpn/server/server.conf << EOSERVCONF
local $PRIMARY_IP
port 1194
proto udp
dev tun

ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/vpn-server.crt
key /etc/openvpn/server/vpn-server.key
dh /etc/openvpn/server/dh.pem

server 10.8.0.0 255.255.255.0

push "redirect-gateway def1"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

duplicate-cn
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256
auth SHA512

keepalive 20 60
persist-key
persist-tun

daemon
user nobody
group nobody

log-append /var/log/openvpn.log
verb 3

# Autenticación con usuario/contraseña PAM
verify-client-cert none
plugin /usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so login
EOSERVCONF

log_info "Generando archivo de configuración para clientes (.ovpn)..."
CA_CERT=$(cat /etc/openvpn/client/ca.crt)

cat > /etc/openvpn/client/${DOMAIN%%.*}.ovpn << EOCLIENTCONF
# OpenVPN Client Configuration - $DOMAIN
client
dev tun
proto udp
remote vpn.$DOMAIN 1194

<ca>
$CA_CERT
</ca>

auth SHA512
auth-nocache
data-ciphers-fallback AES-256-CBC
tls-version-min 1.2
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256

resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3

# Autenticación usuario/contraseña
auth-user-pass
EOCLIENTCONF

log_info "Iniciando OpenVPN..."
systemctl enable openvpn-server@server
systemctl start openvpn-server@server

sleep 3

if ! systemctl is-active --quiet openvpn-server@server; then
    log_error "Error iniciando OpenVPN. Ver: journalctl -u openvpn-server@server"
fi

log_info "OpenVPN configurado correctamente"

#==========================================
# FASE 4: SERVIDOR EMAIL
#==========================================
log_section "FASE 4: SERVIDOR EMAIL"

log_info "Instalando paquetes de email..."
dnf install -y dovecot postfix procmail \
    cyrus-sasl cyrus-sasl-gssapi cyrus-sasl-md5 cyrus-sasl-plain \
    opendkim opendkim-tools \
    spamassassin spamass-milter \
    mailx

log_info "Configurando OpenDKIM..."
mv /etc/opendkim.conf /etc/opendkim.conf.backup 2>/dev/null || true

cat > /etc/opendkim.conf << EODKIM
PidFile /run/opendkim/opendkim.pid
Mode sv
Syslog yes
SyslogSuccess yes
LogWhy yes
UserID opendkim:opendkim
Socket inet:8891@localhost
Umask 002
SendReports yes
ReportAddress postmaster@$DOMAIN
SoftwareHeader yes
Canonicalization relaxed/relaxed
Selector default
MinimumKeyBits 1024
KeyFile /etc/opendkim/keys/default.private
KeyTable /etc/opendkim/KeyTable
SigningTable refile:/etc/opendkim/SigningTable
ExternalIgnoreList refile:/etc/opendkim/TrustedHosts
InternalHosts refile:/etc/opendkim/TrustedHosts
OversignHeaders From
QueryCache yes
EODKIM

cat > /etc/opendkim/SigningTable << EOSIGNING
*@$DOMAIN default._domainkey.$DOMAIN
EOSIGNING

cat > /etc/opendkim/KeyTable << EOKEYTABLE
default._domainkey.$DOMAIN $DOMAIN:default:/etc/opendkim/keys/$DOMAIN/default.private
EOKEYTABLE

cat > /etc/opendkim/TrustedHosts << EOTRUSTED
127.0.0.1
localhost
.$DOMAIN
EOTRUSTED

mkdir -p /etc/opendkim/keys/$DOMAIN
opendkim-genkey -b 2048 -d $DOMAIN -D /etc/opendkim/keys/$DOMAIN -s default -v
chown -R opendkim:opendkim /etc/opendkim/

# Guardar clave DKIM pública
DKIM_PUBLIC=$(cat /etc/opendkim/keys/$DOMAIN/default.txt | grep -oP 'p=\K[^"]+')
echo "export DKIM_PUBLIC='$DKIM_PUBLIC'" >> "$CONFIG_FILE"

# Guardar clave DKIM pública
DKIM_PUBLIC=$(cat /etc/opendkim/keys/$DOMAIN/default.txt | grep -oP 'p=\K[^"]+')
echo "export DKIM_PUBLIC='$DKIM_PUBLIC'" >> "$CONFIG_FILE"

# MOSTRAR EN PANTALLA LA CLAVE DKIM
echo ""
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  IMPORTANTE: CONFIGURAR REGISTRO DNS DKIM AHORA           ║${NC}"
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
echo ""
echo -e "${GREEN}Añade este registro TXT a tu DNS:${NC}"
echo ""
cat /etc/opendkim/keys/$DOMAIN/default.txt
echo ""
echo -e "${YELLOW}O en formato simple:${NC}"
echo ""
echo "default._domainkey.$DOMAIN IN TXT \"v=DKIM1; k=rsa; p=$DKIM_PUBLIC\""
echo ""
read -p "Presiona Enter cuando hayas configurado el DNS DKIM..."
echo ""

systemctl enable opendkim
systemctl start opendkim

log_info "Configurando SpamAssassin..."
cat > /etc/sysconfig/spamass-milter << EOSPAM
EXTRA_FLAGS="-m -r 8"
SOCKET_OPTIONS="-g postfix"
EOSPAM

mkdir -p /etc/systemd/system/spamass-milter.service.d/
cat > /etc/systemd/system/spamass-milter.service.d/override.conf << EOSPAMSERVICE
[Service]
Group=postfix
EOSPAMSERVICE

systemctl daemon-reload
systemctl enable spamassassin spamass-milter
systemctl start spamassassin spamass-milter

log_info "Configurando Postfix..."
touch /etc/postfix/sender_access_regexp
postmap /etc/postfix/access 2>/dev/null || (touch /etc/postfix/access && postmap /etc/postfix/access)

cp /etc/postfix/main.cf /etc/postfix/main.cf.backup

cat > /etc/postfix/main.cf << EOMAIN
# Postfix Main Configuration
myhostname = mail.$DOMAIN
mydomain = $DOMAIN
myorigin = \$mydomain
inet_interfaces = all
inet_protocols = all
mydestination = \$myhostname, $DOMAIN, localhost.\$mydomain, localhost

# TLS/SSL
smtpd_tls_cert_file = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
smtpd_tls_key_file = /etc/letsencrypt/live/$DOMAIN/privkey.pem
smtp_tls_CAfile = /etc/letsencrypt/live/$DOMAIN/cert.pem
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtpd_use_tls = yes
smtpd_tls_dh1024_param_file = /etc/postfix/dhparams.pem
tls_preempt_cipherlist = yes
smtpd_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtp_tls_protocols = !SSLv2,!SSLv3,!TLSv1,!TLSv1.1
smtpd_tls_exclude_ciphers = aNULL,LOW,EXP,MEDIUM,ADH,AECDH,MD5,DSS,ECDSA,CAMELLIA128,3DES,CAMELLIA256,RSA+AES,eNULL

# Milters (OpenDKIM + SpamAssassin)
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:8891,unix:/run/spamass-milter/spamass-milter.sock
non_smtpd_milters = \$smtpd_milters

# Security
smtpd_sender_restrictions = check_sender_access regexp:/etc/postfix/sender_access_regexp
smtpd_client_restrictions = permit_mynetworks permit_sasl_authenticated
smtpd_recipient_restrictions = permit_sasl_authenticated
smtpd_relay_restrictions = permit_sasl_authenticated defer_unauth_destination
smtpd_sasl_auth_enable = yes
smtpd_tls_auth_only = yes
disable_vrfy_command = yes

# Mailbox
mailbox_command = /usr/bin/procmail -a "\$EXTENSION"
message_size_limit = 204800000
mailbox_size_limit = 0

EOMAIN

openssl dhparam -out /etc/postfix/dhparams.pem 2048

gpasswd -a postfix opendkim

log_info "Configurando Procmail..."
cat > /etc/procmailrc << EOPROC
LOGFILE=/var/log/procmail.log
VERBOSE=on
DROPPRIVS=yes

:0wf
| /usr/bin/spamc

:0
H * ^X-Spam-Status: Yes
/dev/null
EOPROC

touch /var/log/procmail.log
chown postfix:mail /var/log/procmail.log
chmod 666 /var/log/procmail.log

log_info "Configurando Dovecot..."
cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.backup

cat > /etc/dovecot/dovecot.conf << EODOVECONF
protocols = imap pop3 lmtp
listen = *, ::
!include conf.d/*.conf
!include_try local.conf
EODOVECONF

cat > /etc/dovecot/conf.d/10-mail.conf << EODOVEMAIL
mail_location = mbox:~/mail:INBOX=/var/mail/%u
namespace inbox {
  inbox = yes
}
first_valid_uid = 1000
mbox_write_locks = fcntl
EODOVEMAIL

cat > /etc/dovecot/conf.d/10-ssl.conf << EODOVESSL
ssl = required
ssl_cert = </etc/letsencrypt/live/$DOMAIN/fullchain.pem
ssl_key = </etc/letsencrypt/live/$DOMAIN/privkey.pem
ssl_dh = </etc/dovecot/dh.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
ssl_prefer_server_ciphers = no
EODOVESSL

cat > /etc/dovecot/conf.d/15-mailboxes.conf << EODOVEMBOX
namespace inbox {
  mailbox Trash {
    special_use = \\Trash
    auto = subscribe
  }
  mailbox "Sent Messages" {
    special_use = \\Sent
    auto = subscribe
  }
  mailbox Drafts {
    special_use = \\Drafts
    auto = subscribe
  }
  mailbox Spam {
    special_use = \\Junk
    auto = subscribe
  }
}
EODOVEMBOX

echo 'pop3_uidl_format = %v-%u' > /etc/dovecot/conf.d/20-pop3.conf

openssl dhparam -out /etc/dovecot/dh.pem 2048

systemctl enable postfix dovecot saslauthd
systemctl start postfix dovecot saslauthd

log_info "Servidor de email configurado correctamente"

#==========================================
# FASE 5: NEXTCLOUD
#==========================================
log_section "FASE 5: NEXTCLOUD"

log_info "Instalando Apache, PHP y extensiones..."
dnf install -y httpd mod_ssl

dnf install -y php php-fpm php-common php-gmp php-curl php-intl \
    php-pdo php-mbstring php-gd php-xml php-cli php-zip \
    php-mysqli php-process php-pecl-apcu php-pecl-imagick \
    php-bcmath php-opcache php-json php-ldap

log_info "Configurando PHP..."
cp /etc/php.ini /etc/php.ini.backup

sed -i 's/memory_limit = .*/memory_limit = 512M/' /etc/php.ini
sed -i 's/upload_max_filesize = .*/upload_max_filesize = 200M/' /etc/php.ini
sed -i 's/post_max_size = .*/post_max_size = 200M/' /etc/php.ini
sed -i 's/max_execution_time = .*/max_execution_time = 360/' /etc/php.ini
sed -i "s|;date.timezone =.*|date.timezone = $TIMEZONE|" /etc/php.ini
sed -i 's/;opcache.enable=.*/opcache.enable=1/' /etc/php.ini
sed -i 's/;opcache.memory_consumption=.*/opcache.memory_consumption=128/' /etc/php.ini
sed -i 's/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=8/' /etc/php.ini
sed -i 's/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=10000/' /etc/php.ini
sed -i 's/;opcache.revalidate_freq=.*/opcache.revalidate_freq=1/' /etc/php.ini
sed -i 's/;opcache.save_comments=.*/opcache.save_comments=1/' /etc/php.ini

cat > /etc/php.d/40-apcu.ini << 'EOF'
extension=apcu.so
apc.enabled=1
apc.shm_size=32M
apc.enable_cli=1
EOF

log_info "Instalando MariaDB..."
dnf install -y mariadb-server mariadb

systemctl enable mariadb httpd php-fpm
systemctl start mariadb

log_info "Configurando MariaDB..."
NC_DB_PASSWORD=$(openssl rand -base64 24)
echo "export NC_DB_PASSWORD='$NC_DB_PASSWORD'" >> "$CONFIG_FILE"

mysql -u root <<EOSQL
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MASTER_PASSWORD';
DELETE FROM mysql.global_priv WHERE User='';
DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOSQL

# Crear base de datos y usuario Nextcloud
mysql -u root -p"$MASTER_PASSWORD" <<EOSQL
CREATE DATABASE IF NOT EXISTS nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER IF NOT EXISTS 'ncuser'@'localhost' IDENTIFIED BY '$NC_DB_PASSWORD';
GRANT ALL PRIVILEGES ON nextcloud.* TO 'ncuser'@'localhost';
FLUSH PRIVILEGES;
EOSQL

log_info "Base de datos y usuario Nextcloud creados"

log_info "Descargando Nextcloud..."
cd /var/www
wget -q "https://download.nextcloud.com/server/releases/latest.zip" -O nextcloud.zip
unzip -q nextcloud.zip
rm nextcloud.zip

mkdir -p /home/data
chown -R apache:apache /home/data /var/www/nextcloud
chmod 750 /home/data

log_info "Configurando Apache Virtual Host..."
cat > /etc/httpd/conf.d/nextcloud.conf <<EOHTTP
<VirtualHost *:80>
    ServerName cloud.$DOMAIN
    RewriteEngine on
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<VirtualHost *:443>
    ServerAdmin $ADMIN_EMAIL
    DocumentRoot /var/www/nextcloud
    ServerName cloud.$DOMAIN

    <Directory /var/www/nextcloud>
        Options +FollowSymLinks
        AllowOverride All
        Require all granted
        
        <IfModule mod_dav.c>
            Dav off
        </IfModule>
        
        Header always set Strict-Transport-Security "max-age=15552000; includeSubDomains"
    </Directory>

    Protocols h2 http/1.1
    
    SSLEngine on
    SSLHonorCipherOrder on
    SSLSessionTickets off
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN/privkey.pem
    SSLCertificateFile /etc/letsencrypt/live/$DOMAIN/cert.pem
    SSLCertificateChainFile /etc/letsencrypt/live/$DOMAIN/fullchain.pem
    SSLCipherSuite "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    SSLUseStapling On
    
    ErrorLog /var/log/httpd/nextcloud-error_log
    CustomLog /var/log/httpd/nextcloud-access_log common
</VirtualHost>

SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
EOHTTP

cat > /var/www/html/index.html <<EOINDEX
<html>
<head>
<meta http-equiv="refresh" content="0;URL=https://cloud.$DOMAIN">
</head>
<body>
<p>Redirecting to Nextcloud...</p>
</body>
</html>
EOINDEX

systemctl start httpd php-fpm

log_info "Instalando Nextcloud..."
sudo -u apache php /var/www/nextcloud/occ maintenance:install \
    --database "mysql" \
    --database-name "nextcloud" \
    --database-host "localhost" \
    --database-user "ncuser" \
    --database-pass "$NC_DB_PASSWORD" \
    --admin-user "admin" \
    --admin-pass "$MASTER_PASSWORD" \
    --data-dir "/home/data"

sudo -u apache php /var/www/nextcloud/occ config:system:set trusted_domains 0 --value="$DOMAIN"
sudo -u apache php /var/www/nextcloud/occ config:system:set trusted_domains 1 --value="cloud.$DOMAIN"
sudo -u apache php /var/www/nextcloud/occ config:system:set trusted_domains 2 --value="$PRIMARY_IP"
sudo -u apache php /var/www/nextcloud/occ config:system:set default_phone_region --value="CO"
sudo -u apache php /var/www/nextcloud/occ config:system:set memcache.local --value="\\OC\\Memcache\\APCu"

echo "*/15 * * * * php -f /var/www/nextcloud/cron.php" | crontab -u apache -
sudo -u apache php /var/www/nextcloud/occ background:cron

if getenforce | grep -q "Enforcing\|Permissive"; then
    semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/nextcloud(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t httpd_sys_rw_content_t "/home/data(/.*)?" 2>/dev/null || true
    restorecon -R /var/www/nextcloud 2>/dev/null || true
    restorecon -R /home/data 2>/dev/null || true
    setsebool -P httpd_can_network_connect on 2>/dev/null || true
    setsebool -P httpd_can_sendmail on 2>/dev/null || true
fi

log_info "Nextcloud instalado correctamente"

#==========================================
# FASE 6: MATRIX SYNAPSE + COTURN
#==========================================
log_section "FASE 6: MATRIX SYNAPSE + COTURN"

log_info "Instalando Coturn..."
dnf install -y epel-release
dnf install -y coturn

TURN_SECRET=$(openssl rand -hex 32)
echo "export TURN_SECRET='$TURN_SECRET'" >> "$CONFIG_FILE"

cat > /etc/coturn/turnserver.conf <<EOTURN
listening-device=$INTERFACE
listening-port=3478
tls-listening-port=5349

listening-ip=$PRIMARY_IP
relay-ip=$PRIMARY_IP
external-ip=$PRIMARY_IP

min-port=49152
max-port=65535

verbose
fingerprint
use-auth-secret
static-auth-secret=$TURN_SECRET
realm=$DOMAIN

cert=/etc/coturn/fullchain.pem
pkey=/etc/coturn/privkey.pem

cipher-list="ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
dh-file=/etc/coturn/dhp.pem

log-file=/var/log/coturn/turnserver.log
simple-log

no-multicast-peers
no-cli
no-tlsv1
no-tlsv1_1
EOTURN

openssl dhparam -dsaparam -out /etc/coturn/dhp.pem 2048

mkdir -p /var/log/coturn
chown coturn:coturn /var/log/coturn

log_info "Instalando Matrix Synapse..."
dnf install -y python3 python3-pip python3-devel \
    gcc libffi-devel openssl-devel

pip3 install --upgrade pip
pip3 install --ignore-installed matrix-synapse

useradd -r -s /bin/false synapse 2>/dev/null || true

mkdir -p /etc/synapse /var/log/synapse /media_store
chown synapse:synapse /etc/synapse /var/log/synapse /media_store

log_info "Generando configuración Synapse..."
REGISTRATION_SECRET=$(openssl rand -hex 32)
MACAROON_SECRET=$(openssl rand -hex 32)
FORM_SECRET=$(openssl rand -hex 32)

echo "export MATRIX_REGISTRATION_SECRET='$REGISTRATION_SECRET'" >> "$CONFIG_FILE"

cat > /etc/synapse/homeserver.yaml <<EOSYNAPSE
server_name: "$DOMAIN"
pid_file: /run/synapse/homeserver.pid
public_baseurl: "https://$DOMAIN:8448"
report_stats: false

listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['127.0.0.1']
    resources:
      - names: [client]
        compress: false

  - port: 8448
    tls: true
    type: http
    x_forwarded: true
    resources:
      - names: [client, federation]
        compress: false

tls_certificate_path: "/etc/synapse/fullchain.pem"
tls_private_key_path: "/etc/synapse/privkey.pem"

turn_uris:
  - "turn:stun.$DOMAIN?transport=udp"
  - "turn:stun.$DOMAIN?transport=tcp"
turn_shared_secret: "$TURN_SECRET"
turn_user_lifetime: 1h
turn_allow_guests: false

database:
  name: sqlite3
  args:
    database: /etc/synapse/homeserver.db

log_config: "/etc/synapse/log.config"

media_store_path: /media_store
max_upload_size: 50M

enable_registration: false
registration_shared_secret: "$REGISTRATION_SECRET"

macaroon_secret_key: "$MACAROON_SECRET"
form_secret: "$FORM_SECRET"
signing_key_path: "/etc/synapse/$DOMAIN.signing.key"

trusted_key_servers:
  - server_name: "matrix.org"

suppress_key_server_warning: true
EOSYNAPSE

cat > /etc/synapse/log.config <<EOLOG
version: 1
formatters:
  precise:
    format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
handlers:
  file:
    class: logging.handlers.RotatingFileHandler
    formatter: precise
    filename: /var/log/synapse/homeserver.log
    maxBytes: 104857600
    backupCount: 3
root:
  level: INFO
  handlers: [file]
EOLOG

chown synapse:synapse /etc/synapse/homeserver.yaml /etc/synapse/log.config

sudo -u synapse python3 -m synapse.app.homeserver \
    --config-path="/etc/synapse/homeserver.yaml" \
    --generate-keys

log_info "Configurando renovación automática de certificados..."
mkdir -p /etc/letsencrypt/renewal-hooks/deploy

cat > /etc/letsencrypt/renewal-hooks/deploy/copy_certs.sh <<'EOHOOK'
#!/bin/bash
set -e
DOMAIN="DOMAIN_PLACEHOLDER"

for certfile in fullchain.pem privkey.pem ; do
    cp -L "/etc/letsencrypt/live/$DOMAIN/${certfile}" "/etc/coturn/${certfile}.new"
    chown coturn:coturn "/etc/coturn/${certfile}.new"
    mv "/etc/coturn/${certfile}.new" "/etc/coturn/${certfile}"
    
    cp -L "/etc/letsencrypt/live/$DOMAIN/${certfile}" "/etc/synapse/${certfile}.new"
    chown synapse:synapse "/etc/synapse/${certfile}.new"
    mv "/etc/synapse/${certfile}.new" "/etc/synapse/${certfile}"
done

systemctl reload coturn 2>/dev/null || true
systemctl reload synapse 2>/dev/null || true
EOHOOK

sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /etc/letsencrypt/renewal-hooks/deploy/copy_certs.sh
chmod +x /etc/letsencrypt/renewal-hooks/deploy/copy_certs.sh
/etc/letsencrypt/renewal-hooks/deploy/copy_certs.sh

cat > /etc/systemd/system/synapse.service <<EOSERVICE
[Unit]
Description=Matrix Synapse Homeserver
After=network.target

[Service]
Type=simple
User=synapse
Group=synapse
WorkingDirectory=/etc/synapse
ExecStart=/usr/bin/python3 -m synapse.app.homeserver --config-path=/etc/synapse/homeserver.yaml
Restart=on-failure
RestartSec=10
RuntimeDirectory=synapse

[Install]
WantedBy=multi-user.target
EOSERVICE

systemctl daemon-reload

systemctl enable coturn synapse
systemctl start coturn synapse

sleep 5

if ! systemctl is-active --quiet coturn; then
    log_error "Error iniciando Coturn"
fi

if ! systemctl is-active --quiet synapse; then
    log_error "Error iniciando Synapse"
fi

log_info "Creando usuario administrador Matrix..."
register_new_matrix_user \
    -u admin \
    -p "$MASTER_PASSWORD" \
    -a \
    -c /etc/synapse/homeserver.yaml

log_info "Matrix Synapse + Coturn instalados correctamente"

#==========================================
# GUARDAR CREDENCIALES FINALES
#==========================================
log_section "GUARDANDO CREDENCIALES"

cat > "$CRED_DIR/admin_credentials.txt" << EOCREDS
========================================
PRIVACY SERVER - CREDENCIALES
========================================
Generado: $(date)

DOMINIO: $DOMAIN

CONTRASEÑA MAESTRA (usada en todos los servicios):
$MASTER_PASSWORD

========================================
MYSQL ROOT
========================================
Usuario: root
Contraseña: $MASTER_PASSWORD

========================================
NEXTCLOUD
========================================
URL: https://cloud.$DOMAIN
Usuario admin: admin
Contraseña: $MASTER_PASSWORD

Base de datos:
  Usuario: ncuser
  Contraseña: $NC_DB_PASSWORD

========================================
MATRIX SYNAPSE
========================================
Homeserver: https://$DOMAIN:8448
Usuario admin: @admin:$DOMAIN
Contraseña: $MASTER_PASSWORD

Registration Secret: $REGISTRATION_SECRET

========================================
COTURN (TURN/STUN)
========================================
Servidor: stun.$DOMAIN:3478
Secret: $TURN_SECRET

========================================
OPENDKIM
========================================
Clave pública (añadir a DNS):

default._domainkey.$DOMAIN IN TXT "v=DKIM1; k=rsa; p=$DKIM_PUBLIC"

========================================
CONFIGURACIÓN DNS NECESARIA
========================================

# Registros A
$DOMAIN                 IN  A       $PRIMARY_IP
mail.$DOMAIN            IN  A       $PRIMARY_IP
cloud.$DOMAIN           IN  A       $PRIMARY_IP
vpn.$DOMAIN             IN  A       $PRIMARY_IP
stun.$DOMAIN            IN  A       $PRIMARY_IP

# MX
$DOMAIN                 IN  MX  10  mail.$DOMAIN.

# SPF
$DOMAIN                 IN  TXT     "v=spf1 mx ~all"

# DKIM
default._domainkey.$DOMAIN IN TXT "v=DKIM1; k=rsa; p=$DKIM_PUBLIC"

# DMARC
_dmarc.$DOMAIN          IN  TXT     "v=DMARC1; p=quarantine; rua=mailto:postmaster@$DOMAIN"

# SRV (Matrix)
_matrix._tcp.$DOMAIN    IN  SRV     10 0 8448 $DOMAIN.

========================================
ARCHIVOS IMPORTANTES
========================================
Configuración: $CONFIG_FILE
Credenciales: $CRED_DIR/
Archivo VPN: /etc/openvpn/client/${DOMAIN%%.*}.ovpn
Logs: /var/log/privacy_server_install.log

========================================
EOCREDS

chmod 600 "$CRED_DIR/admin_credentials.txt"

#==========================================
# ENVIAR EMAIL CON CREDENCIALES
#==========================================
log_info "Enviando email con credenciales a $ADMIN_EMAIL..."

(
echo "From: postmaster@$DOMAIN"
echo "To: $ADMIN_EMAIL"
echo "Subject: Privacy Server - Instalación Completada"
echo "Content-Type: text/html; charset=UTF-8"
echo ""
cat << EOHTML
<html>
<body style="font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; background: #f5f5f5; padding: 20px;">
<div style="background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
    <h1 style="color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px;">
        🎉 Privacy Server - Instalación Completada
    </h1>
    
    <p>La instalación de tu Privacy Server se ha completado exitosamente.</p>
    
    <h2 style="color: #2c3e50; margin-top: 30px;">📋 Servicios Instalados</h2>
    <ul style="line-height: 1.8;">
        <li>✅ Sistema Base (Firewall, SSH puerto 12999)</li>
        <li>✅ OpenVPN (VPN)</li>
        <li>✅ Servidor Email (Postfix + Dovecot + DKIM)</li>
        <li>✅ Nextcloud (Cloud Storage)</li>
        <li>✅ Matrix Synapse (Mensajería)</li>
        <li>✅ Coturn (TURN/STUN)</li>
    </ul>
    
    <h2 style="color: #e74c3c; margin-top: 30px;">🔐 Contraseña Maestra</h2>
    <div style="background: #ffe6e6; padding: 15px; border-left: 4px solid #e74c3c; font-family: monospace; font-size: 16px;">
        <strong>$MASTER_PASSWORD</strong>
    </div>
    <p style="color: #666; font-size: 14px;">Esta contraseña se usa para MySQL, Nextcloud y Matrix.</p>
    
    <h2 style="color: #2c3e50; margin-top: 30px;">🌐 URLs de Acceso</h2>
    <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
        <tr style="background: #ecf0f1;">
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Nextcloud</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">
                <a href="https://cloud.$DOMAIN">https://cloud.$DOMAIN</a>
            </td>
        </tr>
        <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Matrix</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">https://$DOMAIN:8448</td>
        </tr>
    </table>
    
    <h2 style="color: #2c3e50; margin-top: 30px;">📧 Configuración Email</h2>
    <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
        <tr style="background: #ecf0f1;">
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>IMAP</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">mail.$DOMAIN:993 (SSL/TLS)</td>
        </tr>
        <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>SMTP</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">mail.$DOMAIN:587 (STARTTLS)</td>
        </tr>
    </table>
    
    <h2 style="color: #e67e22; margin-top: 30px;">⚠️ TAREAS PENDIENTES</h2>
    <ol style="line-height: 2; background: #fff3cd; padding: 20px; border-radius: 5px;">
        <li><strong>Configurar DNS:</strong> Revisar archivo de credenciales para registros completos</li>
        <li><strong>Agregar clave DKIM</strong> al DNS</li>
        <li><strong>Probar SSH</strong> en puerto 12999 antes de cerrar sesión actual</li>
        <li><strong>Crear primer usuario</strong> con create_user.sh</li>
    </ol>
    
    <h2 style="color: #2c3e50; margin-top: 30px;">📁 Archivos Importantes</h2>
    <ul style="font-family: monospace; font-size: 13px; background: #f8f9fa; padding: 15px; border-radius: 5px;">
        <li>$CRED_DIR/admin_credentials.txt</li>
        <li>/etc/openvpn/client/${DOMAIN%%.*}.ovpn</li>
        <li>$CONFIG_FILE</li>
    </ul>
    
    <div style="margin-top: 40px; padding-top: 20px; border-top: 2px solid #ecf0f1; color: #7f8c8d; font-size: 12px;">
        <p>Este email contiene información sensible. Guárdalo de forma segura.</p>
        <p>Instalación completada el $(date)</p>
    </div>
</div>
</body>
</html>
EOHTML
) | /usr/sbin/sendmail -t

log_info "Email enviado correctamente"

#==========================================
# RESUMEN FINAL
#==========================================
log_section "INSTALACIÓN COMPLETADA"

cat << EOFINAL

╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        ✅  INSTALACIÓN COMPLETADA EXITOSAMENTE            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

Todos los servicios han sido instalados y configurados:

  ✅ Sistema Base
  ✅ OpenVPN  
  ✅ Servidor Email (Postfix + Dovecot + DKIM)
  ✅ Nextcloud
  ✅ Matrix Synapse + Coturn

CONTRASEÑA MAESTRA: $MASTER_PASSWORD

CREDENCIALES COMPLETAS:
  $CRED_DIR/admin_credentials.txt

EMAIL ENVIADO A:
  $ADMIN_EMAIL

⚠️  IMPORTANTE - ANTES DE CONTINUAR:

1. CONFIGURAR DNS (ver archivo de credenciales)
2. PROBAR SSH en puerto 12999 ANTES de cerrar esta sesión
3. Reiniciar SSH: systemctl restart sshd

PRÓXIMO PASO:
¿Deseas crear el primer usuario ahora?

EOFINAL

read -p "¿Crear primer usuario? (y/n): " create_first_user

if [[ "$create_first_user" == "y" ]]; then
    if [[ -f "./create_user.sh" ]]; then
        bash ./create_user.sh
    else
        log_warn "Archivo create_user.sh no encontrado en el directorio actual"
        log_info "Puedes crearlo manualmente después"
    fi
fi

log_info ""
log_info "Instalación finalizada. Revisa $LOGFILE para detalles completos."
log_info ""

exit 0
