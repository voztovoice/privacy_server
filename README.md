# Privacy Server - Instalador Completo para AlmaLinux 10

Solución completa de servidor de privacidad que instala y configura automáticamente todos los servicios necesarios para tener tu propia infraestructura privada.

## 🎯 Características

### Servicios Instalados
- ✅ **Sistema Base** - Firewall, red, SSH hardening (puerto 12999, solo root con RSA)
- ✅ **OpenVPN** - VPN con autenticación PAM
- ✅ **Servidor Email** - Postfix + Dovecot + OpenDKIM + SpamAssassin
- ✅ **Nextcloud** - Almacenamiento en la nube y colaboración
- ✅ **Matrix Synapse** - Mensajería federada segura
- ✅ **Coturn** - TURN/STUN server para WebRTC

### Automatización Completa
- 🔧 Configuración interactiva con validaciones
- 🔐 Generación automática de contraseñas seguras
- 📧 Email automático con todas las credenciales
- 📝 Documentación integrada
- 🛡️ Seguridad por defecto (TLS 1.2+, firewall restrictivo)

## 📋 Requisitos

### Sistema
- **SO**: AlmaLinux 10 (recién instalado)
- **RAM**: 4GB mínimo (8GB recomendado)
- **Disco**: 40GB mínimo
- **CPU**: 2 cores mínimo
- **Red**: IP pública estática

### Previo a la instalación
1. **Dominio registrado** apuntando a tu servidor
2. **Acceso root** vía SSH con clave RSA configurada
3. **Firewall del proveedor** (si existe) con puertos abiertos

## 🚀 Instalación Rápida

### Paso 1: Configurar DNS

Antes de ejecutar el instalador, configura estos registros DNS:

```dns
# Registros A
tudominio.com           IN  A       TU_IP_PUBLICA
mail.tudominio.com      IN  A       TU_IP_PUBLICA
cloud.tudominio.com     IN  A       TU_IP_PUBLICA
vpn.tudominio.com       IN  A       TU_IP_PUBLICA
stun.tudominio.com      IN  A       TU_IP_PUBLICA

# MX Record
tudominio.com           IN  MX  10  mail.tudominio.com.

# SPF
tudominio.com           IN  TXT     "v=spf1 mx ~all"

# SRV para Matrix
_matrix._tcp.tudominio.com  IN  SRV  10 0 8448 tudominio.com.
```

**Nota:** El registro DKIM se te proporcionará durante la instalación.

### Paso 2: Descargar Scripts

```bash
# Como root
dnf -y install git
cd /usr/src

# Descargar scripts
git clone https://github.com/voztovoice/privacy_server.git
cd privacy_server

# Hacer ejecutables
chmod +x privacy_server_installer.sh
chmod +x create_user.sh
```

### Paso 3: Ejecutar Instalación

```bash
./privacy_server_installer.sh
```

El script te pedirá:
- ✅ Dominio principal
- ✅ Email administrativo
- ✅ IP pública (detecta automáticamente)
- ✅ Interfaz de red (detecta automáticamente, pide confirmación)
- ✅ Zona horaria
- ✅ Nombre de organización (certificados VPN)
- ✅ Confirmación de contraseña maestra

### Paso 4: Completar Configuración DNS

Después de la instalación, añade el registro DKIM mostrado:

```dns
default._domainkey.tudominio.com  IN  TXT  "v=DKIM1; k=rsa; p=CLAVE_PUBLICA_GENERADA"
```

También añade DMARC:

```dns
_dmarc.tudominio.com    IN  TXT     "v=DMARC1; p=quarantine; rua=mailto:postmaster@tudominio.com"
```

### Paso 5: Reiniciar SSH

**IMPORTANTE:** Antes de cerrar la sesión actual:

```bash
# Probar SSH en puerto 12999 desde otra terminal
ssh -p 12999 root@tu-servidor

# Si funciona, reiniciar sshd en la sesión original
systemctl restart sshd
```

### Paso 6: Crear Usuarios

```bash
./create_user.sh
```

El script creará el usuario en todos los servicios y enviará un email con las credenciales.

## 📁 Estructura de Archivos Generados

```
/etc/privacy_server/
├── config.env                      # Configuración principal
└── credentials/
    ├── admin_credentials.txt       # Credenciales del administrador
    └── users/
        ├── usuario1.txt
        └── usuario2.txt

/etc/openvpn/client/
└── tudominio.ovpn                  # Archivo VPN (copiado a Nextcloud de cada usuario)

/var/log/
├── privacy_server_install.log      # Log de instalación
├── openvpn.log                     # Logs OpenVPN
└── synapse/
    └── homeserver.log              # Logs Matrix

/home/data/                         # Datos de Nextcloud
└── usuario/
    └── files/
        └── VPN_Config.ovpn         # Archivo VPN del usuario
```

## 🔧 Configuración de Servicios

### SSH
- **Puerto**: 12999
- **Acceso**: Solo root con clave RSA
- **PasswordAuthentication**: Deshabilitado

### OpenVPN
- **Puerto**: 1194/UDP
- **Autenticación**: Usuario/contraseña Linux (PAM)
- **Archivo cliente**: Disponible en Nextcloud de cada usuario

### Email
| Servicio | Puerto | Seguridad |
|----------|--------|-----------|
| IMAP | 993 | SSL/TLS |
| SMTP | 587 | STARTTLS |
| Webmail | - | (Nextcloud Mail app) |

**Configuración cliente:**
- Servidor IMAP: mail.tudominio.com:993
- Servidor SMTP: mail.tudominio.com:587
- Usuario: nombre@tudominio.com
- Contraseña: contraseña del usuario

### Nextcloud
- **URL**: https://cloud.tudominio.com
- **Admin**: admin
- **Contraseña**: (contraseña maestra generada)
- **Datos**: /home/data

**Apps recomendadas:**
```bash
sudo -u apache php /var/www/nextcloud/occ app:install calendar
sudo -u apache php /var/www/nextcloud/occ app:install contacts
sudo -u apache php /var/www/nextcloud/occ app:install mail
```

### Matrix Synapse
- **Homeserver**: https://tudominio.com:8448
- **Usuario admin**: @admin:tudominio.com
- **Cliente recomendado**: Element (https://element.io)

**Crear usuarios adicionales:**
```bash
register_new_matrix_user -c /etc/synapse/homeserver.yaml
```

## 📧 Emails Automáticos

### Email de Instalación Completada
Se envía al email administrativo con:
- Resumen de servicios instalados
- Contraseña maestra
- URLs de acceso
- Tareas pendientes (configuración DNS)
- Ubicación de archivos importantes

### Email de Nuevo Usuario
Se envía al email personal del usuario con:
- Credenciales de todos los servicios
- Instrucciones de configuración para cada servicio
- Guía paso a paso para conectarse a VPN
- Recomendaciones de seguridad

## 🛠️ Comandos Útiles

### Ver estado de servicios
```bash
systemctl status openvpn-server@server
systemctl status postfix dovecot
systemctl status httpd php-fpm mariadb
systemctl status synapse coturn
```

### Ver logs
```bash
tail -f /var/log/openvpn.log
tail -f /var/log/maillog
tail -f /var/log/synapse/homeserver.log
tail -f /var/log/coturn/turnserver.log
tail -f /var/log/httpd/nextcloud-error_log
```

### Gestión Nextcloud
```bash
# Como usuario apache
sudo -u apache php /var/www/nextcloud/occ

# Listar usuarios
sudo -u apache php /var/www/nextcloud/occ user:list

# Reset contraseña
sudo -u apache php /var/www/nextcloud/occ user:resetpassword usuario

# Actualizar Nextcloud
sudo -u apache php /var/www/nextcloud/occ upgrade
```

### Email
```bash
# Ver cola de correo
mailq

# Test envío
echo "Test" | mail -s "Test Subject" destino@example.com

# Verificar DKIM
opendkim-testkey -d tudominio.com -s default -vvv
```

### Matrix
```bash
# Ver versión
curl https://tudominio.com:8448/_matrix/federation/v1/version

# Crear usuario
register_new_matrix_user -c /etc/synapse/homeserver.yaml
```

## 🔐 Seguridad

### Implementado por Defecto
- ✅ SSH solo puerto 12999, solo root, solo RSA key
- ✅ Firewall iptables con políticas DROP
- ✅ TLS 1.2+ en todos los servicios
- ✅ Certificados Let's Encrypt con renovación automática
- ✅ SPF, DKIM, DMARC para email
- ✅ SpamAssassin anti-spam
- ✅ Ciphers seguros configurados

### Recomendaciones Post-Instalación

**1. Cambiar contraseña maestra**
```bash
# MySQL
mysqladmin -u root -p password 'nueva_contraseña'

# Nextcloud admin
sudo -u apache php /var/www/nextcloud/occ user:resetpassword admin

# Matrix admin
# (requerirá reinstalación del usuario)
```

**2. Habilitar 2FA en Nextcloud**
```bash
sudo -u apache php /var/www/nextcloud/occ app:install twofactor_totp
```

**3. Instalar Fail2Ban**
```bash
dnf install -y fail2ban
systemctl enable --now fail2ban
```

**4. Configurar SELinux en enforcing** (opcional, después de verificar todo)
```bash
setenforce 1
sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
```

## 🔄 Mantenimiento

### Backups Automáticos

Crear script `/root/backup.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/backup/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Nextcloud
rsync -av /home/data/ "$BACKUP_DIR/nextcloud_data/"
mysqldump -u root -p"$MASTER_PASSWORD" nextcloud > "$BACKUP_DIR/nextcloud.sql"

# Matrix
sqlite3 /etc/synapse/homeserver.db ".backup '$BACKUP_DIR/matrix.db'"

# Email
tar -czf "$BACKUP_DIR/mail.tar.gz" /var/mail

# Configuraciones
tar -czf "$BACKUP_DIR/configs.tar.gz" /etc/privacy_server /etc/openvpn/easy-rsa

# Limpiar backups >30 días
find /backup -type d -mtime +30 -exec rm -rf {} +
```

Programar en cron:
```bash
crontab -e
# Añadir:
0 3 * * * /root/backup.sh
```

### Actualizaciones

```bash
# Sistema
dnf update -y

# Nextcloud
sudo -u apache php /var/www/nextcloud/occ upgrade

# Synapse
pip3 install --upgrade matrix-synapse
systemctl restart synapse

# Renovar certificados (automático, pero manual si es necesario)
certbot renew
```

## 🐛 Troubleshooting

### VPN no conecta

```bash
# Ver logs
tail -f /var/log/openvpn.log
systemctl status openvpn-server@server

# Verificar puerto abierto
ss -ulnp | grep 1194

# Verificar NAT
iptables -t nat -L -n -v
```

### Email no envía

```bash
# Ver cola
mailq

# Logs
tail -f /var/log/maillog

# Test SMTP
telnet localhost 25
```

### Nextcloud lento

```bash
# Habilitar Redis
dnf install -y redis
systemctl enable --now redis

# Editar /var/www/nextcloud/config/config.php
'memcache.local' => '\OC\Memcache\Redis',
'redis' => [
    'host' => 'localhost',
    'port' => 6379,
],
```

### Matrix federation no funciona

```bash
# Verificar SRV record
dig _matrix._tcp.tudominio.com SRV

# Test federación
curl https://tudominio.com:8448/_matrix/federation/v1/version

# Logs
tail -f /var/log/synapse/homeserver.log | grep -i federation
```

## 📊 Puertos Utilizados

| Puerto | Protocolo | Servicio |
|--------|-----------|----------|
| 12999 | TCP | SSH |
| 25 | TCP | SMTP |
| 80 | TCP | HTTP (redirect a HTTPS) |
| 110 | TCP | POP3 |
| 143 | TCP | IMAP |
| 443 | TCP | HTTPS (Nextcloud) |
| 465 | TCP | SMTPS |
| 587 | TCP | SMTP Submission |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 1194 | UDP | OpenVPN |
| 3478-3479 | UDP/TCP | TURN/STUN |
| 8448 | TCP | Matrix Federation |
| 49152-65535 | UDP | RTP (WebRTC) |

## 📞 Soporte

### Archivos de Credenciales
- Admin: `/etc/privacy_server/credentials/admin_credentials.txt`
- Usuarios: `/etc/privacy_server/credentials/users/`

### Logs Importantes
- Instalación: `/var/log/privacy_server_install.log`
- OpenVPN: `/var/log/openvpn.log`
- Email: `/var/log/maillog`
- Nextcloud: `/var/log/httpd/nextcloud-error_log`
- Matrix: `/var/log/synapse/homeserver.log`

### Testing Online
- Email: https://www.mail-tester.com
- DKIM: https://dkimvalidator.com
- SPF: https://mxtoolbox.com/spf.aspx
- Matrix Federation: https://federationtester.matrix.org

## 📝 Notas

### Diferencias con el Documento Original
- ✅ **Sin dependencia de expect** - Usa EASYRSA_BATCH
- ✅ **SSH solo root** - No crea usuarios admin con acceso SSH
- ✅ **Puerto SSH customizado** - 12999 en lugar de 2152
- ✅ **Email automatizado** - Envío automático de credenciales
- ✅ **Archivo VPN en Nextcloud** - Copiado automáticamente a cada usuario

### Compatibilidad
- AlmaLinux 10
- PHP 8.x
- MariaDB 10.x
- Nextcloud latest
- Matrix Synapse (vía pip3)

## 📄 Licencia

GPL-3.0

---

**Versión:** 2.0  
**Fecha:** 2026-01-02  
**Autor:** Privacy Server Project
