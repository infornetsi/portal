# AyudaInfornet Helpdesk v3 (completo)

## Despliegue en Render (Docker)
1. Sube estos archivos a un repo en GitHub (raíz).
2. Crea un Web Service en Render (detectará el Dockerfile).
3. Environment:
   - SESSION_SECRET = <cadena_larga>
   - COOKIE_SECURE = false
   - DATA_DIR = /data
   - (SMTP opcional para emails)
4. Disks → Add Disk → Mount Path: /data
5. Deploy → Logs: "Helpdesk portal listo ..."

## Admin inicial
- Email: mseoane@holainfornet.com
- Password: Infornet1138
Cámbiala en: /account/password

## Dominio
- Añade help.ayudainfornet.com como Custom Domain en Render y crea CNAME en DonDominio.
- Cuando SSL active → cambia COOKIE_SECURE=true y redeploy.
