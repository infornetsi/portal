# Helpdesk Portal — AyudaInfornet (Render + Docker + DATA_DIR)

## Despliegue en Render (paso a paso)
1) Sube estos archivos a un repositorio de **GitHub** (en la raíz).
2) En Render → **New + → Web Service** → conecta tu GitHub y elige el repo.
3) Render detectará el **Dockerfile** automáticamente.
4) En **Environment** añade estas variables (copiando de `.env.example`):
   - `SESSION_SECRET` = valor largo y único
   - `COOKIE_SECURE=false` (ponlo `true` cuando tu dominio tenga SSL)
   - `DATA_DIR=/data`
   - SMTP: opcional; si no tienes proveedor, déjalo vacío
5) En **Disks** → **Add Disk**:
   - Mount Path: **/data**
   - Size: 1–5 GB
6) **Create Web Service** → Deploy. Debes ver en logs:  
   `Helpdesk portal listo ... (DATA_DIR=/data)`

## Dominio (DonDominio)
1) En Render → Settings → **Custom Domains** → añade `help.ayudainfornet.com`.
2) Render mostrará un **CNAME target** (ej. `xxxxx.onrender.com`).
3) En **DonDominio** → DNS de `ayudainfornet.com` → crea **CNAME**:
   - Host: `help`
   - Tipo: CNAME
   - Valor: el target que te dio Render
   - TTL: 300
4) Cuando Render marque el dominio como **Verified**, SSL se activa.
5) Cambia `COOKIE_SECURE=true` en **Environment** y redeploy.

## Usuarios demo
- Admin: `admin@example.com` / `Admin123!`
- Cliente: `client@example.com` / `Client123!`

## Backups
- Copia periódicamente el contenido de `/data` (DB y adjuntos).
