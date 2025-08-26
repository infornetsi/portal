# Helpdesk Portal - AyudaInfornet

## Despliegue rápido en Render
1. Sube este repo a GitHub (sube los archivos, no el zip).
2. En Render → New + → Web Service → conecta tu repo.
3. Runtime: Docker (usa el Dockerfile incluido).
4. Variables de entorno: copia de `.env.example`.
   - Cambia SESSION_SECRET por un valor aleatorio largo.
   - Si tu dominio ya tiene SSL, deja COOKIE_SECURE=true.
   - MAIL_FROM ya está listo para tu helpdesk.
   - SMTP_* rellénalo cuando tengas servidor de correo.
5. Añade un disco (1-5GB) montado en `/app` para persistencia.
6. Deploy → Render te da URL temporal.

## Dominio personalizado
1. En Render: Settings → Custom Domains → add `help.ayudainfornet.com`.
2. En DonDominio: crea un CNAME `help` apuntando al target de Render.
3. Render validará y activará SSL.
4. Tu portal quedará en https://help.ayudainfornet.com

## Usuarios demo
- Admin: admin@example.com / Admin123!
- Cliente: client@example.com / Client123!

## Logo
El logo está en /public/logo.png y se muestra en la cabecera.
