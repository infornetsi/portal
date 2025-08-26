FROM node:20
WORKDIR /app

# Copiamos primero package.json para aprovechar la cache
COPY package*.json ./
RUN npm install --omit=dev

# Copiamos TODO el repo
COPY . .

# Listado en build (debe mostrar helpdesk-portal.js)
RUN echo "== BUILD: contenido de /app ==" && ls -lah /app

# Creamos carpeta de adjuntos
RUN mkdir -p /app/uploads

ENV NODE_ENV=production
EXPOSE 3000

# Modo diagnóstico en runtime: listamos y luego arrancamos
CMD ["bash","-lc","echo '== RUNTIME: pwd ==' && pwd && echo '== RUNTIME: ls -lah /app ==' && ls -lah /app && echo '== RUNTIME: ls -lah /app/public ==' && ls -lah /app/public || true && node helpdesk-portal.js"]
