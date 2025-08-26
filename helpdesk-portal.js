require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const csurf = require('csurf');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// Seguridad
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'", "https://cdn.jsdelivr.net"],
      "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com"],
      "img-src": ["'self'", "data:"]
    }
  }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Archivos estáticos (logo)
app.use(express.static(path.join(__dirname, 'public')));

// Subidas de adjuntos
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_')}`)
});
const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } });
app.use('/uploads', express.static(uploadDir));

// Sesiones
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'change_me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: String(process.env.COOKIE_SECURE).toLowerCase() === 'true' }
}));

// CSRF
const csrfProtection = csurf();
app.use(csrfProtection);

// DB helpers
const db = new sqlite3.Database(path.join(__dirname, 'helpdesk.sqlite'));
function run(db, sql, params=[]) { return new Promise((res,rej)=>db.run(sql,params,function(err){ if(err)rej(err); else res(this);})); }
function get(db, sql, params=[]) { return new Promise((res,rej)=>db.get(sql,params,(err,row)=>{ if(err)rej(err); else res(row);})); }
function all(db, sql, params=[]) { return new Promise((res,rej)=>db.all(sql,params,(err,rows)=>{ if(err)rej(err); else res(rows);})); }

// Email
let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
}

// Inicializar DB
async function init() {
  await run(db, `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, email TEXT UNIQUE, password_hash TEXT, is_admin INTEGER DEFAULT 0,
    group_id INTEGER, created_at TEXT
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT, user_id INTEGER,
    subject TEXT, description TEXT, category TEXT DEFAULT 'General',
    sla_hours INTEGER DEFAULT 72, priority TEXT DEFAULT 'Media',
    status TEXT DEFAULT 'Abierto', group_id INTEGER, assignee_user_id INTEGER,
    created_at TEXT, updated_at TEXT
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, filename TEXT,
    path TEXT, size INTEGER, uploaded_at TEXT
  )`);

  // grupos por defecto
  for (const g of ['Soporte N1','Soporte N2','Infra','QA']) {
    try { await run(db, 'INSERT INTO groups (name) VALUES (?)', [g]); } catch {}
  }
  // usuarios demo
  const admin = await get(db, 'SELECT * FROM users WHERE email=?',['admin@example.com']);
  if (!admin) {
    const hash = await bcrypt.hash('Admin123!',12);
    await run(db,'INSERT INTO users (name,email,password_hash,is_admin,created_at) VALUES (?,?,?,?,datetime("now"))',
      ['Administrador','admin@example.com',hash,1]);
  }
  const client = await get(db, 'SELECT * FROM users WHERE email=?',['client@example.com']);
  if (!client) {
    const hash = await bcrypt.hash('Client123!',12);
    await run(db,'INSERT INTO users (name,email,password_hash,is_admin,created_at) VALUES (?,?,?,?,datetime("now"))',
      ['Cliente Demo','client@example.com',hash,0]);
  }
}

// Layout HTML
function layout(title, csrfToken, content, req) {
  const logged = !!req.session.user; const isAdmin = logged && req.session.user.is_admin===1;
  return `<!doctype html><html lang="es"><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body>
<nav class="navbar navbar-expand-lg bg-white"><div class="container">
  <a class="navbar-brand d-flex align-items-center gap-2" href="/">
    <img src="/logo.png" alt="Logo" height="32"><span>Helpdesk</span>
  </a>
  <div class="ms-auto">${logged?`<span class=me-3>Hola, ${req.session.user.name}${isAdmin?' (Admin)':''}</span><a class="btn btn-outline-secondary btn-sm" href="/logout">Salir</a>`:`<a class="btn btn-primary btn-sm" href="/login">Entrar</a>`}</div>
</div></nav>
<main class="container py-4">${content}</main>
</body></html>`;
}
function requireAuth(req,res,next){ if(!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req,res,next){ if(!req.session.user||req.session.user.is_admin!==1) return res.redirect('/'); next(); }

// Rutas
app.get('/', (req,res)=> req.session.user ? res.redirect(req.session.user.is_admin?'/admin':'/client') : res.redirect('/login'));

app.get('/login',(req,res)=>{
  const c=`<div class="row justify-content-center"><div class="col-md-6"><div class="card p-4">
    <h1 class="h5 mb-3">Acceso</h1>
    <form method=POST action=/login><input type=hidden name=_csrf value="${req.csrfToken()}">
      <div class=mb-3><label>Email</label><input class=form-control type=email name=email required></div>
      <div class=mb-3><label>Contraseña</label><input class=form-control type=password name=password required></div>
      <button class="btn btn-primary w-100">Entrar</button>
    </form>
    <small class="text-muted">Admin: admin@example.com / Admin123!<br>Cliente: client@example.com / Client123!</small>
  </div></div></div>`;
  res.send(layout('Login',req.csrfToken(),c,req));
});
app.post('/login',async(req,res)=>{
  const {email,password}=req.body;
  const u=await get(db,'SELECT * FROM users WHERE email=?',[email]);
  if(!u||!(await bcrypt.compare(password,u.password_hash)))
    return res.send(layout('Login',req.csrfToken(),'<div class="alert alert-danger">Credenciales inválidas</div>',req));
  req.session.user={id:u.id,name:u.name,is_admin:u.is_admin,group_id:u.group_id};
  res.redirect('/');
});
app.get('/logout',(req,res)=>req.session.destroy(()=>res.redirect('/login')));

// Cliente
app.get('/client',requireAuth,async(req,res)=>{
  if(req.session.user.is_admin) return res.redirect('/admin');
  const tickets=await all(db,'SELECT * FROM tickets WHERE user_id=? ORDER BY created_at DESC',[req.session.user.id]);
  const list=tickets.map(t=>`<tr><td>${t.uuid}</td><td>${t.subject}<div class=text-muted>${t.category} • ${t.priority}</div></td><td>${t.status}</td><td>${new Date(t.created_at).toLocaleString('es-ES')}</td></tr>`).join('');
  const c=`<div class="row">
    <div class="col-md-5"><div class="card p-3">
      <h2 class="h6">Nuevo ticket</h2>
      <form method=POST action=/tickets enctype=multipart/form-data><input type=hidden name=_csrf value="${req.csrfToken()}">
        <div class=mb-2><input class=form-control name=subject placeholder=Asunto required></div>
        <div class=mb-2><textarea class=form-control name=description placeholder=Descripción required></textarea></div>
        <div class=mb-2><input class=form-control name=category placeholder=Categoría value="General"></div>
        <div class=mb-2><select class=form-select name=priority><option>Alta</option><option selected>Media</option><option>Baja</option></select></div>
        <div class=mb-2><input class=form-control type=number name=sla_hours value=72 min=1 max=720></div>
        <div class=mb-2><input class=form-control type=file name=files multiple></div>
        <button class="btn btn-primary w-100">Crear</button>
      </form>
    </div></div>
    <div class="col-md-7"><div class="card p-3"><h2 class="h6">Mis tickets</h2>
      <table class="table">${list}</table></div></div>
  </div>`;
  res.send(layout('Cliente',req.csrfToken(),c,req));
});

// Crear ticket
app.post('/tickets',requireAuth,upload.array('files',5),async(req,res)=>{
  const {subject,description,priority,category,sla_hours}=req.body;
  const uuid=uuidv4().slice(0,8).toUpperCase(); const now=new Date().toISOString();
  const r=await run(db,`INSERT INTO tickets (uuid,user_id,subject,description,category,sla_hours,priority,status,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?, 'Abierto',?,?)`,[uuid,req.session.user.id,subject,description,category||'General',Number(sla_hours)||72,priority,now,now]);
  const ticketId=r.lastID;
  if(req.files) for(const f of req.files)
    await run(db,'INSERT INTO attachments (ticket_id,filename,path,size,uploaded_at) VALUES (?,?,?,?,datetime("now"))',
      [ticketId,f.originalname,`/uploads/${path.basename(f.path)}`,f.size]);
  res.redirect('/client');
});

// Admin
app.get('/admin',requireAdmin,async(req,res)=>{
  const tickets=await all(db,`SELECT t.*,u.name as user_name FROM tickets t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC`);
  const rows=tickets.map(t=>`<tr><td>${t.uuid}</td><td>${t.subject}</td><td>${t.user_name}</td><td>${t.priority}</td><td>${t.status}</td></tr>`).join('');
  const c=`<div class="card p-3"><h2 class="h6">Tickets</h2>
    <table class="table"><tr><th>ID</th><th>Asunto</th><th>Cliente</th><th>Prioridad</th><th>Estado</th></tr>${rows}</table></div>`;
  res.send(layout('Admin',req.csrfToken(),c,req));
});

init().then(()=>app.listen(PORT,()=>console.log(`Helpdesk listo en http://localhost:${PORT}`)));
