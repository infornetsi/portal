/* AyudaInfornet Helpdesk v5 - Full */
"use strict";
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const csurf = require("csurf");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const nodemailer = require("nodemailer");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.json({ limit: "10mb" }));

// Static
app.use(express.static(path.join(__dirname, "public")));

// Ensure data dir
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Uploads
const uploadDir = path.join(DATA_DIR, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, String(Date.now()) + "-" + file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_"))
});
const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } });
app.use("/uploads", express.static(uploadDir));

// Sessions
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || "change_me_please",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: String(process.env.COOKIE_SECURE).toLowerCase() === "true" }
}));

// CSRF per-route
const csrfProtection = csurf();

// DB helpers
const db = new sqlite3.Database(path.join(DATA_DIR, "helpdesk.sqlite"));
try { db.configure && db.configure("busyTimeout", 5000); } catch(e) {}
function run(db, sql, params=[]) { return new Promise((res,rej)=>db.run(sql,params,function(err){ if(err)rej(err); else res(this);})); }
function get(db, sql, params=[]) { return new Promise((res,rej)=>db.get(sql,params,(err,row)=>{ if(err)rej(err); else res(row);})); }
function all(db, sql, params=[]) { return new Promise((res,rej)=>db.all(sql,params,(err,rows)=>{ if(err)rej(err); else res(rows);})); }

// Email
let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
}
async function sendMail(to, subject, text) {
  if (!transporter) return;
  try { await transporter.sendMail({ from: process.env.MAIL_FROM || "helpdesk@localhost", to, subject, text }); }
  catch(e){ console.error("[MAIL]", e && e.message ? e.message : e); }
}
async function notifyAdmins(subject, text) {
  const admins = await all(db, "SELECT email FROM users WHERE role='admin' AND approved=1");
  const emails = admins.map(x=>x.email);
  if (emails.length) await sendMail(emails.join(","), subject, text);
}
async function notifyCompany(company_id, subject, text) {
  if (!company_id) return;
  const sup = await all(db, "SELECT u.email FROM users u WHERE u.role='supervisor' AND u.approved=1 AND u.company_id=?", [company_id]);
  const emails = sup.map(x=>x.email);
  if (emails.length) await sendMail(emails.join(","), subject, text);
}

// --- Migrations + Roles seed ---
async function colExists(table, col) {
  const rows = await all(db, "PRAGMA table_info("+table+")");
  return rows.some(r => String(r.name).toLowerCase() === String(col).toLowerCase());
}
async function ensureColumn(table, colDef) {
  const [colName] = colDef.split(/\s+/,1);
  const exists = await colExists(table, colName);
  if (!exists) {
    console.log(">> MIGRATION: add column", table+"."+colName);
    await run(db, "ALTER TABLE "+table+" ADD COLUMN "+colDef);
  }
}
async function migrate() {
  await run(db, "PRAGMA foreign_keys = ON");
  await run(db, `CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    address TEXT, cif TEXT, email TEXT, phone TEXT, contract_type TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'pending',
    approved INTEGER NOT NULL DEFAULT 0,
    company_id INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES companies(id)
  )`);
  await ensureColumn("users","role TEXT DEFAULT 'pending'");
  await ensureColumn("users","approved INTEGER DEFAULT 0");
  await ensureColumn("users","company_id INTEGER");
  await ensureColumn("users","phone TEXT");
  await ensureColumn("users","created_at TEXT DEFAULT CURRENT_TIMESTAMP");

  await run(db, `CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT NOT NULL,
    company_id INTEGER, creator_user_id INTEGER NOT NULL,
    subject TEXT NOT NULL, description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'General',
    priority TEXT NOT NULL CHECK(priority IN ('Alta','Media','Baja')) DEFAULT 'Media',
    sla_hours INTEGER NOT NULL DEFAULT 24,
    status TEXT NOT NULL CHECK(status IN ('Abierto','En progreso','En espera','Resuelto','Cerrado')) DEFAULT 'Abierto',
    assignee_user_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES companies(id),
    FOREIGN KEY (creator_user_id) REFERENCES users(id),
    FOREIGN KEY (assignee_user_id) REFERENCES users(id)
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL,
    filename TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id)
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL,
    user_id INTEGER, is_private INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS status_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL,
    from_status TEXT, to_status TEXT NOT NULL, user_id INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id), FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  await run(db, `CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_key TEXT UNIQUE NOT NULL, name TEXT NOT NULL, perms TEXT NOT NULL
  )`);
  const count = await get(db, "SELECT COUNT(*) as c FROM roles");
  if (!count || !count.c) {
    const seed = [
      ["admin","Administrador", JSON.stringify({
        manage_all:true, view_all:true, assign:true, comment_private:true,
        change_status_any:true, approve_users:true, manage_roles:true, manage_companies:true,
        view_company:true, view_own:true, create_ticket:true, view_assigned:true, change_status_assigned:true
      })],
      ["technician","Técnico", JSON.stringify({
        view_assigned:true, change_status_assigned:true, comment_private:true, view_own:true
      })],
      ["supervisor","Supervisor", JSON.stringify({
        view_company:true, create_ticket:true, view_own:true
      })],
      ["user","Usuario", JSON.stringify({
        view_own:true, create_ticket:true
      })]
    ];
    for (const r of seed) await run(db, "INSERT INTO roles (role_key,name,perms) VALUES (?,?,?)", r);
  }
}

async function loadPerms(roleKey){
  const r = await get(db, "SELECT * FROM roles WHERE role_key=?", [roleKey]);
  return r ? JSON.parse(r.perms||"{}") : {};
}
function requireAuth(req,res,next){ if(!req.session.user) return res.redirect("/login"); next(); }
function requirePerm(perm){
  return async (req,res,next)=>{
    if (!req.session.user) return res.redirect("/login");
    if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
    if (!req.session.perms[perm] && !req.session.perms.manage_all) return res.status(403).send("No autorizado");
    next();
  };
}

// Init + admin seed
async function init() {
  await migrate();
  const existing = await get(db, "SELECT * FROM users WHERE role='admin' AND email=?", ["mseoane@holainfornet.com"]);
  if (!existing) {
    const hash = await bcrypt.hash("Infornet1138", 12);
    await run(db, "INSERT INTO users (name,email,phone,password_hash,role,approved) VALUES (?,?,?,?, 'admin', 1)", ["Administrador","mseoane@holainfornet.com","",hash]);
    console.log("===> Admin creado: mseoane@holainfornet.com / pass: Infornet1138");
  }
}

// Layout with sidebar
function layout(title, csrfToken, content, req) {
  const logged = !!(req.session && req.session.user);
  const isAdmin = logged && req.session.perms && req.session.perms.manage_all;
  return [
    "<!doctype html><html lang='es'><head>",
    "<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>",
    "<title>"+title+"</title>",
    "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>",
    "<style>:root{--brand:#c8a100}.btn-primary{background:var(--brand);border-color:var(--brand)}.btn-primary:hover{background:#b39000;border-color:#b39000}body{background:#f6f7fb}.card{border:none;border-radius:1rem;box-shadow:0 8px 22px rgba(0,0,0,.06)}.sidebar{min-height:100vh;background:#fff;box-shadow:0 8px 24px rgba(0,0,0,.06)}.sidebar a{display:block;padding:.65rem 1rem;color:#333;text-decoration:none;border-left:3px solid transparent}.sidebar a.active,.sidebar a:hover{background:#f2f2f2;border-left-color:var(--brand)}</style>",
    "</head><body>",
    "<nav class='navbar navbar-expand-lg bg-white shadow-sm'><div class='container-fluid'>",
    "<a class='navbar-brand d-flex align-items-center gap-2' href='/'><img src='/logo.png' height='28'><strong>AyudaInfornet</strong></a>",
    "<div class='ms-auto'>",
    (logged
      ? ("<a class='btn btn-outline-secondary btn-sm' href='/logout'>Salir</a>")
      : ("<a class='btn btn-outline-primary btn-sm me-2' href='/register'>Crear cuenta</a><a class='btn btn-primary btn-sm' href='/login'>Entrar</a>")
    ),
    "</div></div></nav>",
    "<div class='container-fluid'><div class='row'>",
    (isAdmin ? ("<aside class='col-md-2 p-0 sidebar'>"+
      "<div class='p-2 text-muted small'>Administración</div>"+
      "<a href='/admin' class='"+(title==='Admin'?'active':'')+"'>Panel</a>"+
      "<a href='/admin/tickets' class='"+(title.startsWith('Tickets')?'active':'')+"'>Tickets</a>"+
      "<a href='/admin/companies' class='"+(title.startsWith('Empresas')?'active':'')+"'>Empresas</a>"+
      "<a href='/admin/users' class='"+(title.startsWith('Usuarios')?'active':'')+"'>Usuarios</a>"+
      "<a href='/admin/technicians' class='"+(title.startsWith('Técnicos')?'active':'')+"'>Técnicos</a>"+
      "<a href='/admin/roles' class='"+(title.startsWith('Roles')?'active':'')+"'>Roles</a>"+
      "<a href='/admin/reports' class='"+(title.startsWith('Reportes')?'active':'')+"'>Reportes</a>"+
      "</aside>") : ""),
    "<main class='"+(isAdmin?'col-md-10':'col-12')+" p-3'>", content ,"</main>",
    "</div></div>",
    "<script>window.__CSRF__='"+csrfToken+"'</script>",
    "<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>",
    "</body></html>"
  ].join("");
}
function csrfTokenFor(req){ try { return req.csrfToken(); } catch(e){ return ""; } }

// Home
app.get("/", async (req,res)=>{
  if (!req.session.user) {
    const c = [
      "<div class='row justify-content-center'>",
      "<div class='col-md-7'><div class='card p-4 p-md-5 text-center'>",
      "<img src='/logo.png' alt='AyudaInfornet' height='48' class='mb-3'>",
      "<h1 class='h5 mb-3'>Portal de Soporte AyudaInfornet</h1>",
      "<p class='text-muted mb-4'>Abre, consulta y sigue tus incidencias en tiempo real.</p>",
      "<div class='d-flex justify-content-center gap-2'>",
      "<a class='btn btn-primary' href='/login'>Entrar</a>",
      "<a class='btn btn-outline-primary' href='/register'>Crear cuenta</a>",
      "</div>",
      "</div></div>",
      "</div>"
    ].join("");
    return res.send(layout("AyudaInfornet Helpdesk", "", c, req));
  }
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  const p = req.session.perms;
  if (p.manage_all) return res.redirect("/admin");
  if (p.view_assigned) return res.redirect("/tech");
  if (p.view_company) return res.redirect("/supervisor");
  return res.redirect("/client");
});

// Register/Login
app.get("/register", csrfProtection, (req,res)=>{
  const c = [
    "<div class='row justify-content-center'><div class='col-md-7'><div class='card p-4 p-md-5'>",
    "<h1 class='h5 mb-3'>Registro</h1>",
    "<form method='POST' action='/register'>",
    "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='mb-3'><label class='form-label'>Nombre</label><input class='form-control' name='name' required></div>",
    "<div class='mb-3'><label class='form-label'>Email</label><input class='form-control' type='email' name='email' required></div>",
    "<div class='mb-3'><label class='form-label'>Teléfono</label><input class='form-control' name='phone'></div>",
    "<div class='mb-3'><label class='form-label'>Contraseña</label><input class='form-control' type='password' name='password' required></div>",
    "<button class='btn btn-primary w-100'>Crear cuenta</button>",
    "<p class='text-muted small mt-3'>Tu cuenta quedará en espera hasta aprobación de un administrador.</p>",
    "</form></div></div></div>"
  ].join("");
  res.send(layout("Registro", req.csrfToken(), c, req));
});
app.post("/register", csrfProtection, async (req,res)=>{
  const {name,email,phone,password} = req.body;
  const exists = await get(db, "SELECT id FROM users WHERE email=?", [email]);
  if (exists) return res.status(400).send(layout("Registro", req.csrfToken(), "<div class='alert alert-danger'>Ese correo ya está registrado.</div>", req));
  const hash = await bcrypt.hash(password, 12);
  await run(db, "INSERT INTO users (name,email,phone,password_hash,role,approved) VALUES (?,?,?,?, 'pending', 0)", [name,email,phone||"",hash]);
  await notifyAdmins("[Helpdesk] Nueva solicitud de registro", "Se registró "+name+" <"+email+">");
  res.send(layout("Registro", req.csrfToken(), "<div class='alert alert-success'>Registro enviado. Te avisaremos cuando esté aprobado.</div><a class='btn btn-primary mt-3' href='/login'>Ir a login</a>", req));
});

app.get("/login", csrfProtection, (req,res)=>{
  const c = [
    "<div class='row justify-content-center'><div class='col-md-6'><div class='card p-4 p-md-5'>",
    "<h1 class='h5 mb-3'>Acceso</h1>",
    "<form method='POST' action='/login'>",
    "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='mb-3'><label class='form-label'>Email</label><input class='form-control' type='email' name='email' required></div>",
    "<div class='mb-3'><label class='form-label'>Contraseña</label><input class='form-control' type='password' name='password' required></div>",
    "<button class='btn btn-primary w-100'>Entrar</button>",
    "<div class='mt-3 text-center'><a href='/register'>Crear cuenta</a></div>",
    "</form></div></div></div>"
  ].join("");
  res.send(layout("Login", req.csrfToken(), c, req));
});
app.post("/login", csrfProtection, async (req,res)=>{
  const {email,password} = req.body;
  const u = await get(db, "SELECT * FROM users WHERE email=?", [email]);
  if (!u) return res.status(401).send(layout("Login", req.csrfToken(), "<div class='alert alert-danger'>Usuario o contraseña incorrectos.</div>", req));
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).send(layout("Login", req.csrfToken(), "<div class='alert alert-danger'>Usuario o contraseña incorrectos.</div>", req));
  if (!u.approved) return res.status(403).send(layout("Login", req.csrfToken(), "<div class='alert alert-warning'>Tu cuenta está pendiente de aprobación.</div>", req));
  req.session.user = { id:u.id, name:u.name, email:u.email, role:u.role, company_id:u.company_id || null };
  req.session.perms = await loadPerms(u.role);
  res.redirect("/");
});
app.get("/logout",(req,res)=> req.session.destroy(()=>res.redirect("/")));

// Account - change password
app.get("/account/password", requireAuth, csrfProtection, (req,res)=>{
  const c = [
    "<div class='row justify-content-center'><div class='col-md-6'><div class='card p-4'>",
    "<h1 class='h5 mb-3'>Cambiar contraseña</h1>",
    "<form method='POST' action='/account/password'>",
    "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='mb-3'><label class='form-label'>Contraseña actual</label><input class='form-control' type='password' name='current' required></div>",
    "<div class='mb-3'><label class='form-label'>Nueva contraseña</label><input class='form-control' type='password' name='next' required></div>",
    "<button class='btn btn-primary'>Actualizar</button>",
    "</form></div></div></div>"
  ].join("");
  res.send(layout("Cambiar contraseña", req.csrfToken(), c, req));
});
app.post("/account/password", requireAuth, csrfProtection, async (req,res)=>{
  const { current, next } = req.body;
  const u = await get(db, "SELECT * FROM users WHERE id=?", [req.session.user.id]);
  const ok = await bcrypt.compare(current, u.password_hash);
  if (!ok) return res.status(400).send(layout("Cambiar contraseña", req.csrfToken(), "<div class='alert alert-danger'>La contraseña actual no es correcta.</div>", req));
  const hash = await bcrypt.hash(next, 12);
  await run(db, "UPDATE users SET password_hash=? WHERE id=?", [hash, u.id]);
  res.send(layout("Cambiar contraseña", req.csrfToken(), "<div class='alert alert-success'>Contraseña actualizada.</div><a class='btn btn-primary mt-3' href='/'>Volver</a>", req));
});

// Permission helpers
function requireManageAll(req,res,next){ if(!req.session.perms) return res.redirect("/"); if(req.session.perms.manage_all) return next(); return res.status(403).send("No autorizado"); }
function requireApproveUsers(req,res,next){ if(!req.session.perms) return res.redirect("/"); if(req.session.perms.approve_users || req.session.perms.manage_all) return next(); return res.status(403).send("No autorizado"); }

// Admin dashboard (pendientes)
app.get("/admin", requireAuth, async (req,res)=>{
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  if (!req.session.perms.manage_all) return res.status(403).send("No autorizado");
  const pending = await all(db, "SELECT * FROM users WHERE approved=0 ORDER BY created_at");
  const companies = await all(db, "SELECT * FROM companies ORDER BY name");
  const roles = await all(db, "SELECT role_key,name FROM roles ORDER BY name");
  const pendingHtml = pending.length? "<ul class='list-group list-group-flush'>" + pending.map(p=>"<li class='list-group-item'><strong>"+p.name+"</strong> <span class='text-muted'>&lt;"+p.email+"&gt;</span>"+
    "<form class='mt-2' method='POST' action='/admin/approve'><input type='hidden' name='_csrf' value='"+csrfTokenFor(req)+"'><input type='hidden' name='user_id' value='"+p.id+"'>"+
    "<div class='row g-2 align-items-end'><div class='col-md-4'><label class='form-label small'>Rol</label><select class='form-select form-select-sm' name='role'>"+
    roles.map(r=>"<option value='"+r.role_key+"'>"+r.name+"</option>").join("")+
    "</select></div>"+
    "<div class='col-md-6'><label class='form-label small'>Empresa</label><select class='form-select form-select-sm' name='company_id'><option value=''>—</option>"+companies.map(c=>"<option value='"+c.id+"'>"+c.name+"</option>").join("")+"</select></div>"+
    "<div class='col-md-2'><button class='btn btn-sm btn-primary w-100'>Aprobar</button></div></div></form></li>").join("") + "</ul>" : "<div class='text-muted'>Sin pendientes</div>";
  const c = "<div class='card p-3'><h1 class='h6 mb-2'>Resumen</h1>"+pendingHtml+"</div>";
  res.send(layout("Admin", "", c, req));
});
app.post("/admin/approve", requireApproveUsers, csrfProtection, async (req,res)=>{
  const { user_id, role, company_id } = req.body;
  const cid = company_id ? Number(company_id) : null;
  await run(db, "UPDATE users SET role=?, approved=1, company_id=COALESCE(?, company_id) WHERE id=?", [role, cid, user_id]);
  const u = await get(db, "SELECT * FROM users WHERE id=?", [user_id]);
  await sendMail(u.email, "[Helpdesk] Cuenta aprobada", "Tu cuenta ha sido aprobada con rol: "+u.role);
  res.redirect("/admin");
});

// Companies CRUD
app.get("/admin/companies", requireManageAll, csrfProtection, async (req,res)=>{
  const list = await all(db, "SELECT * FROM companies ORDER BY name");
  const rows = list.map(c=>"<tr><td>"+c.name+"</td><td>"+(c.cif||"")+"</td><td>"+(c.email||"")+"</td><td>"+(c.phone||"")+"</td><td>"+(c.contract_type||"")+"</td>"+
    "<td><a class='btn btn-sm btn-outline-primary' href='/admin/companies/"+c.id+"/edit'>Editar</a> "+
    "<a class='btn btn-sm btn-outline-danger' href='/admin/companies/"+c.id+"/delete?_csrf="+req.csrfToken()+"' onclick='return confirm(\"¿Eliminar empresa?\")'>Eliminar</a></td></tr>").join("");
  const c = [
    "<div class='card p-3'><div class='d-flex justify-content-between align-items-center'><h1 class='h6 mb-0'>Empresas</h1><a class='btn btn-sm btn-primary' href='/admin/companies/new'>Nueva empresa</a></div>",
    "<div class='table-responsive mt-3'><table class='table table-sm align-middle'><thead><tr><th>Nombre</th><th>CIF</th><th>Email</th><th>Teléfono</th><th>Contrato</th><th></th></tr></thead><tbody>",
    rows or "<tr><td colspan='6' class='text-muted'>Sin empresas</td></tr>",
    "</tbody></table></div></div>"
  ].join("");
  res.send(layout("Empresas", req.csrfToken(), c, req));
});
app.get("/admin/companies/new", requireManageAll, csrfProtection, (req,res)=>{
  const c = [
    "<div class='card p-3'><h1 class='h6'>Nueva empresa</h1>",
    "<form method='POST' action='/admin/companies/new'><input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='row g-2'><div class='col-md-6'><label class='form-label'>Nombre</label><input class='form-control' name='name' required></div>",
    "<div class='col-md-6'><label class='form-label'>CIF</label><input class='form-control' name='cif'></div></div>",
    "<div class='row g-2 mt-2'><div class='col-md-6'><label class='form-label'>Email</label><input class='form-control' name='email' type='email'></div>",
    "<div class='col-md-6'><label class='form-label'>Teléfono</label><input class='form-control' name='phone'></div></div>",
    "<div class='mt-2'><label class='form-label'>Tipo de contrato</label><input class='form-control' name='contract_type'></div>",
    "<div class='mt-2'><label class='form-label'>Dirección</label><input class='form-control' name='address'></div>",
    "<button class='btn btn-primary mt-3'>Crear</button>",
    "</form></div>"
  ].join("");
  res.send(layout("Empresas - nueva", req.csrfToken(), c, req));
});
app.post("/admin/companies/new", requireManageAll, csrfProtection, async (req,res)=>{
  const { name, cif, email, phone, contract_type, address } = req.body;
  await run(db, "INSERT INTO companies (name,address,cif,email,phone,contract_type) VALUES (?,?,?,?,?,?)", [name,address||"",cif||"",email||"",phone||"",contract_type||""]);
  res.redirect("/admin/companies");
});
app.get("/admin/companies/:id/edit", requireManageAll, csrfProtection, async (req,res)=>{
  const cpy = await get(db, "SELECT * FROM companies WHERE id=?", [req.params.id]);
  if (!cpy) return res.status(404).send("No encontrado");
  const c = [
    "<div class='card p-3'><h1 class='h6'>Editar empresa</h1>",
    "<form method='POST' action='/admin/companies/"+cpy.id+"/edit'><input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='row g-2'><div class='col-md-6'><label class='form-label'>Nombre</label><input class='form-control' name='name' value='"+cpy.name+"' required></div>",
    "<div class='col-md-6'><label class='form-label'>CIF</label><input class='form-control' name='cif' value='"+(cpy.cif||"")+"'></div></div>",
    "<div class='row g-2 mt-2'><div class='col-md-6'><label class='form-label'>Email</label><input class='form-control' name='email' value='"+(cpy.email||"")+"'></div>",
    "<div class='col-md-6'><label class='form-label'>Teléfono</label><input class='form-control' name='phone' value='"+(cpy.phone||"")+"'></div></div>",
    "<div class='mt-2'><label class='form-label'>Tipo de contrato</label><input class='form-control' name='contract_type' value='"+(cpy.contract_type||"")+"'></div>",
    "<div class='mt-2'><label class='form-label'>Dirección</label><input class='form-control' name='address' value='"+(cpy.address||"")+"'></div>",
    "<button class='btn btn-primary mt-3'>Guardar</button>",
    "</form></div>"
  ].join("");
  res.send(layout("Empresas - editar", req.csrfToken(), c, req));
});
app.post("/admin/companies/:id/edit", requireManageAll, csrfProtection, async (req,res)=>{
  const { name, cif, email, phone, contract_type, address } = req.body;
  await run(db, "UPDATE companies SET name=?, address=?, cif=?, email=?, phone=?, contract_type=? WHERE id=?", [name,address||"",cif||"",email||"",phone||"",contract_type||"", req.params.id]);
  res.redirect("/admin/companies");
});
app.get("/admin/companies/:id/delete", requireManageAll, csrfProtection, async (req,res)=>{
  await run(db, "DELETE FROM companies WHERE id=?", [req.params.id]);
  await run(db, "UPDATE users SET company_id=NULL WHERE company_id=?", [req.params.id]);
  res.redirect("/admin/companies");
});

// Users management
app.get("/admin/users", requireApproveUsers, csrfProtection, async (req,res)=>{
  const users = await all(db, "SELECT u.*, c.name as company_name FROM users u LEFT JOIN companies c ON c.id=u.company_id ORDER BY u.created_at DESC LIMIT 500");
  const companies = await all(db, "SELECT id,name FROM companies ORDER BY name");
  const roles = await all(db, "SELECT role_key,name FROM roles ORDER BY name");
  const rows = users.map(u=>"<tr><td>"+u.name+"</td><td>"+u.email+"</td><td>"+(u.company_name||"—")+"</td><td>"+u.role+"</td><td>"+(u.approved?"Sí":"No")+"</td><td>"+
    "<form method='POST' action='/admin/users/"+u.id+"/update' class='d-flex gap-1'>"+
    "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>"+
    "<select name='role' class='form-select form-select-sm'>"+roles.map(r=>"<option value='"+r.role_key+"'"+(r.role_key===u.role?" selected":"")+">"+r.name+"</option>").join("")+"</select>"+
    "<select name='company_id' class='form-select form-select-sm'><option value=''>—</option>"+companies.map(c=>"<option value='"+c.id+"'"+(String(c.id)===String(u.company_id||"")?" selected":"")+">"+c.name+"</option>").join("")+"</select>"+
    "<select name='approved' class='form-select form-select-sm'><option value='0'"+(u.approved? "":" selected")+">No</option><option value='1'"+(u.approved? " selected":"")+">Sí</option></select>"+
    "<button class='btn btn-sm btn-primary'>Guardar</button>"+
    "<a class='btn btn-sm btn-outline-danger' href='/admin/users/"+u.id+"/delete?_csrf="+req.csrfToken()+"' onclick='return confirm(\"¿Eliminar usuario?\")'>Eliminar</a>"+
    "</form></td></tr>").join("");
  const c = [
    "<div class='d-flex justify-content-between align-items-center mb-2'><h1 class='h6 mb-0'>Usuarios</h1><a class='btn btn-sm btn-primary' href='/admin/users/new'>Nuevo usuario</a></div>",
    "<div class='card p-3'>",
    "<div class='table-responsive'><table class='table table-sm align-middle'><thead><tr><th>Nombre</th><th>Email</th><th>Empresa</th><th>Rol</th><th>Aprobado</th><th>Acciones</th></tr></thead><tbody>",
    rows or "",
    "</tbody></table></div>",
    "</div>"
  ].join("");
  res.send(layout("Usuarios", req.csrfToken(), c, req));
});
app.get("/admin/users/new", requireApproveUsers, csrfProtection, async (req,res)=>{
  const companies = await all(db, "SELECT id,name FROM companies ORDER BY name");
  const roles = await all(db, "SELECT role_key,name FROM roles ORDER BY name");
  const c = [
    "<div class='card p-3'><h1 class='h6'>Nuevo usuario</h1>",
    "<form method='POST' action='/admin/users/new'><input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='row g-2'><div class='col-md-4'><label class='form-label'>Nombre</label><input class='form-control' name='name' required></div>",
    "<div class='col-md-4'><label class='form-label'>Email</label><input class='form-control' name='email' type='email' required></div>",
    "<div class='col-md-4'><label class='form-label'>Teléfono</label><input class='form-control' name='phone'></div></div>",
    "<div class='row g-2 mt-2'><div class='col-md-4'><label class='form-label'>Rol</label><select class='form-select' name='role'>"+roles.map(r=>"<option value='"+r.role_key+"'>"+r.name+"</option>").join("")+"</select></div>",
    "<div class='col-md-4'><label class='form-label'>Empresa</label><select class='form-select' name='company_id'><option value=''>—</option>"+companies.map(c=>"<option value='"+c.id+"'>"+c.name+"</option>").join("")+"</select></div>",
    "<div class='col-md-4'><label class='form-label'>Contraseña</label><input class='form-control' name='password' type='password' required></div></div>",
    "<div class='form-check mt-2'><input class='form-check-input' type='checkbox' name='approved' id='ap'><label class='form-check-label' for='ap'>Aprobado</label></div>",
    "<button class='btn btn-primary mt-3'>Crear</button>",
    "</form></div>"
  ].join("");
  res.send(layout("Usuarios - nuevo", req.csrfToken(), c, req));
});
app.post("/admin/users/new", requireApproveUsers, csrfProtection, async (req,res)=>{
  const { name, email, phone, role, company_id, password, approved } = req.body;
  const hash = await bcrypt.hash(password, 12);
  await run(db, "INSERT INTO users (name,email,phone,password_hash,role,approved,company_id) VALUES (?,?,?,?,?,?,?)", [name,email,phone||"",hash,role, approved?1:0, company_id||null]);
  res.redirect("/admin/users");
});
app.post("/admin/users/:id/update", requireApproveUsers, csrfProtection, async (req,res)=>{
  const id = req.params.id;
  const { role, company_id, approved } = req.body;
  await run(db, "UPDATE users SET role=?, company_id=?, approved=? WHERE id=?", [role || null, company_id || null, approved ? 1 : 0, id]);
  res.redirect("/admin/users");
});
app.get("/admin/users/:id/delete", requireApproveUsers, csrfProtection, async (req,res)=>{
  const id = req.params.id;
  await run(db, "DELETE FROM users WHERE id=?", [id]);
  res.redirect("/admin/users");
});

// Technicians
app.get("/admin/technicians", requireManageAll, csrfProtection, async (req,res)=>{
  const techs = await all(db, "SELECT u.*, c.name as company_name FROM users u LEFT JOIN companies c ON c.id=u.company_id WHERE u.role='technician' ORDER BY u.name");
  const users = await all(db, "SELECT id,name,email FROM users WHERE role!='technician' ORDER BY name LIMIT 200");
  const rows = techs.map(t=>"<tr><td>"+t.name+"</td><td>"+t.email+"</td><td>"+(t.phone||"")+"</td><td>"+(t.company_name||"—")+"</td></tr>").join("");
  const c = [
    "<div class='d-flex justify-content-between align-items-center mb-2'><h1 class='h6 mb-0'>Técnicos</h1>",
    "<form class='d-flex gap-2' method='POST' action='/admin/technicians/promote'><input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>"+
    "<select class='form-select form-select-sm' name='user_id'>"+users.map(u=>"<option value='"+u.id+"'>"+u.name+" ("+u.email+")</option>").join("")+"</select>"+
    "<button class='btn btn-sm btn-primary'>Convertir en Técnico</button></form></div>",
    "<div class='card p-3'><div class='table-responsive'><table class='table table-sm align-middle'><thead><tr><th>Nombre</th><th>Email</th><th>Teléfono</th><th>Empresa</th></tr></thead><tbody>",
    rows or "<tr><td colspan='4' class='text-muted'>Sin técnicos</td></tr>",
    "</tbody></table></div></div>"
  ].join("");
  res.send(layout("Técnicos", req.csrfToken(), c, req));
});
app.post("/admin/technicians/promote", requireManageAll, csrfProtection, async (req,res)=>{
  const { user_id } = req.body;
  await run(db, "UPDATE users SET role='technician', approved=1 WHERE id=?", [user_id]);
  res.redirect("/admin/technicians");
});

// Roles CRUD (igual que arriba)
app.get("/admin/roles", requireManageAll, csrfProtection, async (req,res)=>{
  const roles = await all(db, "SELECT * FROM roles ORDER BY name");
  const rows = roles.map(r=>"<tr><td><code>"+r.role_key+"</code></td><td>"+r.name+"</td><td><pre class='small mb-0'>"+String(r.perms).replace(/</g,"&lt;")+"</pre></td><td>"+
    "<a class='btn btn-sm btn-outline-primary' href='/admin/roles/"+r.id+"/edit'>Editar</a> "+
    (r.role_key==="admin" ? "" : "<a class='btn btn-sm btn-outline-danger' href='/admin/roles/"+r.id+"/delete?_csrf="+csrfTokenFor(req)+"' onclick='return confirm(\"¿Eliminar rol?\")'>Eliminar</a>")+
    "</td></tr>").join("");
  const c = [
    "<div class='card p-3'>",
    "<div class='d-flex justify-content-between align-items-center'><h1 class='h6 mb-0'>Roles</h1><a class='btn btn-sm btn-primary' href='/admin/roles/new'>Nuevo rol</a></div>",
    "<div class='table-responsive mt-3'><table class='table table-sm align-middle'><thead><tr><th>Clave</th><th>Nombre</th><th>Permisos</th><th></th></tr></thead><tbody>",
    rows || "<tr><td colspan='4' class='text-muted'>Sin roles</td></tr>",
    "</tbody></table></div>",
    "<p class='text-muted small mt-3'>Permisos: manage_all, view_all, assign, comment_private, change_status_any, approve_users, manage_roles, manage_companies, view_company, view_assigned, view_own, create_ticket, change_status_assigned</p>",
    "</div>"
  ].join("");
  res.send(layout("Roles", req.csrfToken(), c, req));
});
app.get("/admin/roles/new", requireManageAll, csrfProtection, (req,res)=>{
  const c = [
    "<div class='card p-3'>",
    "<h1 class='h6'>Nuevo rol</h1>",
    "<form method='POST' action='/admin/roles/new'>",
    "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='mb-2'><label class='form-label'>Clave</label><input class='form-control' name='role_key' required></div>",
    "<div class='mb-2'><label class='form-label'>Nombre</label><input class='form-control' name='name' required></div>",
    "<div class='mb-2'><label class='form-label'>Permisos (JSON)</label><textarea class='form-control' name='perms' rows='8'>{\"view_own\":true}</textarea></div>",
    "<button class='btn btn-primary'>Crear</button>",
    "</form></div>"
  ].join("");
  res.send(layout("Nuevo rol", req.csrfToken(), c, req));
});
app.post("/admin/roles/new", requireManageAll, csrfProtection, async (req,res)=>{
  const { role_key, name, perms } = req.body;
  let parsed = {};
  try { parsed = JSON.parse(perms || "{}"); } catch(e){ return res.status(400).send("JSON inválido en permisos"); }
  await run(db, "INSERT INTO roles (role_key,name,perms) VALUES (?,?,?)", [role_key.trim(), name.trim(), JSON.stringify(parsed)]);
  res.redirect("/admin/roles");
});
app.get("/admin/roles/:id/edit", requireManageAll, csrfProtection, async (req,res)=>{
  const r = await get(db, "SELECT * FROM roles WHERE id=?", [req.params.id]);
  if (!r) return res.status(404).send("Rol no encontrado");
  const c = [
    "<div class='card p-3'>",
    "<h1 class='h6'>Editar rol</h1>",
    "<form method='POST' action='/admin/roles/"+r.id+"/edit'>",
    "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='mb-2'><label class='form-label'>Clave</label><input class='form-control' name='role_key' value='"+r.role_key+"' required "+(r.role_key==="admin"?"readonly":"")+"></div>",
    "<div class='mb-2'><label class='form-label'>Nombre</label><input class='form-control' name='name' value='"+r.name+"' required></div>",
    "<div class='mb-2'><label class='form-label'>Permisos (JSON)</label><textarea class='form-control' name='perms' rows='10'>"+String(r.perms).replace(/</g,"&lt;")+"</textarea></div>",
    "<button class='btn btn-primary'>Guardar</button>",
    "</form></div>"
  ].join("");
  res.send(layout("Editar rol", req.csrfToken(), c, req));
});
app.post("/admin/roles/:id/edit", requireManageAll, csrfProtection, async (req,res)=>{
  const { role_key, name, perms } = req.body;
  let parsed = {};
  try { parsed = JSON.parse(perms || "{}"); } catch(e){ return res.status(400).send("JSON inválido en permisos"); }
  const r = await get(db, "SELECT * FROM roles WHERE id=?", [req.params.id]);
  if (!r) return res.status(404).send("No encontrado");
  if (r.role_key==="admin" && role_key !== "admin") return res.status(400).send("No se puede renombrar el rol admin");
  await run(db, "UPDATE roles SET role_key=?, name=?, perms=? WHERE id=?", [role_key.trim(), name.trim(), JSON.stringify(parsed), req.params.id]);
  res.redirect("/admin/roles");
});
app.get("/admin/roles/:id/delete", requireManageAll, csrfProtection, async (req,res)=>{
  const r = await get(db, "SELECT * FROM roles WHERE id=?", [req.params.id]);
  if (!r) return res.status(404).send("No encontrado");
  if (r.role_key==="admin") return res.status(400).send("No se puede eliminar el rol admin");
  const inUse = await get(db, "SELECT COUNT(*) as c FROM users WHERE role=?", [r.role_key]);
  if (inUse.c > 0) return res.status(400).send("Rol en uso por usuarios, no se puede eliminar");
  await run(db, "DELETE FROM roles WHERE id=?", [req.params.id]);
  res.redirect("/admin/roles");
});

// Admin Tickets list + assign
app.get("/admin/tickets", requireManageAll, csrfProtection, async (req,res)=>{
  const { q, status, priority, company_id, assignee } = req.query;
  const where=[]; const params=[];
  if (q){ where.push("(t.subject LIKE ? OR t.description LIKE ? OR t.uuid LIKE ?)"); params.push("%"+q+"%","%"+q+"%","%"+q+"%"); }
  if (status){ where.push("t.status=?"); params.push(status); }
  if (priority){ where.push("t.priority=?"); params.push(priority); }
  if (company_id){ where.push("t.company_id=?"); params.push(company_id); }
  if (assignee){ where.push("t.assignee_user_id=?"); params.push(assignee); }
  const whereSql = where.length? "WHERE "+where.join(" AND ") : "";
  const tickets = await all(db,
    "SELECT t.*, c.name as company_name, u.name as creator_name, a.name as assignee_name "+
    "FROM tickets t LEFT JOIN companies c ON c.id=t.company_id LEFT JOIN users u ON u.id=t.creator_user_id LEFT JOIN users a ON a.id=t.assignee_user_id "+
    whereSql+" ORDER BY t.created_at DESC LIMIT 200", params);
  const companies = await all(db, "SELECT id,name FROM companies ORDER BY name");
  const techs = await all(db, "SELECT id,name FROM users WHERE role='technician' AND approved=1 ORDER BY name");
  const rows = tickets.map(t=>"<tr>"+
      "<td><span class='badge text-bg-light'>"+t.uuid+"</span></td>"+
      "<td><a href='/tickets/"+t.id+"'>"+t.subject+"</a></td>"+
      "<td>"+(t.company_name||"—")+"</td>"+
      "<td>"+t.priority+"</td>"+
      "<td>"+t.status+"</td>"+
      "<td>"+(t.assignee_name||"—")+"</td>"+
      "<td>"+
        "<form method='POST' action='/admin/tickets/"+t.id+"/assign' class='d-flex gap-2'>"+
        "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>"+
        "<select class='form-select form-select-sm' name='assignee_user_id'><option value=''>—</option>"+techs.map(te=>"<option value='"+te.id+"'"+(t.assignee_user_id===te.id?" selected":"")+">"+te.name+"</option>").join("")+"</select>"+
        "<button class='btn btn-primary btn-sm'>Asignar</button>"+
        "</form>"+
      "</td>"+
    "</tr>").join("");
  const c = [
    "<div class='card p-3'>",
    "<h1 class='h5 mb-3'>Tickets (asignación)</h1>",
    "<form class='row g-2 mb-3' method='GET'>",
    "<div class='col-md-3'><input class='form-control' name='q' placeholder='Buscar' value='"+(req.query.q||"")+"'></div>",
    "<div class='col-md-2'><select class='form-select' name='status'><option value=''>Estado</option>"+["Abierto","En progreso","En espera","Resuelto","Cerrado"].map(s=>"<option"+(s===status?" selected":"")+">"+s+"</option>").join("")+"</select></div>",
    "<div class='col-md-2'><select class='form-select' name='priority'><option value=''>Prioridad</option>"+["Alta","Media","Baja"].map(p=>"<option"+(p===priority?" selected":"")+">"+p+"</option>").join("")+"</select></div>",
    "<div class='col-md-2'><select class='form-select' name='company_id'><option value=''>Empresa</option>"+companies.map(x=>"<option value='"+x.id+"'"+(String(x.id)===String(company_id||"")?" selected":"")+">"+x.name+"</option>").join("")+"</select></div>",
    "<div class='col-md-2'><select class='form-select' name='assignee'><option value=''>Técnico</option>"+techs.map(x=>"<option value='"+x.id+"'"+(String(x.id)===String(assignee||"")?" selected":"")+">"+x.name+"</option>").join("")+"</select></div>",
    "<div class='col-md-1'><button class='btn btn-secondary w-100'>Filtrar</button></div>",
    "</form>",
    "<div class='table-responsive'><table class='table table-sm align-middle'><thead><tr><th>ID</th><th>Asunto</th><th>Empresa</th><th>Prioridad</th><th>Estado</th><th>Asignado</th><th>Gestión</th></tr></thead><tbody>",
    (rows || ""),
    "</tbody></table></div>",
    "</div>"
  ].join("");
  res.send(layout("Tickets (admin)", req.csrfToken(), c, req));
});
app.post("/admin/tickets/:id/assign", requireManageAll, csrfProtection, async (req,res)=>{
  const id = req.params.id; const assignee = req.body.assignee_user_id || null;
  await run(db, "UPDATE tickets SET assignee_user_id=?, updated_at=datetime('now') WHERE id=?", [assignee, id]);
  const t = await get(db, "SELECT * FROM tickets WHERE id=?", [id]);
  if (assignee) {
    const tech = await get(db, "SELECT * FROM users WHERE id=?", [assignee]);
    await sendMail(tech.email, "[Helpdesk] Ticket asignado "+t.uuid, "Se te ha asignado el ticket: "+t.subject);
  }
  await notifyAdmins("[Helpdesk] Ticket "+t.uuid+" asignado", "Se ha asignado el ticket.");
  if (t.company_id) await notifyCompany(t.company_id, "[Helpdesk] Ticket actualizado "+t.uuid, "Se ha actualizado un ticket de su empresa.");
  res.redirect("/admin/tickets");
});

// Portales
app.get("/client", requireAuth, csrfProtection, async (req,res)=>{
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  const mine = await all(db, "SELECT * FROM tickets WHERE creator_user_id=? ORDER BY created_at DESC", [req.session.user.id]);
  const list = mine.map(t=>"<tr><td><span class='badge text-bg-light'>"+t.uuid+"</span></td><td><a href='/tickets/"+t.id+"'>"+t.subject+"</a></td><td>"+t.status+"</td><td>"+new Date(t.created_at).toLocaleString("es-ES")+"</td></tr>").join("");
  const canCreate = req.session.perms.create_ticket;
  const form = !canCreate ? "<div class='alert alert-warning'>Tu rol no puede crear tickets.</div>" :
    "<form method='POST' action='/tickets' enctype='multipart/form-data'><input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>"+
    "<div class='mb-2'><label class='form-label'>Asunto</label><input class='form-control' name='subject' required maxlength='120'></div>"+
    "<div class='mb-2'><label class='form-label'>Descripción</label><textarea class='form-control' name='description' rows='5' required></textarea></div>"+
    "<div class='mb-2'><label class='form-label'>Categoría</label><input class='form-control' name='category' value='General' required></div>"+
    "<div class='mb-2'><label class='form-label'>Prioridad</label><select class='form-select' name='priority'><option>Alta</option><option selected>Media</option><option>Baja</option></select></div>"+
    "<div class='mb-2'><label class='form-label'>SLA (horas)</label><input type='number' class='form-control' name='sla_hours' value='24' min='1' max='720'></div>"+
    "<div class='mb-2'><label class='form-label'>Adjuntos</label><input class='form-control' type='file' name='files' multiple></div>"+
    "<button class='btn btn-primary w-100'>Crear</button></form>";
  const c = [
    "<div class='row g-3'>",
      "<div class='col-md-5'><div class='card p-3'>",
        "<h2 class='h6'>Nuevo ticket</h2>", form,
      "</div></div>",
      "<div class='col-md-7'><div class='card p-3'>",
        "<h2 class='h6'>Mis tickets</h2>",
        "<div class='table-responsive'><table class='table table-sm align-middle'><thead><tr><th>ID</th><th>Asunto</th><th>Estado</th><th>Creado</th></tr></thead><tbody>"+(list || "")+"</tbody></table></div>",
      "</div></div>",
    "</div>"
  ].join("");
  res.send(layout("Cliente", req.csrfToken(), c, req));
});

app.get("/supervisor", requireAuth, csrfProtection, async (req,res)=>{
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  if (!req.session.perms.view_company && !req.session.perms.manage_all) return res.status(403).send("No autorizado");
  const cid = req.session.user.company_id;
  const tickets = await all(db, "SELECT * FROM tickets WHERE company_id=? ORDER BY created_at DESC", [cid]);
  const rows = tickets.map(t=>"<tr><td><span class='badge text-bg-light'>"+t.uuid+"</span></td><td><a href='/tickets/"+t.id+"'>"+t.subject+"</a></td><td>"+t.priority+"</td><td>"+t.status+"</td></tr>").join("");
  const c = "<div class='card p-3'><h2 class='h6'>Tickets de mi empresa</h2><div class='table-responsive'><table class='table table-sm'><thead><tr><th>ID</th><th>Asunto</th><th>Prioridad</th><th>Estado</th></tr></thead><tbody>"+(rows || "")+"</tbody></table></div></div>";
  res.send(layout("Supervisor", req.csrfToken(), c, req));
});

app.get("/tech", requireAuth, csrfProtection, async (req,res)=>{
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  if (!req.session.perms.view_assigned && !req.session.perms.manage_all) return res.status(403).send("No autorizado");
  const myid = req.session.user.id;
  const tickets = await all(db, "SELECT * FROM tickets WHERE assignee_user_id=? ORDER BY updated_at DESC", [myid]);
  const rows = tickets.map(t=>"<tr><td><span class='badge text-bg-light'>"+t.uuid+"</span></td><td><a href='/tickets/"+t.id+"'>"+t.subject+"</a></td><td>"+t.priority+"</td><td>"+t.status+"</td></tr>").join("");
  const c = "<div class='card p-3'><h2 class='h6'>Mis tickets asignados</h2><div class='table-responsive'><table class='table table-sm'><thead><tr><th>ID</th><th>Asunto</th><th>Prioridad</th><th>Estado</th></tr></thead><tbody>"+(rows || "")+"</tbody></table></div></div>";
  res.send(layout("Técnicos", req.csrfToken(), c, req));
});

// Create ticket
app.post("/tickets", requireAuth, upload.array("files", 5), csrfProtection, async (req,res)=>{
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  if (!req.session.perms.create_ticket && !req.session.perms.manage_all) return res.status(403).send("No autorizado");
  const { subject, description, category, priority, sla_hours } = req.body;
  const creator = req.session.user.id;
  const u = await get(db, "SELECT company_id FROM users WHERE id=?", [creator]);
  const company_id = u ? u.company_id : null;
  const uuid = uuidv4().slice(0,8).toUpperCase();
  const result = await run(db, "INSERT INTO tickets (uuid,company_id,creator_user_id,subject,description,category,priority,sla_hours,status,assignee_user_id) VALUES (?,?,?,?,?,?,?,?, 'Abierto', NULL)",
    [uuid, company_id, creator, subject, description, category||"General", priority||"Media", Number(sla_hours)||24]);
  const ticketId = result.lastID;
  if (req.files && req.files.length) {
    for (const f of req.files) {
      await run(db, "INSERT INTO attachments (ticket_id,filename,path,size) VALUES (?,?,?,?)", [ticketId, f.originalname, "/uploads/"+path.basename(f.path), f.size]);
    }
  }
  await notifyAdmins("[Helpdesk] Ticket creado "+uuid, "Se ha creado un nuevo ticket: "+subject);
  if (company_id) await notifyCompany(company_id, "[Helpdesk] Ticket creado "+uuid, "Se ha creado un ticket en su empresa.");
  res.redirect("/tickets/"+ticketId);
});

// Ticket detail + comments + status
app.get("/tickets/:id", requireAuth, csrfProtection, async (req,res)=>{
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  const id = req.params.id;
  const t = await get(db, "SELECT t.*, u.name as creator_name, a.name as assignee_name, c.name as company_name FROM tickets t LEFT JOIN users u ON u.id=t.creator_user_id LEFT JOIN users a ON a.id=t.assignee_user_id LEFT JOIN companies c ON c.id=t.company_id WHERE t.id=?", [id]);
  if (!t) return res.status(404).send("Ticket no encontrado");
  const perms = req.session.perms;
  const u = req.session.user;
  let allowed = false;
  if (perms.manage_all || perms.view_all) allowed = true;
  else if (perms.view_assigned && t.assignee_user_id===u.id) allowed = true;
  else if (perms.view_company && t.company_id===u.company_id) allowed = true;
  else if (perms.view_own && t.creator_user_id===u.id) allowed = true;
  if (!allowed) return res.status(403).send("No autorizado");

  const atts = await all(db, "SELECT * FROM attachments WHERE ticket_id=?", [id]);
  const comments = await all(db, "SELECT c.*, u.name as user_name FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE ticket_id=? ORDER BY created_at", [id]);
  const canPrivate = perms.comment_private || perms.manage_all;
  const commentsHtml = comments.filter(c=> (c.is_private? canPrivate : true)).map(c=>"<div class='p-2 border rounded mb-2 "+(c.is_private?"bg-light":"")+"'><div class='small text-muted'>"+(c.user_name||"")+" • "+new Date(c.created_at).toLocaleString("es-ES")+(c.is_private?" • Privado":"")+"</div><div>"+String(c.body).replace(/</g,"&lt;")+"</div></div>").join("");
  const techs = await all(db,"SELECT id,name FROM users WHERE role='technician' AND approved=1 ORDER BY name");
  const canAssign = perms.manage_all || perms.assign;
  const canChangeStatus = perms.manage_all || perms.change_status_any || (perms.change_status_assigned && t.assignee_user_id===u.id);

  const assignBox = canAssign ? ("<form class='d-flex gap-2' method='POST' action='/admin/tickets/"+id+"/assign'><input type='hidden' name='_csrf' value='"+req.csrfToken()+"'><select class='form-select form-select-sm' name='assignee_user_id'><option value=''>—</option>"+techs.map(a=>"<option value='"+a.id+"'"+(t.assignee_user_id===a.id?" selected":"")+">"+a.name+"</option>").join("")+"</select><button class='btn btn-sm btn-primary'>Asignar</button></form>") : "";
  const statusBox = canChangeStatus ? ("<form class='d-flex gap-2' method='POST' action='/tickets/"+id+"/status'><input type='hidden' name='_csrf' value='"+req.csrfToken()+"'><select name='status' class='form-select form-select-sm'>"+["Abierto","En progreso","En espera","Resuelto","Cerrado"].map(s=>"<option"+(s===t.status?" selected":"")+">"+s+"</option>").join("")+"</select><button class='btn btn-outline-primary btn-sm'>Actualizar estado</button></form>") : "";

  const c = [
    "<div class='row g-3'>",
      "<div class='col-lg-8'><div class='card p-3'>",
        "<div class='d-flex justify-content-between'><h1 class='h5'>Ticket "+t.uuid+"</h1><span class='badge text-bg-secondary'>"+t.status+"</span></div>",
        "<div class='text-muted small'>Empresa: "+(t.company_name||"—")+" • Creador: "+(t.creator_name||"")+"</div>",
        "<hr><h2 class='h6'>"+t.subject+"</h2><p>"+String(t.description).replace(/</g,"&lt;")+"</p>",
        "<div class='small text-muted'>Categoría: "+t.category+" • Prioridad: "+t.priority+" • SLA: "+t.sla_hours+"h</div>",
        "<hr><h3 class='h6'>Adjuntos</h3><ul>"+(atts.length? atts.map(a=>"<li><a href='"+a.path+"' target='_blank' rel='noopener'>"+a.filename+"</a> <span class='text-muted small'>("+Math.round(a.size/1024)+" KB)</span></li>").join("") : "<li class='text-muted'>Sin adjuntos</li>")+"</ul>",
        "<hr><h3 class='h6'>Comentarios</h3>"+(commentsHtml || "<div class='text-muted'>Sin comentarios</div>"),
        "<form class='mt-3' method='POST' action='/tickets/"+id+"/comment'><input type='hidden' name='_csrf' value='"+req.csrfToken()+"'><div class='mb-2'><label class='form-label'>Comentario</label><textarea class='form-control' name='body' required></textarea></div>"+
        (canPrivate ? "<div class='form-check mb-2'><input class='form-check-input' type='checkbox' name='is_private' id='priv'><label class='form-check-label' for='priv'>Privado (solo equipo Infornet)</label></div>" : "")+
        "<button class='btn btn-primary btn-sm'>Añadir</button></form>",
      "</div></div>",
      "<div class='col-lg-4'><div class='card p-3'><h2 class='h6'>Gestión</h2>"+assignBox+"<div class='mt-2'>"+statusBox+"</div></div></div>",
    "</div>"
  ].join("");
  res.send(layout("Ticket "+t.uuid, req.csrfToken(), c, req));
});
app.post("/tickets/:id/status", requireAuth, csrfProtection, async (req,res)=>{
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  const id = req.params.id; const status = req.body.status;
  const t = await get(db, "SELECT * FROM tickets WHERE id=?", [id]);
  if (!t) return res.status(404).send("No encontrado");
  const u = req.session.user; const p = req.session.perms;
  const isAllowed = p.manage_all || p.change_status_any || (p.change_status_assigned && t.assignee_user_id===u.id);
  if (!isAllowed) return res.status(403).send("No autorizado");
  const from = t.status;
  await run(db, "UPDATE tickets SET status=?, updated_at=datetime('now') WHERE id=?", [status, id]);
  await run(db, "INSERT INTO status_events (ticket_id, from_status, to_status, user_id) VALUES (?,?,?,?)", [id, from, status, u.id]);
  await notifyAdmins("[Helpdesk] Estado "+t.uuid+": "+from+" -> "+status, "Ticket "+t.uuid+" cambio a "+status);
  if (t.company_id) await notifyCompany(t.company_id, "[Helpdesk] Ticket "+t.uuid+" actualizado", "El ticket cambió a: "+status);
  const creator = await get(db, "SELECT email FROM users WHERE id=?", [t.creator_user_id]);
  if (creator && (status==="En progreso" || status==="Resuelto" || status==="Cerrado")) await sendMail(creator.email, "[Helpdesk] Ticket "+t.uuid+" "+status, "Tu ticket está ahora: "+status);
  res.redirect("/tickets/"+id);
});
app.post("/tickets/:id/comment", requireAuth, csrfProtection, async (req,res)=>{
  if (!req.session.perms) req.session.perms = await loadPerms(req.session.user.role);
  const id = req.params.id; const { body } = req.body;
  const is_private = (req.body.is_private === "on") ? 1 : 0;
  const t = await get(db, "SELECT * FROM tickets WHERE id=?", [id]);
  if (!t) return res.status(404).send("No encontrado");
  const p = req.session.perms; const u = req.session.user;
  if (is_private && !(p.comment_private || p.manage_all)) return res.status(403).send("No autorizado para comentarios privados");
  let allowed = false;
  if (p.manage_all || p.view_all) allowed = true;
  else if (p.view_assigned && t.assignee_user_id===u.id) allowed = true;
  else if (p.view_company && t.company_id===u.company_id) allowed = true;
  else if (p.view_own && t.creator_user_id===u.id) allowed = true;
  if (!allowed) return res.status(403).send("No autorizado");
  await run(db, "INSERT INTO comments (ticket_id,user_id,is_private,body) VALUES (?,?,?,?)", [id, u.id, is_private, body]);
  await notifyAdmins("[Helpdesk] Nuevo comentario en "+t.uuid, "Se ha añadido un comentario.");
  if (t.company_id) await notifyCompany(t.company_id, "[Helpdesk] Movimiento en ticket "+t.uuid, "Se registraron comentarios.");
  if (!is_private) {
    const creator = await get(db, "SELECT email FROM users WHERE id=?", [t.creator_user_id]);
    if (creator) await sendMail(creator.email, "[Helpdesk] Comentario en ticket "+t.uuid, "Se ha añadido un comentario a tu ticket.");
  }
  res.redirect("/tickets/"+id);
});

// Reports
app.get("/admin/reports", requireManageAll, csrfProtection, async (req,res)=>{
  const byCompany = await all(db, "SELECT COALESCE(c.name,'—') as company, COUNT(*) as total FROM tickets t LEFT JOIN companies c ON c.id=t.company_id GROUP BY t.company_id ORDER BY total DESC");
  const byStatus = await all(db, "SELECT status, COUNT(*) as total FROM tickets GROUP BY status");
  const byPriority = await all(db, "SELECT priority, COUNT(*) as total FROM tickets GROUP BY priority");
  const c = [
    "<div class='row g-3'>",
      "<div class='col-md-6'><div class='card p-3'><h2 class='h6'>Tickets por empresa</h2><table class='table table-sm'><thead><tr><th>Empresa</th><th>Total</th></tr></thead><tbody>"+byCompany.map(r=>"<tr><td>"+r.company+"</td><td>"+r.total+"</td></tr>").join("")+"</tbody></table></div></div>",
      "<div class='col-md-3'><div class='card p-3'><h2 class='h6'>Por estado</h2><table class='table table-sm'><thead><tr><th>Estado</th><th>Total</th></tr></thead><tbody>"+byStatus.map(r=>"<tr><td>"+r.status+"</td><td>"+r.total+"</td></tr>").join("")+"</tbody></table></div></div>",
      "<div class='col-md-3'><div class='card p-3'><h2 class='h6'>Por prioridad</h2><table class='table table-sm'><thead><tr><th>Prioridad</th><th>Total</th></tr></thead><tbody>"+byPriority.map(r=>"<tr><td>"+r.priority+"</td><td>"+r.total+"</td></tr>").join("")+"</tbody></table></div></div>",
    "</div>"
  ].join("");
  res.send(layout("Reportes", req.csrfToken(), c, req));
});

// Health + errors
app.get("/health",(req,res)=> res.json({ ok: true }));
app.use((err, req, res, next)=>{
  console.error("[ERROR]", err && err.stack ? err.stack : err);
  if (err.code === "EBADCSRFTOKEN") return res.status(403).send("Sesión caducada. Recarga la página e inténtalo de nuevo.");
  res.status(500).send("Error inesperado");
});

init().then(()=>{
  app.listen(PORT, "0.0.0.0", ()=> console.log("Helpdesk portal listo en http://0.0.0.0:"+PORT+" (DATA_DIR="+DATA_DIR+")"));
}).catch(err=>{ console.error("Init error", err); process.exit(1); });
