/* AyudaInfornet Helpdesk v3 (completo) */
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

// Data dir
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

// CSRF
const csrfProtection = csurf();
app.use(csrfProtection);

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

// Init schema + seed
async function init() {
  await run(db, "PRAGMA foreign_keys = ON");
  await run(db, `CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT, cif TEXT, email TEXT, phone TEXT,
    contract_type TEXT,
    created_at TEXT NOT NULL
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'pending',
    approved INTEGER NOT NULL DEFAULT 0,
    company_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id)
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,
    company_id INTEGER,
    creator_user_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'General',
    priority TEXT NOT NULL CHECK(priority IN ('Alta','Media','Baja')) DEFAULT 'Media',
    sla_hours INTEGER NOT NULL DEFAULT 24,
    status TEXT NOT NULL CHECK(status IN ('Abierto','En progreso','En espera','Resuelto','Cerrado')) DEFAULT 'Abierto',
    assignee_user_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (company_id) REFERENCES companies(id),
    FOREIGN KEY (creator_user_id) REFERENCES users(id),
    FOREIGN KEY (assignee_user_id) REFERENCES users(id)
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id)
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    user_id INTEGER,
    is_private INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
  await run(db, `CREATE TABLE IF NOT EXISTS status_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    user_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (ticket_id) REFERENCES tickets(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // Seed admin fixed
  const existing = await get(db, "SELECT * FROM users WHERE role='admin' AND email=?", ["mseoane@holainfornet.com"]);
  if (!existing) {
    const hash = await bcrypt.hash("Infornet1138", 12);
    await run(db, "INSERT INTO users (name,email,phone,password_hash,role,approved,created_at) VALUES (?,?,?,?, 'admin', 1, datetime('now'))", ["Administrador","mseoane@holainfornet.com","",hash]);
    console.log("===> Admin creado: mseoane@holainfornet.com / pass: Infornet1138");
  }
}

// UI helpers
function layout(title, csrfToken, content, req) {
  const logged = !!(req.session && req.session.user);
  const role = logged ? req.session.user.role : "";
  return [
    "<!doctype html><html lang='es'><head>",
    "<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>",
    "<title>"+title+"</title>",
    "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>",
    "<style>:root{--brand:#c8a100}.btn-primary{background:var(--brand);border-color:var(--brand)}.btn-primary:hover{background:#b39000;border-color:#b39000}.navbar{box-shadow:0 4px 12px rgba(0,0,0,.05)}body{background:#f6f7fb}.card{border:none;border-radius:1rem;box-shadow:0 8px 22px rgba(0,0,0,.06)}</style>",
    "</head><body>",
    "<nav class='navbar navbar-expand-lg bg-white'><div class='container'>",
    "<a class='navbar-brand d-flex align-items-center gap-2' href='/'><img src='/logo.png' height='32'><strong>AyudaInfornet</strong></a>",
    "<div class='ms-auto'>",
    (logged
      ? ("<span class='me-3'>"+req.session.user.name+" ("+role+")</span><a class='btn btn-outline-secondary btn-sm' href='/logout'>Salir</a>")
      : ("<a class='btn btn-outline-primary btn-sm me-2' href='/register'>Crear cuenta</a><a class='btn btn-primary btn-sm' href='/login'>Entrar</a>")
    ),
    "</div></div></nav>",
    "<main class='container py-4'>", content ,"</main>",
    "<script>window.__CSRF__='"+csrfToken+"'</script>",
    "<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>",
    "</body></html>"
  ].join("");
}
function requireAuth(req,res,next){ if(!req.session.user) return res.redirect("/login"); next(); }
function requireRole(roles){ return (req,res,next)=>{ if(!req.session.user || roles.indexOf(req.session.user.role)===-1) return res.redirect("/"); next(); }; }
function csrfTokenFor(req){ try { return req.csrfToken(); } catch(e){ return ""; } }

// Home (landing)
app.get("/", (req,res)=>{
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
    return res.send(layout("AyudaInfornet Helpdesk", req.csrfToken(), c, req));
  }
  const r = req.session.user.role;
  if (r === "admin") return res.redirect("/admin");
  if (r === "technician") return res.redirect("/tech");
  if (r === "supervisor") return res.redirect("/supervisor");
  return res.redirect("/client");
});

// Register/Login
app.get("/register",(req,res)=>{
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
app.post("/register", async (req,res)=>{
  const {name,email,phone,password} = req.body;
  const exists = await get(db, "SELECT id FROM users WHERE email=?", [email]);
  if (exists) return res.status(400).send(layout("Registro", req.csrfToken(), "<div class='alert alert-danger'>Ese correo ya está registrado.</div>", req));
  const hash = await bcrypt.hash(password, 12);
  await run(db, "INSERT INTO users (name,email,phone,password_hash,role,approved,created_at) VALUES (?,?,?,?, 'pending', 0, datetime('now'))", [name,email,phone||"",hash]);
  await notifyAdmins("[Helpdesk] Nueva solicitud de registro", "Se registró "+name+" <"+email+">");
  res.send(layout("Registro", req.csrfToken(), "<div class='alert alert-success'>Registro enviado. Te avisaremos cuando esté aprobado.</div><a class='btn btn-primary mt-3' href='/login'>Ir a login</a>", req));
});

app.get("/login",(req,res)=>{
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
app.post("/login", async (req,res)=>{
  const {email,password} = req.body;
  const u = await get(db, "SELECT * FROM users WHERE email=?", [email]);
  if (!u) return res.status(401).send(layout("Login", req.csrfToken(), "<div class='alert alert-danger'>Usuario o contraseña incorrectos.</div>", req));
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).send(layout("Login", req.csrfToken(), "<div class='alert alert-danger'>Usuario o contraseña incorrectos.</div>", req));
  if (!u.approved) return res.status(403).send(layout("Login", req.csrfToken(), "<div class='alert alert-warning'>Tu cuenta está pendiente de aprobación.</div>", req));
  req.session.user = { id:u.id, name:u.name, email:u.email, role:u.role, company_id:u.company_id || null };
  res.redirect("/");
});
app.get("/logout",(req,res)=> req.session.destroy(()=>res.redirect("/")));

// Account - change password
app.get("/account/password", requireAuth, (req,res)=>{
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
app.post("/account/password", requireAuth, async (req,res)=>{
  const { current, next } = req.body;
  const u = await get(db, "SELECT * FROM users WHERE id=?", [req.session.user.id]);
  const ok = await bcrypt.compare(current, u.password_hash);
  if (!ok) return res.status(400).send(layout("Cambiar contraseña", req.csrfToken(), "<div class='alert alert-danger'>La contraseña actual no es correcta.</div>", req));
  const hash = await bcrypt.hash(next, 12);
  await run(db, "UPDATE users SET password_hash=? WHERE id=?", [hash, u.id]);
  res.send(layout("Cambiar contraseña", req.csrfToken(), "<div class='alert alert-success'>Contraseña actualizada.</div><a class='btn btn-primary mt-3' href='/'>Volver</a>", req));
});

// Admin dashboard
app.get("/admin", requireRole(["admin"]), async (req,res)=>{
  const pending = await all(db, "SELECT * FROM users WHERE approved=0 ORDER BY created_at");
  const companies = await all(db, "SELECT * FROM companies ORDER BY name");
  const users = await all(db, "SELECT u.*, c.name as company_name FROM users u LEFT JOIN companies c ON c.id=u.company_id ORDER BY u.created_at DESC LIMIT 100");
  const c = [
    "<div class='row g-3'>",
      "<div class='col-lg-5'><div class='card p-3'>",
        "<h2 class='h6'>Pendientes de aprobación</h2>",
        (pending.length? "<ul class='list-group list-group-flush'>" + pending.map(p=>"<li class='list-group-item'><strong>"+p.name+"</strong> <span class='text-muted'>&lt;"+p.email+"&gt;</span>"+
          "<form class='mt-2' method='POST' action='/admin/approve'><input type='hidden' name='_csrf' value='"+csrfTokenFor(req)+"'><input type='hidden' name='user_id' value='"+p.id+"'>"+
          "<div class='row g-2 align-items-end'><div class='col-md-4'><label class='form-label small'>Rol</label><select class='form-select form-select-sm' name='role'><option value='user'>usuario</option><option value='supervisor'>supervisor</option><option value='technician'>technician</option><option value='admin'>admin</option></select></div>"+
          "<div class='col-md-6'><label class='form-label small'>Empresa</label><select class='form-select form-select-sm' name='company_id'><option value=''>—</option>"+companies.map(c=>"<option value='"+c.id+"'>"+c.name+"</option>").join("")+"</select></div>"+
          "<div class='col-md-2'><button class='btn btn-sm btn-primary w-100'>Aprobar</button></div></div></form></li>").join("") + "</ul>" : "<div class='text-muted'>Sin pendientes</div>"),
      "</div></div>",
      "<div class='col-lg-7'><div class='card p-3'>",
        "<h2 class='h6'>Usuarios recientes</h2>",
        "<div class='table-responsive'><table class='table table-sm'><thead><tr><th>Nombre</th><th>Email</th><th>Rol</th><th>Empresa</th><th>Aprob.</th></tr></thead><tbody>"+users.map(u=>"<tr><td>"+u.name+"</td><td>"+u.email+"</td><td>"+u.role+"</td><td>"+(u.company_name||"—")+"</td><td>"+(u.approved?"Si":"No")+"</td></tr>").join("")+"</tbody></table></div>",
        "<div class='mt-2 d-flex gap-2'><a class='btn btn-outline-primary btn-sm' href='/admin/tickets'>Gestionar tickets</a><a class='btn btn-outline-secondary btn-sm' href='/admin/reports'>Reportes</a></div>",
      "</div></div>",
      "<div class='col-lg-6'><div class='card p-3'>",
        "<h2 class='h6'>Crear empresa</h2>",
        "<form method='POST' action='/admin/companies/create'><input type='hidden' name='_csrf' value='"+csrfTokenFor(req)+"'>",
        "<div class='row g-2'><div class='col-md-6'><label class='form-label small'>Nombre</label><input class='form-control form-control-sm' name='name' required></div>",
        "<div class='col-md-6'><label class='form-label small'>CIF</label><input class='form-control form-control-sm' name='cif'></div>",
        "<div class='col-md-6'><label class='form-label small'>Email</label><input class='form-control form-control-sm' name='email'></div>",
        "<div class='col-md-6'><label class='form-label small'>Telefono</label><input class='form-control form-control-sm' name='phone'></div>",
        "<div class='col-md-8'><label class='form-label small'>Direccion</label><input class='form-control form-control-sm' name='address'></div>",
        "<div class='col-md-4'><label class='form-label small'>Contrato</label><input class='form-control form-control-sm' name='contract_type'></div>",
        "<div class='col-12'><button class='btn btn-primary btn-sm mt-2'>Crear</button></div></div></form>",
      "</div></div>",
    "</div>"
  ].join("");
  res.send(layout("Admin", req.csrfToken(), c, req));
});
app.post("/admin/approve", requireRole(["admin"]), async (req,res)=>{
  const { user_id, role, company_id } = req.body;
  const cid = company_id ? Number(company_id) : null;
  await run(db, "UPDATE users SET role=?, approved=1, company_id=COALESCE(?, company_id) WHERE id=?", [role, cid, user_id]);
  const u = await get(db, "SELECT * FROM users WHERE id=?", [user_id]);
  await sendMail(u.email, "[Helpdesk] Cuenta aprobada", "Tu cuenta ha sido aprobada con rol: "+u.role);
  res.redirect("/admin");
});
app.post("/admin/companies/create", requireRole(["admin"]), async (req,res)=>{
  const { name, address, cif, email, phone, contract_type } = req.body;
  await run(db, "INSERT INTO companies (name,address,cif,email,phone,contract_type,created_at) VALUES (?,?,?,?,?,?,datetime('now'))", [name,address||"",cif||"",email||"",phone||"",contract_type||""]);
  res.redirect("/admin");
});

// Admin tickets list + assignment
app.get("/admin/tickets", requireRole(["admin"]), async (req,res)=>{
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
    "FROM tickets t LEFT JOIN companies c ON c.id=t.company_id "+
    "LEFT JOIN users u ON u.id=t.creator_user_id "+
    "LEFT JOIN users a ON a.id=t.assignee_user_id "+
    whereSql+" ORDER BY t.created_at DESC LIMIT 200", params);
  const companies = await all(db, "SELECT id,name FROM companies ORDER BY name");
  const techs = await all(db, "SELECT id,name FROM users WHERE role='technician' AND approved=1 ORDER BY name");
  const c = [
    "<div class='card p-3'>",
    "<h1 class='h5 mb-3'>Tickets (asignacion)</h1>",
    "<form class='row g-2 mb-3' method='GET'>",
    "<div class='col-md-3'><input class='form-control' name='q' placeholder='Buscar' value='"+(req.query.q||"")+"'></div>",
    "<div class='col-md-2'><select class='form-select' name='status'><option value=''>Estado</option>"+["Abierto","En progreso","En espera","Resuelto","Cerrado"].map(s=>"<option"+(s===status?" selected":"")+">"+s+"</option>").join("")+"</select></div>",
    "<div class='col-md-2'><select class='form-select' name='priority'><option value=''>Prioridad</option>"+["Alta","Media","Baja"].map(p=>"<option"+(p===priority?" selected":"")+">"+p+"</option>").join("")+"</select></div>",
    "<div class='col-md-2'><select class='form-select' name='company_id'><option value=''>Empresa</option>"+companies.map(x=>"<option value='"+x.id+"'"+(String(x.id)===String(company_id||"")?" selected":"")+">"+x.name+"</option>").join("")+"</select></div>",
    "<div class='col-md-2'><select class='form-select' name='assignee'><option value=''>Tecnico</option>"+techs.map(x=>"<option value='"+x.id+"'"+(String(x.id)===String(assignee||"")?" selected":"")+">"+x.name+"</option>").join("")+"</select></div>",
    "<div class='col-md-1'><button class='btn btn-secondary w-100'>Filtrar</button></div>",
    "</form>",
    "<div class='table-responsive'><table class='table table-sm align-middle'><thead><tr><th>ID</th><th>Asunto</th><th>Empresa</th><th>Prioridad</th><th>Estado</th><th>Asignado</th><th>Gestion</th></tr></thead><tbody>",
    tickets.map(t=>"<tr>"+
      "<td><span class='badge text-bg-light'>"+t.uuid+"</span></td>"+
      "<td><a href='/tickets/"+t.id+"'>"+t.subject+"</a></td>"+
      "<td>"+(t.company_name||"—")+"</td>"+
      "<td>"+t.priority+"</td>"+
      "<td>"+t.status+"</td>"+
      "<td>"+(t.assignee_name||"—")+"</td>"+
      "<td>"+
        "<form method='POST' action='/admin/tickets/"+t.id+"/assign' class='d-flex gap-2'>"+
        "<input type='hidden' name='_csrf' value='"+csrfTokenFor(req)+"'>"+
        "<select class='form-select form-select-sm' name='assignee_user_id'><option value=''>—</option>"+techs.map(te=>"<option value='"+te.id+"'"+(t.assignee_user_id===te.id?" selected":"")+">"+te.name+"</option>").join("")+"</select>"+
        "<button class='btn btn-primary btn-sm'>Asignar</button>"+
        "</form>"+
      "</td>"+
    "</tr>").join(""),
    "</tbody></table></div>",
    "</div>"
  ].join("");
  res.send(layout("Tickets", req.csrfToken(), c, req));
});
app.post("/admin/tickets/:id/assign", requireRole(["admin"]), async (req,res)=>{
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

// Client portal
app.get("/client", requireRole(["user","supervisor","admin"]), async (req,res)=>{
  const mine = await all(db, "SELECT * FROM tickets WHERE creator_user_id=? ORDER BY created_at DESC", [req.session.user.id]);
  const list = mine.map(t=>"<tr><td><span class='badge text-bg-light'>"+t.uuid+"</span></td><td><a href='/tickets/"+t.id+"'>"+t.subject+"</a></td><td>"+t.status+"</td><td>"+new Date(t.created_at).toLocaleString("es-ES")+"</td></tr>").join("");
  const c = [
    "<div class='row g-3'>",
      "<div class='col-md-5'><div class='card p-3'>",
        "<h2 class='h6'>Nuevo ticket</h2>",
        "<form method='POST' action='/tickets' enctype='multipart/form-data'>",
        "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
        "<div class='mb-2'><label class='form-label'>Asunto</label><input class='form-control' name='subject' required maxlength='120'></div>",
        "<div class='mb-2'><label class='form-label'>Descripcion</label><textarea class='form-control' name='description' rows='5' required></textarea></div>",
        "<div class='mb-2'><label class='form-label'>Categoria</label><input class='form-control' name='category' value='General' required></div>",
        "<div class='mb-2'><label class='form-label'>Prioridad</label><select class='form-select' name='priority'><option>Alta</option><option selected>Media</option><option>Baja</option></select></div>",
        "<div class='mb-2'><label class='form-label'>SLA (horas)</label><input type='number' class='form-control' name='sla_hours' value='24' min='1' max='720'></div>",
        "<div class='mb-2'><label class='form-label'>Adjuntos</label><input class='form-control' type='file' name='files' multiple></div>",
        "<button class='btn btn-primary w-100'>Crear</button>",
        "</form>",
      "</div></div>",
      "<div class='col-md-7'><div class='card p-3'>",
        "<h2 class='h6'>Mis tickets</h2>",
        "<div class='table-responsive'><table class='table table-sm align-middle'><thead><tr><th>ID</th><th>Asunto</th><th>Estado</th><th>Creado</th></tr></thead><tbody>"+list+"</tbody></table></div>",
      "</div></div>",
    "</div>"
  ].join("");
  res.send(layout("Cliente", req.csrfToken(), c, req));
});

// Supervisor portal
app.get("/supervisor", requireRole(["supervisor","admin"]), async (req,res)=>{
  const cid = req.session.user.company_id;
  const tickets = await all(db, "SELECT * FROM tickets WHERE company_id=? ORDER BY created_at DESC", [cid]);
  const rows = tickets.map(t=>"<tr><td><span class='badge text-bg-light'>"+t.uuid+"</span></td><td><a href='/tickets/"+t.id+"'>"+t.subject+"</a></td><td>"+t.priority+"</td><td>"+t.status+"</td></tr>").join("");
  const c = "<div class='card p-3'><h2 class='h6'>Tickets de mi empresa</h2><div class='table-responsive'><table class='table table-sm'><thead><tr><th>ID</th><th>Asunto</th><th>Prioridad</th><th>Estado</th></tr></thead><tbody>"+rows+"</tbody></table></div></div>";
  res.send(layout("Supervisor", req.csrfToken(), c, req));
});

// Technician portal
app.get("/tech", requireRole(["technician","admin"]), async (req,res)=>{
  const myid = req.session.user.id;
  const tickets = await all(db, "SELECT * FROM tickets WHERE assignee_user_id=? ORDER BY updated_at DESC", [myid]);
  const rows = tickets.map(t=>"<tr><td><span class='badge text-bg-light'>"+t.uuid+"</span></td><td><a href='/tickets/"+t.id+"'>"+t.subject+"</a></td><td>"+t.priority+"</td><td>"+t.status+"</td></tr>").join("");
  const c = "<div class='card p-3'><h2 class='h6'>Mis tickets asignados</h2><div class='table-responsive'><table class='table table-sm'><thead><tr><th>ID</th><th>Asunto</th><th>Prioridad</th><th>Estado</th></tr></thead><tbody>"+rows+"</tbody></table></div></div>";
  res.send(layout("Tecnico", req.csrfToken(), c, req));
});

// Create ticket
app.post("/tickets", requireRole(["user","supervisor","admin"]), upload.array("files", 5), async (req,res)=>{
  const { subject, description, category, priority, sla_hours } = req.body;
  const creator = req.session.user.id;
  const u = await get(db, "SELECT company_id FROM users WHERE id=?", [creator]);
  const company_id = u ? u.company_id : null;
  const uuid = uuidv4().slice(0,8).toUpperCase();
  const now = new Date().toISOString();
  const result = await run(db, "INSERT INTO tickets (uuid,company_id,creator_user_id,subject,description,category,priority,sla_hours,status,assignee_user_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?, 'Abierto', NULL, ?, ?)",
    [uuid, company_id, creator, subject, description, category||"General", priority||"Media", Number(sla_hours)||24, now, now]);
  const ticketId = result.lastID;
  if (req.files && req.files.length) {
    for (const f of req.files) {
      await run(db, "INSERT INTO attachments (ticket_id,filename,path,size,uploaded_at) VALUES (?,?,?,?,datetime('now'))", [ticketId, f.originalname, "/uploads/"+path.basename(f.path), f.size]);
    }
  }
  await notifyAdmins("[Helpdesk] Ticket creado "+uuid, "Se ha creado un nuevo ticket: "+subject);
  if (company_id) await notifyCompany(company_id, "[Helpdesk] Ticket creado "+uuid, "Se ha creado un ticket en su empresa.");
  res.redirect("/tickets/"+ticketId);
});

// Ticket detail + comments + status
app.get("/tickets/:id", requireAuth, async (req,res)=>{
  const id = req.params.id;
  const t = await get(db, "SELECT t.*, u.name as creator_name, a.name as assignee_name, c.name as company_name FROM tickets t LEFT JOIN users u ON u.id=t.creator_user_id LEFT JOIN users a ON a.id=t.assignee_user_id LEFT JOIN companies c ON c.id=t.company_id WHERE t.id=?", [id]);
  if (!t) return res.status(404).send("Ticket no encontrado");
  const role = req.session.user.role;
  const u = req.session.user;
  if (role!=="admin") {
    if (role==="technician" && t.assignee_user_id!==u.id) return res.status(403).send("No autorizado");
    if (role==="supervisor" && t.company_id!==u.company_id) return res.status(403).send("No autorizado");
    if (role==="user" && t.creator_user_id!==u.id) return res.status(403).send("No autorizado");
  }
  const atts = await all(db, "SELECT * FROM attachments WHERE ticket_id=?", [id]);
  const comments = await all(db, "SELECT c.*, u.name as user_name FROM comments c LEFT JOIN users u ON u.id=c.user_id WHERE ticket_id=? ORDER BY created_at", [id]);
  const commentsHtml = comments.filter(c=> (c.is_private? (role==="admin"||role==="technician") : true)).map(c=>"<div class='p-2 border rounded mb-2 "+(c.is_private?"bg-light":"")+"'><div class='small text-muted'>"+(c.user_name||"")+" • "+new Date(c.created_at).toLocaleString("es-ES")+(c.is_private?" • Privado":"")+"</div><div>"+String(c.body).replace(/</g,"&lt;")+"</div></div>").join("");
  const techs = await all(db,"SELECT id,name FROM users WHERE role='technician' AND approved=1 ORDER BY name");
  const assignBox = (role==="admin") ? ("<form class='d-flex gap-2' method='POST' action='/admin/tickets/"+id+"/assign'><input type='hidden' name='_csrf' value='"+csrfTokenFor(req)+"'><select class='form-select form-select-sm' name='assignee_user_id'><option value=''>—</option>"+techs.map(a=>"<option value='"+a.id+"'"+(t.assignee_user_id===a.id?" selected":"")+">"+a.name+"</option>").join("")+"</select><button class='btn btn-sm btn-primary'>Asignar</button></form>") : "";
  const statusBox = ((role==="technician" && t.assignee_user_id===u.id) || role==="admin") ? ("<form class='d-flex gap-2' method='POST' action='/tickets/"+id+"/status'><input type='hidden' name='_csrf' value='"+csrfTokenFor(req)+"'><select name='status' class='form-select form-select-sm'>"+["Abierto","En progreso","En espera","Resuelto","Cerrado"].map(s=>"<option"+(s===t.status?" selected":"")+">"+s+"</option>").join("")+"</select><button class='btn btn-outline-primary btn-sm'>Actualizar estado</button></form>") : "";
  const c = [
    "<div class='row g-3'>",
      "<div class='col-lg-8'><div class='card p-3'>",
        "<div class='d-flex justify-content-between'><h1 class='h5'>Ticket "+t.uuid+"</h1><span class='badge text-bg-secondary'>"+t.status+"</span></div>",
        "<div class='text-muted small'>Empresa: "+(t.company_name||"—")+" • Creador: "+(t.creator_name||"")+"</div>",
        "<hr><h2 class='h6'>"+t.subject+"</h2><p>"+String(t.description).replace(/</g,"&lt;")+"</p>",
        "<div class='small text-muted'>Categoria: "+t.category+" • Prioridad: "+t.priority+" • SLA: "+t.sla_hours+"h</div>",
        "<hr><h3 class='h6'>Adjuntos</h3><ul>"+(atts.length? atts.map(a=>"<li><a href='"+a.path+"' target='_blank' rel='noopener'>"+a.filename+"</a> <span class='text-muted small'>("+Math.round(a.size/1024)+" KB)</span></li>").join("") : "<li class='text-muted'>Sin adjuntos</li>")+"</ul>",
        "<hr><h3 class='h6'>Comentarios</h3>"+(commentsHtml || "<div class='text-muted'>Sin comentarios</div>"),
        "<form class='mt-3' method='POST' action='/tickets/"+id+"/comment'><input type='hidden' name='_csrf' value='"+csrfTokenFor(req)+"'><div class='mb-2'><label class='form-label'>Comentario</label><textarea class='form-control' name='body' required></textarea></div>"+
        (role==="admin"||role==="technician" ? "<div class='form-check mb-2'><input class='form-check-input' type='checkbox' name='is_private' id='priv'><label class='form-check-label' for='priv'>Privado (solo equipo Infornet)</label></div>" : "")+
        "<button class='btn btn-primary btn-sm'>Añadir</button></form>",
      "</div></div>",
      "<div class='col-lg-4'><div class='card p-3'>",
        "<h2 class='h6'>Gestion</h2>",
        "<div class='mb-2'>Asignado a: "+(t.assignee_user_name||t.assignee_name||"—")+"</div>", assignBox,
        "<div class='mt-2'>", statusBox ,"</div>",
      "</div></div>",
    "</div>"
  ].join("");
  res.send(layout("Ticket "+t.uuid, req.csrfToken(), c, req));
});
app.post("/tickets/:id/status", requireAuth, async (req,res)=>{
  const id = req.params.id; const status = req.body.status;
  const t = await get(db, "SELECT * FROM tickets WHERE id=?", [id]);
  if (!t) return res.status(404).send("No encontrado");
  const role = req.session.user.role;
  const isTechAllowed = (role==="technician" && t.assignee_user_id===req.session.user.id);
  const isAdmin = role==="admin";
  if (!isTechAllowed && !isAdmin) return res.status(403).send("No autorizado");
  const from = t.status;
  await run(db, "UPDATE tickets SET status=?, updated_at=datetime('now') WHERE id=?", [status, id]);
  await run(db, "INSERT INTO status_events (ticket_id, from_status, to_status, user_id, created_at) VALUES (?,?,?,?, datetime('now'))", [id, from, status, req.session.user.id]);
  await notifyAdmins("[Helpdesk] Estado "+t.uuid+": "+from+" -> "+status, "Ticket "+t.uuid+" cambio a "+status);
  if (t.company_id) await notifyCompany(t.company_id, "[Helpdesk] Ticket "+t.uuid+" actualizado", "El ticket cambio a: "+status);
  const creator = await get(db, "SELECT email FROM users WHERE id=?", [t.creator_user_id]);
  if (creator && (status==="En progreso" || status==="Resuelto" || status==="Cerrado")) await sendMail(creator.email, "[Helpdesk] Ticket "+t.uuid+" "+status, "Tu ticket esta ahora: "+status);
  res.redirect("/tickets/"+id);
});
app.post("/tickets/:id/comment", requireAuth, async (req,res)=>{
  const id = req.params.id; const { body } = req.body;
  const is_private = (req.body.is_private === "on") ? 1 : 0;
  const t = await get(db, "SELECT * FROM tickets WHERE id=?", [id]);
  if (!t) return res.status(404).send("No encontrado");
  if (is_private && !(req.session.user.role==="admin" || req.session.user.role==="technician")) return res.status(403).send("No autorizado para comentarios privados");
  const u = req.session.user;
  if (u.role!=="admin") {
    if (u.role==="technician" && t.assignee_user_id!==u.id) return res.status(403).send("No autorizado");
    if (u.role==="supervisor" && t.company_id!==u.company_id) return res.status(403).send("No autorizado");
    if (u.role==="user" && t.creator_user_id!==u.id) return res.status(403).send("No autorizado");
  }
  await run(db, "INSERT INTO comments (ticket_id,user_id,is_private,body,created_at) VALUES (?,?,?,?, datetime('now'))", [id, u.id, is_private, body]);
  await notifyAdmins("[Helpdesk] Nuevo comentario en "+t.uuid, "Se ha añadido un comentario.");
  if (t.company_id) await notifyCompany(t.company_id, "[Helpdesk] Movimiento en ticket "+t.uuid, "Se registraron comentarios.");
  if (!is_private) {
    const creator = await get(db, "SELECT email FROM users WHERE id=?", [t.creator_user_id]);
    if (creator) await sendMail(creator.email, "[Helpdesk] Comentario en ticket "+t.uuid, "Se ha añadido un comentario a tu ticket.");
  }
  res.redirect("/tickets/"+id);
});

// Reports
app.get("/admin/reports", requireRole(["admin"]), async (req,res)=>{
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
  if (err.code === "EBADCSRFTOKEN") return res.status(403).send("Sesion caducada. Recarga la pagina e intentalo de nuevo.");
  res.status(500).send("Error inesperado");
});

// Start
init().then(()=>{
  app.listen(PORT, "0.0.0.0", ()=> console.log("Helpdesk portal listo en http://0.0.0.0:"+PORT+" (DATA_DIR="+DATA_DIR+")"));
}).catch(err=>{ console.error("Init error", err); process.exit(1); });
