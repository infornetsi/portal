// helpdesk-portal.js (fixed start, no stray chars)
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
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const uploadDir = path.join(DATA_DIR, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, String(Date.now()) + "-" + file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_"))
});
const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } });
app.use("/uploads", express.static(uploadDir));

app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || "change_me_please",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: String(process.env.COOKIE_SECURE).toLowerCase() === "true" }
}));

const csrfProtection = csurf();
app.use(csrfProtection);

const db = new sqlite3.Database(path.join(DATA_DIR, "helpdesk.sqlite"));
function run(db, sql, params=[]) { return new Promise((res,rej)=>db.run(sql,params,function(err){ if(err)rej(err); else res(this);})); }
function get(db, sql, params=[]) { return new Promise((res,rej)=>db.get(sql,params,(err,row)=>{ if(err)rej(err); else res(row);})); }
function all(db, sql, params=[]) { return new Promise((res,rej)=>db.all(sql,params,(err,rows)=>{ if(err)rej(err); else res(rows);})); }

let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
}

async function init() {
  await run(db, "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, group_id INTEGER, created_at TEXT NOT NULL)");
  await run(db, "CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL)");
  await run(db, "CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT NOT NULL, user_id INTEGER NOT NULL, subject TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'General', sla_hours INTEGER NOT NULL DEFAULT 72, priority TEXT NOT NULL DEFAULT 'Media', status TEXT NOT NULL DEFAULT 'Abierto', group_id INTEGER, assignee_user_id INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)");
  await run(db, "CREATE TABLE IF NOT EXISTS attachments (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL, filename TEXT NOT NULL, path TEXT NOT NULL, size INTEGER NOT NULL, uploaded_at TEXT NOT NULL)");

  for (const g of ["Soporte N1","Soporte N2","Infra","QA"]) { try { await run(db, "INSERT INTO groups (name) VALUES (?)", [g]); } catch {} }

  const admin = await get(db, "SELECT * FROM users WHERE email=?", ["admin@example.com"]);
  if (!admin) { const hash = await bcrypt.hash("Admin123!", 12); await run(db, 'INSERT INTO users (name,email,password_hash,is_admin,created_at) VALUES (?,?,?,?,datetime("now"))', ["Administrador","admin@example.com",hash,1]); }
  const client = await get(db, "SELECT * FROM users WHERE email=?", ["client@example.com"]);
  if (!client) { const hash = await bcrypt.hash("Client123!", 12); await run(db, 'INSERT INTO users (name,email,password_hash,is_admin,created_at) VALUES (?,?,?,?,datetime("now"))', ["Cliente Demo","client@example.com",hash,0]); }
}

function layout(title, csrfToken, content, req) {
  const logged = !!(req.session && req.session.user);
  const isAdmin = logged && req.session.user.is_admin === 1;
  return [
    "<!doctype html><html lang='es'><head>",
    "<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>",
    "<title>"+title+"</title>",
    "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css' rel='stylesheet'>",
    "<style>body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#f6f7fb}.card{border:none;border-radius:1rem;box-shadow:0 10px 25px rgba(0,0,0,.06)}.navbar{box-shadow:0 4px 10px rgba(0,0,0,.05)}.container-narrow{max-width:1100px}</style>",
    "</head><body>",
    "<nav class='navbar navbar-expand-lg bg-white'><div class='container'>",
    "<a class='navbar-brand fw-semibold d-flex align-items-center gap-2' href='/'><img src='/logo.png' alt='AyudaInfornet' height='32'><span>Helpdesk</span></a>",
    "<div class='ms-auto'>",
    logged ? ("<span class='me-3'>Hola, "+req.session.user.name+(isAdmin?" (Admin)":"")+"</span><a class='btn btn-outline-secondary btn-sm' href='/logout'>Salir</a>")
           : ("<a class='btn btn-primary btn-sm' href='/login'>Entrar</a>"),
    "</div></div></nav>",
    "<main class='container container-narrow py-4'>"+content+"</main>",
    "<script>window.__CSRF__='"+csrfToken+"'</script>",
    "<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js'></script>",
    "</body></html>"
  ].join("");
}
function requireAuth(req,res,next){ if(!req.session.user) return res.redirect("/login"); next(); }
function requireAdmin(req,res,next){ if(!req.session.user || req.session.user.is_admin!==1) return res.redirect("/"); next(); }
function csrfTokenFor(req){ try { return req.csrfToken(); } catch(e){ return ""; } }

app.get("/", (req,res)=>{ if(!req.session.user) return res.redirect("/login"); return req.session.user.is_admin===1 ? res.redirect("/admin") : res.redirect("/client"); });

app.get("/login",(req,res)=>{
  const c = [
    "<div class='row justify-content-center'><div class='col-md-7'><div class='card p-4 p-md-5'>",
    "<h1 class='h4 mb-3'>Acceso al portal</h1>",
    "<form method='POST' action='/login'>",
    "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='mb-3'><label class='form-label'>Email</label><input class='form-control' type='email' name='email' required></div>",
    "<div class='mb-3'><label class='form-label'>Contraseña</label><input class='form-control' type='password' name='password' required></div>",
    "<button class='btn btn-primary w-100' type='submit'>Entrar</button>",
    "<p class='text-muted small mt-3'>Demo: admin@example.com / Admin123! — client@example.com / Client123!</p>",
    "</form></div></div></div>"
  ].join("");
  res.send(layout("Login", req.csrfToken(), c, req));
});
app.post("/login", async (req,res)=>{
  const email = req.body.email; const password = req.body.password;
  const u = await get(db, "SELECT * FROM users WHERE email=?", [email]);
  if(!u) return res.status(401).send(layout("Login", req.csrfToken(), "<div class='alert alert-danger'>Credenciales inválidas</div>", req));
  const ok = await bcrypt.compare(password, u.password_hash);
  if(!ok) return res.status(401).send(layout("Login", req.csrfToken(), "<div class='alert alert-danger'>Credenciales inválidas</div>", req));
  req.session.user = { id:u.id, name:u.name, email:u.email, is_admin:u.is_admin, group_id:u.group_id };
  res.redirect("/");
});
app.get("/logout",(req,res)=>{ req.session.destroy(()=>res.redirect("/login")); });

app.get("/client", requireAuth, async (req,res)=>{
  if(req.session.user.is_admin===1) return res.redirect("/admin");
  const tickets = await all(db, "SELECT * FROM tickets WHERE user_id=? ORDER BY created_at DESC", [req.session.user.id]);
  const rows = tickets.map(t=>"<tr><td><span class='badge text-bg-light'>"+t.uuid+"</span></td><td>"+t.subject+"<div class='text-muted small'>"+t.category+" • SLA: "+t.sla_hours+"h</div></td><td><span class='badge text-bg-secondary'>"+t.priority+"</span></td><td><span class='badge text-bg-light'>"+t.status+"</span></td><td>"+new Date(t.created_at).toLocaleString("es-ES")+"</td></tr>").join("");

  const groups = await all(db, "SELECT id,name FROM groups ORDER BY name");
  const groupOptions = groups.map(g=>"<option value='"+g.id+"'>"+g.name+"</option>").join("");

  const c = [
    "<div class='row g-4'>",
    "<div class='col-md-5'><div class='card p-4'><h2 class='h5'>Nuevo ticket</h2>",
    "<form method='POST' action='/tickets' enctype='multipart/form-data'>",
    "<input type='hidden' name='_csrf' value='"+req.csrfToken()+"'>",
    "<div class='mb-3'><label class='form-label'>Asunto</label><input name='subject' class='form-control' required maxlength='120'></div>",
    "<div class='mb-3'><label class='form-label'>Descripción</label><textarea name='description' class='form-control' rows='5' required></textarea></div>",
    "<div class='mb-3'><label class='form-label'>Categoría</label><input name='category' class='form-control' value='General' required></div>",
    "<div class='mb-3'><label class='form-label'>Prioridad</label><select class='form-select' name='priority'><option>Alta</option><option selected>Media</option><option>Baja</option></select></div>",
    "<div class='mb-3'><label class='form-label'>SLA (horas)</label><input type='number' min='1' max='720' step='1' class='form-control' name='sla_hours' value='72' required></div>",
    "<div class='mb-3'><label class='form-label'>Grupo destino (opcional)</label><select class='form-select' name='group_id'><option value=''>—</option>"+groupOptions+"</select></div>",
    "<div class='mb-3'><label class='form-label'>Adjuntos</label><input class='form-control' type='file' name='files' multiple></div>",
    "<button class='btn btn-primary w-100'>Crear ticket</button>",
    "</form></div></div>",
    "<div class='col-md-7'><div class='card p-4'><h2 class='h5 mb-3'>Mis tickets</h2>",
    "<div class='table-responsive'><table class='table align-middle'><thead><tr><th>ID</th><th>Ticket</th><th>Prioridad</th><th>Estado</th><th>Creado</th></tr></thead><tbody>"+rows+"</tbody></table></div>",
    "</div></div></div>"
  ].join("");

  res.send(layout("Portal cliente", req.csrfToken(), c, req));
});

app.post("/tickets", requireAuth, upload.array("files", 5), async (req,res)=>{
  const subject = req.body.subject;
  const description = req.body.description;
  const priority = req.body.priority || "Media";
  const category = req.body.category || "General";
  const sla_hours = Number(req.body.sla_hours || 72);
  const group_id = req.body.group_id || null;

  const id = uuidv4().slice(0,8).toUpperCase();
  const now = new Date().toISOString();
  const result = await run(db, "INSERT INTO tickets (uuid,user_id,subject,description,category,sla_hours,priority,status,group_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'Abierto',?,?,?)",
    [id, req.session.user.id, subject, description, category, sla_hours, priority, group_id, now, now]);
  const ticketId = result.lastID;

  if (req.files && req.files.length) {
    for (const f of req.files) {
      await run(db, "INSERT INTO attachments (ticket_id,filename,path,size,uploaded_at) VALUES (?,?,?,?,datetime('now'))",
        [ticketId, f.originalname, "/uploads/"+path.basename(f.path), f.size]);
    }
  }

  if (transporter) {
    try {
      await transporter.sendMail({ from: process.env.MAIL_FROM || "helpdesk@localhost", to: req.session.user.email, subject: "[Helpdesk] Ticket creado "+id, text: "Hemos recibido tu ticket "+id+"\n\nAsunto: "+subject+"\nPrioridad: "+priority+"\nCategoría: "+category+"\nSLA: "+sla_hours+"h" });
    } catch(e){ console.error("Mail error:", e.message); }
  }
  res.redirect("/client");
});

app.get("/admin", requireAdmin, async (req,res)=>{
  const q = req.query.q || "";
  const status = req.query.status || "";
  const priority = req.query.priority || "";
  const category = req.query.category || "";
  const from = req.query.from || "";
  const to = req.query.to || "";
  const group_id = req.query.group_id || "";
  const assignee = req.query.assignee || "";

  const where = []; const params = [];
  if (q) { where.push("(t.subject LIKE ? OR t.description LIKE ? OR t.uuid LIKE ?)"); params.push("%"+q+"%","%"+q+"%","%"+q+"%"); }
  if (status) { where.push("t.status = ?"); params.push(status); }
  if (priority) { where.push("t.priority = ?"); params.push(priority); }
  if (category) { where.push("t.category = ?"); params.push(category); }
  if (group_id) { where.push("t.group_id = ?"); params.push(group_id); }
  if (assignee) { where.push("t.assignee_user_id = ?"); params.push(assignee); }
  if (from) { where.push("date(t.created_at) >= date(?)"); params.push(from); }
  if (to) { where.push("date(t.created_at) <= date(?)"); params.push(to); }
  const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";

  const tickets = await all(db,
    "SELECT t.*, u.name as user_name, u.email as user_email, g.name as group_name, a.name as assignee_name "+
    "FROM tickets t JOIN users u ON u.id=t.user_id "+
    "LEFT JOIN groups g ON g.id=t.group_id "+
    "LEFT JOIN users a ON a.id=t.assignee_user_id "+
    whereSql + " ORDER BY t.created_at DESC", params);

  const groups = await all(db, "SELECT id,name FROM groups ORDER BY name");
  const agents = await all(db, "SELECT id,name FROM users WHERE is_admin=1 OR group_id IS NOT NULL ORDER BY name");

  function opts(list, value, label, sel) {
    return ["<option value=''>—</option>"].concat(list.map(x=>"<option value='"+x[value]+"'"+(String(x[value])===String(sel)?" selected":"")+">"+x[label]+"</option>")).join("");
  }

  const rows = tickets.map(t=>"<tr>"+
    "<td><span class='badge text-bg-light'>"+t.uuid+"</span></td>"+
    "<td><div class='fw-semibold'>"+t.subject+"</div><div class='text-muted small'>"+t.category+" • SLA "+t.sla_hours+"h</div><div class='small mt-1'>"+(t.description||"").substring(0,160)+((t.description||"").length>160?"…":"")+"</div>"+(t.id?"<div class='small mt-1'>Adjuntos: <a href='/admin/tickets/"+t.id+"/attachments'>ver</a></div>":"")+"</td>"+
    "<td>"+t.user_name+"<div class='text-muted small'>"+t.user_email+"</div></td>"+
    "<td><span class='badge text-bg-secondary'>"+t.priority+"</span></td>"+
    "<td>"+(t.group_name||"—")+"</td>"+
    "<td>"+(t.assignee_name||"—")+"</td>"+
    "<td>"+
      "<form method='POST' action='/tickets/"+t.id+"/status' class='d-flex gap-2 align-items-center'>"+
      "<input type='hidden' name='_csrf' value='"+csrfTokenFor(req)+"'>"+
      "<select name='status' class='form-select form-select-sm'>"+["Abierto","En progreso","En espera","Resuelto","Cerrado"].map(s=>"<option"+(s===t.status?" selected":"")+">"+s+"</option>").join("")+"</select>"+
      "<select name='assignee_user_id' class='form-select form-select-sm'>"+opts(agents,"id","name",t.assignee_user_id)+"</select>"+
      "<select name='group_id' class='form-select form-select-sm'>"+opts(groups,"id","name",t.group_id)+"</select>"+
      "<button class='btn btn-outline-primary btn-sm'>Actualizar</button>"+
      "</form>"+
    "</td>"+
    "<td class='text-nowrap'>"+new Date(t.created_at).toLocaleString("es-ES")+"</td>"+
  "</tr>").join("");

  const c = [
    "<div class='card p-4'>",
      "<h1 class='h5 m-0 mb-3'>Panel de administración</h1>",
      "<form class='row g-2 mb-3' method='GET' action='/admin'>",
        "<div class='col-md-3'><input class='form-control' name='q' placeholder='Buscar (texto/ID)' value='"+q+"'></div>",
        "<div class='col-md-2'><select class='form-select' name='status'><option value=''>Estado</option>"+["Abierto","En progreso","En espera","Resuelto","Cerrado"].map(s=>"<option"+(s===status?" selected":"")+">"+s+"</option>").join("")+"</select></div>",
        "<div class='col-md-2'><select class='form-select' name='priority'><option value=''>Prioridad</option>"+["Alta","Media","Baja"].map(p=>"<option"+(p===priority?" selected":"")+">"+p+"</option>").join("")+"</select></div>",
        "<div class='col-md-2'><input class='form-control' name='category' placeholder='Categoría' value='"+category+"'></div>",
        "<div class='col-md-1'><input class='form-control' type='date' name='from' value='"+from+"'></div>",
        "<div class='col-md-1'><input class='form-control' type='date' name='to' value='"+to+"'></div>",
        "<div class='col-md-2'><select class='form-select' name='group_id'><option value=''>Grupo</option>"+groups.map(g=>"<option value='"+g.id+"'"+(String(g.id)===String(group_id||"")?" selected":"")+">"+g.name+"</option>").join("")+"</select></div>",
        "<div class='col-md-2'><select class='form-select' name='assignee'><option value=''>Responsable</option>"+agents.map(a=>"<option value='"+a.id+"'"+(String(a.id)===String(assignee||"")?" selected":"")+">"+a.name+"</option>").join("")+"</select></div>",
        "<div class='col-md-2'><button class='btn btn-secondary w-100'>Filtrar</button></div>",
      "</form>",
      "<div class='table-responsive'><table class='table align-middle'><thead><tr><th>ID</th><th>Ticket</th><th>Cliente</th><th>Prioridad</th><th>Grupo</th><th>Responsable</th><th>Gestión</th><th>Creado</th></tr></thead><tbody>"+rows+"</tbody></table></div>",
    "</div>"
  ].join("");

  res.send(layout("Admin", csrfTokenFor(req), c, req));
});

app.get("/admin/tickets/:id/attachments", requireAdmin, async (req,res)=>{
  const files = await all(db, "SELECT * FROM attachments WHERE ticket_id=?", [req.params.id]);
  const list = files.length ? files.map(f=>"<li><a href='"+f.path+"' target='_blank' rel='noopener'>"+f.filename+"</a> <span class='text-muted'>("+Math.round(f.size/1024)+" KB)</span></li>").join("") : "<li class='text-muted'>No hay adjuntos</li>";
  const c = "<div class='card p-4'><h2 class='h5'>Adjuntos del ticket "+req.params.id+"</h2><ul>"+list+"</ul><a class='btn btn-secondary' href='/admin'>Volver</a></div>";
  res.send(layout("Adjuntos", csrfTokenFor(req), c, req));
});

app.post("/tickets/:id/status", requireAdmin, async (req,res)=>{
  const status = req.body.status;
  const assignee_user_id = req.body.assignee_user_id || null;
  const group_id = req.body.group_id || null;
  const valid = ["Abierto","En progreso","En espera","Resuelto","Cerrado"];
  if (status && valid.indexOf(status)===-1) return res.status(400).send("Estado invalido");
  await run(db, "UPDATE tickets SET status=COALESCE(?,status), assignee_user_id=COALESCE(?,assignee_user_id), group_id=COALESCE(?,group_id), updated_at=datetime('now') WHERE id=?",
    [status || null, assignee_user_id, group_id, req.params.id]);

  const t = await get(db, "SELECT t.*, u.email as user_email FROM tickets t JOIN users u ON u.id=t.user_id WHERE t.id=?", [req.params.id]);
  if (transporter && t) {
    try {
      await transporter.sendMail({ from: process.env.MAIL_FROM || "helpdesk@localhost", to: t.user_email, subject: "[Helpdesk] Ticket "+t.uuid+" actualizado", text: "Estado: "+(status||t.status)+"\nGrupo: "+(group_id||"—")+"\nResponsable: "+(assignee_user_id||"—") });
    } catch(e){ console.error("Mail error:", e.message); }
  }
  res.redirect("/admin");
});

app.use((req,res)=> res.status(404).send("No encontrado"));

init().then(()=>{
  app.listen(PORT, "0.0.0.0", ()=> console.log("Helpdesk portal listo en http://0.0.0.0:"+PORT+" (DATA_DIR="+DATA_DIR+")"));
}).catch(err=>{ console.error("DB init error", err); process.exit(1); });
