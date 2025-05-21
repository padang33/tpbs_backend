// backend/server.js
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const loginAttempts = {};
const MAX_ATTEMPTS = 3;
const LOCK_TIME = 30 * 60 * 1000;

const app = express();
const saltRounds = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'your-refresh-secret-key';

function log(...args) {
  const msg = args.map(a => typeof a==='string'? a : JSON.stringify(a)).join(' ');
  const ts = new Date().toLocaleString('en-US',{timeZone:'Asia/Bangkok'});
  console.log(`[${ts}] ${msg}`);
}

// ==== MySQL pool ====
const pool = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  charset: 'utf8mb4',
  timezone: '+07:00',
  dateStrings: ['DATE']
});

app.use(cors({ origin: ['https://himtang.com'], credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ---- signup (unchanged) ----
// app.post('/Backend/api/signup', …)  ← (ใส่ logic เดิมตามที่มีไป)

// ---- signin: คืน JSON { accessToken, refreshToken } ----
app.post("/Backend/api/signin", async (req, res) => {
  const { user, password, captchaResponse } = req.body;
  if (!user || !password || !captchaResponse)
    return res.status(400).json({ message: "Missing required fields" });

  // brute-force lock
  if (loginAttempts[user]?.count >= MAX_ATTEMPTS
    && Date.now() - loginAttempts[user].lastAttempt < LOCK_TIME) {
    return res.status(429).json({ message: "Too many attempts" });
  }

  pool.getConnection((err, conn) => {
    if (err) return res.status(500).json({ message: "DB error" });
    conn.query("SELECT * FROM users WHERE user = ?", [user], async (err, rows) => {
      conn.release();
      if (err) return res.status(500).json({ message: "DB query error" });
      if (rows.length === 0)
        return res.status(401).json({ message: "Invalid credentials" });

      const userRec = rows[0];
      const match = await bcrypt.compare(password, userRec.password);
      if (!match) {
        loginAttempts[user] = loginAttempts[user]||{count:0,lastAttempt:0};
        loginAttempts[user].count++;
        loginAttempts[user].lastAttempt = Date.now();
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // reset attempts
      loginAttempts[user] = { count: 0, lastAttempt: Date.now() };
      const accessToken  = jwt.sign({ userId: userRec.id }, JWT_SECRET, { expiresIn: '7d' });
      const refreshToken = jwt.sign({ userId: userRec.id }, REFRESH_SECRET, { expiresIn: '7d' });

      // (ถ้าใช้ cookie) set cookies…
      // res.cookie('token', accessToken, { httpOnly:true, secure:true, sameSite:'lax' });
      // res.cookie('refreshToken', refreshToken, { … });

      // คืน payload
      return res.json({ message:'Login successful', accessToken, refreshToken });
    });
  });
});

// ---- Bearer-auth middleware ----
function authenticateToken(req, res, next) {
  const header = req.headers['authorization'] || '';
  if (!header.startsWith('Bearer '))
    return res.status(401).json({ message:'Unauthorized' });
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ message:'Unauthorized' });
  }
}

// ---- Protected: create schedule ----
app.post('/Backend/api/schedule', authenticateToken, (req, res) => {
  const { date, title, detail, type, related_user } = req.body;
  const [y,m,d] = date.split('-');
  const localDate = `${y}-${m}-${d}`;
  const sql = `INSERT INTO schedule(date,title,detail,type,created_by,related_user)
               VALUES(?,?,?,?,?,?)`;
  pool.query(sql,
    [ localDate, title, detail, type, req.userId, related_user ],
    err => err
      ? res.status(500).json({ message:'Insert error' })
      : res.json({ message:'Saved' })
  );
});

// ---- Protected: update schedule ----
app.put('/Backend/api/schedule/:id', authenticateToken, (req,res)=>{
  const { title,detail,type,related_user } = req.body;
  const id = req.params.id;
  const sql = `UPDATE schedule SET title=?,detail=?,type=?,related_user=?,updated_by=?,updated_at=NOW()
               WHERE id=?`;
  pool.query(sql,
    [ title,detail,type,related_user,req.userId,id ],
    err => err
      ? res.status(500).json({ message:'Update error' })
      : res.json({ message:'Updated' })
  );
});

// ---- Protected: delete schedule ----
app.delete('/Backend/api/schedule/:id', authenticateToken, (req,res)=>{
  const id = req.params.id;
  pool.query('DELETE FROM schedule WHERE id=?',[id],
    err => err
      ? res.status(500).json({ message:'Delete error' })
      : res.json({ message:'Deleted' })
  );
});

// --- fetch current user ---
app.get('/Backend/api/me', authenticateToken, (req, res) => {
  const userId = req.userId;
  pool.query(
    'SELECT id, user, email, fristname, lastname, jobposition FROM users WHERE id = ?',
    [userId],
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      if (!results.length) return res.status(404).json({ message: 'User not found' });
      // คืนข้อมูล user
      res.json(results[0]);
    }
  );
});

// ---- Public: list schedules ----
app.get('/Backend/api/schedule', (req, res) => {
  const sql = `
    SELECT s.id, s.date, s.title, s.detail, s.type, s.related_user, s.created_by,
           u.fristname,u.lastname
    FROM schedule s
    LEFT JOIN users u ON s.created_by=u.id`;
  pool.query(sql, (err, results) => {
    if (err) return res.status(500).json({ message:'DB error' });
    const out = results.map(item => ({
      ...item,
      created_by_name:
        item.fristname && item.lastname
          ? item.fristname+' '+item.lastname
          : null,
      date: typeof item.date==='string'
        ? item.date
        : item.date.toISOString().slice(0,10)
    }));
    res.json(out);
  });
});

// ---- Users list ----
app.get('/Backend/api/users', (req, res) => {
  pool.query('SELECT id,fristname,lastname FROM users', (err,rows)=>{
    if(err) return res.status(500).json({ message:'DB error' });
    res.json(rows);
  });
});


// ใช้ชื่อ middleware ให้ตรงกับที่ประกาศไว้
app.post(
  "/Backend/api/logout",
  authenticateToken,              // <-- เปลี่ยนจาก authenticateAccessToken
  async (req, res) => {
    try {
      const userId = req.userId;  // <-- ได้มาจาก middleware แล้ว
      // 1) รีเซ็ตตัวนับ loginAttempts ตาม key เป็น userId
      delete loginAttempts[userId];

      // 2) เพิกถอน (revoke) refresh token ในฐานข้อมูล
      //    สมมติคุณมีตาราง refresh_tokens ที่เก็บ user_id กับ token
      await pool
        .promise()
        .query("DELETE FROM refresh_tokens WHERE user_id = ?", [userId]);

      // 3) ลบ cookie ถ้าเคย set ชื่อ refreshToken (path ต้องตรงกับที่ set ตอน login)
      res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/Backend/api/refresh",
      });

      // 4) ส่งกลับ 204 No Content
      return res.sendStatus(204);
    } catch (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ message: "Logout failed" });
    }
  }
);


const PORT = process.env.PORT||3000;
app.listen(PORT,()=>log(`Server started on port ${PORT}`));
