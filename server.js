// backend/server.js
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { body, validationResult } = require("express-validator");
const path = require("path");
const multer = require("multer");

require("dotenv").config();

const loginAttempts = {};
const MAX_ATTEMPTS = 3;
const LOCK_TIME = 30 * 60 * 1000;

const app = express();
const saltRounds = 10;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your-refresh-secret-key";

function log(...args) {
  const msg = args
    .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
    .join(" ");
  const ts = new Date().toLocaleString("en-US", { timeZone: "Asia/Bangkok" });
  console.log(`[${ts}] ${msg}`);
}

// ==== MySQL pool ====
const pool = mysql.createPool({
  connectionLimit: 10,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  charset: "utf8mb4",
  timezone: "+07:00",
  dateStrings: ["DATE"]
});

app.use(cors({ origin: ["https://himtang.com"], credentials: true }));
app.use(express.json());
app.use(cookieParser());

//app.use('/Backend/UserImage', express.static(path.join(__dirname, 'UserImage')));

// ---- signup (unchanged) ----
// app.post('/Backend/api/signup', …)  ← (ใส่ logic เดิมตามที่มีไป)

app.get("/Backend", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8"/>
        <title>Server Status</title>
      </head>
      <body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
        <h1>✅ Server is running</h1>
        <p>Time: ${new Date().toLocaleString()}</p>
      </body>
    </html>
  `);
});

app.post("/Backend/api/signup", async (req, res) => {
  const {
    fristname,
    lastname,
    dateofbirth,
    jobposition,
    center,
    side,
    institute,
    user,
    email,
    password,
  } = req.body;

  if (
    !fristname || !lastname || !dateofbirth || !jobposition ||
    !center || !side || !institute || !user || !email || !password
  ) {
    return res.status(400).json({ message: "กรอกข้อมูลให้ครบทุกช่อง" });
  }

  try {
    const conn = await pool.promise().getConnection();

    const [existing] = await conn.query(
      "SELECT id FROM users WHERE user = ? OR email = ?",
      [user, email]
    );

    if (existing.length > 0) {
      conn.release();
      return res.status(409).json({ message: "ชื่อผู้ใช้หรืออีเมลนี้มีอยู่แล้ว" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const defaultImage = `account.png`; // หรือใช้ "default.jpg"

    await conn.query(
      `INSERT INTO users 
        (firstname, lastname, dateofbirth, jobposition, center, side, institute, user, email, password, imageUrl) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        fristname,
        lastname,
        dateofbirth,
        jobposition,
        center,
        side,
        institute,
        user,
        email,
        hashedPassword,
        defaultImage
      ]
    );

    conn.release();
    res.status(201).json({ message: "สมัครสมาชิกสำเร็จ" });
  } catch (error) {
    console.error("❌ Signup Error:", error);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในระบบ" });
  }
});


// ---- signin: คืน JSON { accessToken, refreshToken } ----
app.post("/Backend/api/signin", async (req, res) => {
  const { user, password, captchaResponse } = req.body;
  if (!user || !password || !captchaResponse)
    return res.status(400).json({ message: "Missing required fields" });

  // brute-force lock
  if (
    loginAttempts[user]?.count >= MAX_ATTEMPTS &&
    Date.now() - loginAttempts[user].lastAttempt < LOCK_TIME
  ) {
    return res.status(429).json({ message: "Too many attempts" });
  }

  pool.getConnection((err, conn) => {
    if (err) return res.status(500).json({ message: "DB error" });
    conn.query(
      "SELECT * FROM users WHERE user = ?",
      [user],
      async (err, rows) => {
        conn.release();
        if (err) return res.status(500).json({ message: "DB query error" });
        if (rows.length === 0)
          return res.status(401).json({ message: "Invalid credentials" });

        const userRec = rows[0];
        const match = await bcrypt.compare(password, userRec.password);
        if (!match) {
          loginAttempts[user] = loginAttempts[user] || {
            count: 0,
            lastAttempt: 0
          };
          loginAttempts[user].count++;
          loginAttempts[user].lastAttempt = Date.now();
          return res.status(401).json({ message: "Invalid credentials" });
        }

        // reset attempts
        loginAttempts[user] = { count: 0, lastAttempt: Date.now() };
        const accessToken = jwt.sign({ userId: userRec.id }, JWT_SECRET, {
          expiresIn: "7d"
        });
        const refreshToken = jwt.sign({ userId: userRec.id }, REFRESH_SECRET, {
          expiresIn: "7d"
        });

        // (ถ้าใช้ cookie) set cookies…
        // res.cookie('token', accessToken, { httpOnly:true, secure:true, sameSite:'lax' });
        // res.cookie('refreshToken', refreshToken, { … });

        // คืน payload
        return res.json({
          message: "Login successful",
          accessToken,
          refreshToken
        });
      }
    );
  });
});

// ---- Bearer-auth middleware ----
function authenticateToken(req, res, next) {
  const header = req.headers["authorization"] || "";
  //console.log("🔑 Token:", req.headers['authorization']);
  if (!header.startsWith("Bearer "))
    return res.status(401).json({ message: "Unauthorized" });
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.userId };

    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

// ---- Protected: create schedule ----
app.post("/Backend/api/schedule", authenticateToken, (req, res) => {
  const { date, title, detail, type, related_user } = req.body;
  const [y, m, d] = date.split("-");
  const localDate = `${y}-${m}-${d}`;
  const sql = `INSERT INTO schedule(date,title,detail,type,created_by,related_user)
               VALUES(?,?,?,?,?,?)`;
  pool.query(
    sql,
    [localDate, title, detail, type, req.userId, related_user],
    (err) =>
      err
        ? res.status(500).json({ message: "Insert error" })
        : res.json({ message: "Saved" })
  );
});

// ---- Protected: update schedule ----
app.put("/Backend/api/schedule/:id", authenticateToken, (req, res) => {
  const { title, detail, type, related_user } = req.body;
  const id = req.params.id;
  const sql = `UPDATE schedule SET title=?,detail=?,type=?,related_user=?,updated_by=?,updated_at=NOW()
               WHERE id=?`;
  pool.query(sql, [title, detail, type, related_user, req.userId, id], (err) =>
    err
      ? res.status(500).json({ message: "Update error" })
      : res.json({ message: "Updated" })
  );
});

// ---- Protected: delete schedule ----
app.delete("/Backend/api/schedule/:id", authenticateToken, (req, res) => {
  const id = req.params.id;
  pool.query("DELETE FROM schedule WHERE id=?", [id], (err) =>
    err
      ? res.status(500).json({ message: "Delete error" })
      : res.json({ message: "Deleted" })
  );
});

// Multer config for image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "UserImage/"),
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

// --- fetch current user ---
app.get("/Backend/api/me", authenticateToken, (req, res) => {
  console.log("🔑 Fetching req:", req.user.id);
  const userId = req.user.id;
  console.log("🔑 Fetching user ID:", userId);
  pool.query(
    "SELECT id, user, email, firstname, lastname, dateofbirth, jobposition, center, side, institute, imageUrl  FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err) return res.status(500).json({ message: "Database error" });
      if (!results.length)
        return res.status(404).json({ message: "User not found" });
      // คืนข้อมูล user
      res.json(results[0]);
    }
  );
});

// POST: Upload profile image
app.post(
  "/Backend/api/upload-profile",
  authenticateToken,
  upload.single("image"),
  (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    console.log("File uploaded:", req.file);
    // เช็คว่าเป็นไฟล์รูปภาพไหม
    //console.log('File type:', req.file.mimetype);
    //console.log('File size:', req.file.size);
    //console.log('File path:', req.file.path);
    //console.log('File filename:', req.file.filename);
    const imageUrl = `https://himtang.com/Backend/UserImage/${req.file.filename}`;
    const userId = req.user.id;

    pool.query(
      "UPDATE users SET imageUrl = ? WHERE id = ?",
      [imageUrl, userId],
      (err) => {
        if (err) return res.status(500).json({ message: "Database error" });
        res.json({ imageUrl });
      }
    );
  }
);

// POST: Update user profile
app.post("/Backend/api/update-profile", authenticateToken, (req, res) => {
  const {
    firstname,
    lastname,
    email,
    jobposition,
    center,
    side,
    institute,
    imageUrl
  } = req.body;
  const userId = req.user.id;

  const sql = `UPDATE users SET firstname = ?, lastname = ?, email = ?, jobposition = ?, center = ?, side = ?, institute = ?, imageUrl = ? WHERE id = ?`;

  pool.query(
    sql,
    [
      firstname,
      lastname,
      email,
      jobposition,
      center,
      side,
      institute,
      imageUrl,
      userId
    ],
    (err, result) => {
      if (err) {
        console.error("❌ DB Error (update-profile):", err);
        return res
          .status(500)
          .json({ message: "Database error", error: err.message });
      }
      res.json({ success: true });
    }
  );
});

// ---- Public: list schedules ----
app.get("/Backend/api/schedule", (req, res) => {
  const sql = `
    SELECT s.id, s.date, s.title, s.detail, s.type, s.related_user, s.created_by,
           u.firstname,u.lastname
    FROM schedule s
    LEFT JOIN users u ON s.created_by=u.id`;
  pool.query(sql, (err, results) => {
    if (err) return res.status(500).json({ message: "DB error" });
    const out = results.map((item) => ({
      ...item,
      created_by_name:
        item.firstname && item.lastname
          ? item.firstname + " " + item.lastname
          : null,
      date:
        typeof item.date === "string"
          ? item.date
          : item.date.toISOString().slice(0, 10)
    }));
    res.json(out);
  });
});

// ---- Users list ----
app.get("/Backend/api/users", (req, res) => {
  const includeCenter = req.query.includeCenter === "true";
  const columns = includeCenter
    ? "id, firstname, lastname, center"
    : "id, firstname, lastname";

  pool.query(`SELECT ${columns} FROM users`, (err, rows) => {
    if (err) return res.status(500).json({ message: "DB error" });
    res.json(rows);
  });
});

// ใช้ชื่อ middleware ให้ตรงกับที่ประกาศไว้
app.post(
  "/Backend/api/logout",
  authenticateToken, // <-- เปลี่ยนจาก authenticateAccessToken
  async (req, res) => {
    try {
      const userId = req.user.id; // <-- ได้มาจาก middleware แล้ว
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
        path: "/Backend/api/refresh"
      });

      // 4) ส่งกลับ 204 No Content
      return res.sendStatus(204);
    } catch (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ message: "Logout failed" });
    }
  }
);

/*********************************จัดการรูปภาพ**********************/

// Serve static files จากโฟลเดอร์ UserImage
app.use(
  "/Backend/UserImage",
  express.static(path.join(__dirname, "UserImage"))
);

// API สำหรับส่ง URL ของรูปภาพ
app.get("/Backend/api/user-image/:filename", (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, "UserImage", filename);

  // เช็คว่ามีไฟล์อยู่จริงไหม
  if (!require("fs").existsSync(filePath)) {
    return res.status(404).json({ error: "Image not found" });
  }

  const imageUrl = `https://himtang.com/Backend/UserImage/${filename}`;
  res.json({ url: imageUrl });
});

app.get("/Backend/api/job", authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { year, month } = req.query;

  function formatDate(dateObj) {
    const y = dateObj.getFullYear();
    const m = String(dateObj.getMonth() + 1).padStart(2, "0");
    const d = String(dateObj.getDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
  }

  if (!year || !month) {
    return res.status(400).json({ message: "Missing year or month" });
  }

  const paddedMonth = String(month).padStart(2, "0");
  const start = `${year}-${paddedMonth}-01`;
  const endDate = new Date(year, parseInt(month), 0);
  const end = formatDate(endDate);

  const sql = `
  SELECT d.date, j.shift_code, w.title
  FROM (
    SELECT DATE_ADD(?, INTERVAL seq DAY) AS date
    FROM (
      SELECT @row := @row + 1 AS seq
      FROM information_schema.columns a,
           information_schema.columns b,
           (SELECT @row := -1) r
      LIMIT 31
    ) AS days
    WHERE DATE_ADD(?, INTERVAL seq DAY) <= ?
  ) d
  LEFT JOIN job j ON j.date = d.date AND j.user_id = ?
  LEFT JOIN works w ON d.date BETWEEN w.start_date AND w.end_date
`;

  pool.query(sql, [start, start, end, userId], (err, results) => {
    console.log("🔑 Job query:", sql, [start, start, end, userId]);
    if (err) {
      console.error("❌ SQL error", err);
      return res.status(500).json({ message: "DB error" });
    }

    // 👇 รวมข้อมูลทั้งหมดไว้ก่อน
    const grouped = {};

    for (let d = 1; d <= endDate.getDate(); d++) {
      const day = new Date(
        `${year}-${paddedMonth}-${String(d).padStart(2, "0")}`
      );
      const dateStr = formatDate(day);
      grouped[dateStr] = []; // เตรียมทุกวัน
    }

    results.forEach(({ date, shift_code, title }) => {
      if (!grouped[date]) grouped[date] = [];
      grouped[date].push({ shift_code, title });
    });

    // 👇 ใส่ A09 ถ้าไม่มี A00 หรือ A15 ในวันทำงาน (จันทร์-ศุกร์)
    for (let d = 1; d <= endDate.getDate(); d++) {
      const day = new Date(
        `${year}-${paddedMonth}-${String(d).padStart(2, "0")}`
      );
      const dateStr = formatDate(day);
      const dow = day.getDay();

      const shifts = grouped[dateStr] || [];

      const hasRealShift = shifts.some(
        (s) =>
          s.shift_code === "A00" ||
          s.shift_code === "A15" ||
          s.shift_code === "A09"
      );

      if (dow >= 1 && dow <= 5 && !hasRealShift) {
        const titleForThatDay =
          results.find((r) => r.date === dateStr && r.title)?.title || null;
        grouped[dateStr].push({ shift_code: "A09", title: titleForThatDay });
      }
    }

    // 👇 สร้าง output array จาก grouped
    const output = [];
    for (const [date, shifts] of Object.entries(grouped)) {
      const filtered = shifts.filter((s) => s.shift_code !== null); // ❌ ลบ shift ว่างทิ้ง
      if (filtered.length === 0) {
        output.push({ date, shift_code: null, title: null });
      } else {
        filtered.forEach(({ shift_code, title }) => {
          output.push({ date, shift_code, title });
        });
      }
    }

    res.json(output);
  });
});

app.post("/Backend/api/job", authenticateToken, (req, res) => {
  const { date, center, shifts } = req.body;
  const updated_by = req.user.id;

  if (!date || !center || !Array.isArray(shifts)) {
    return res.status(400).json({ message: "Missing fields" });
  }

  const conn = pool;

  // ลบข้อมูลเก่าของวันที่และศูนย์เดียวกันก่อน
  conn.query(
    "DELETE FROM job WHERE date = ? AND center = ?",
    [date, center],
    (err) => {
      if (err) return res.status(500).json({ message: "Delete old error" });

      // เตรียมข้อมูลใหม่
      const values = shifts.map((s) => [
        s.userId,
        date,
        s.shift,
        center,
        updated_by
      ]);

      const sql = `
        INSERT INTO job (user_id, date, shift_code, center, updated_by)
        VALUES ?
      `;
      conn.query(sql, [values], (err2, result) => {
        if (err2)
          return res
            .status(500)
            .json({ message: "Insert error", error: err2.message });
        res.json({
          message: "Job records inserted",
          count: result.affectedRows
        });
      });
    }
  );
});

app.put("/Backend/api/job/:id", authenticateToken, (req, res) => {
  const { date, shift_code } = req.body;
  const userId = req.user.id;
  const jobId = req.params.id;
  const sql =
    "UPDATE job SET date = ?, shift_code = ? WHERE id = ? AND user_id = ?";
  pool.query(sql, [date, shift_code, jobId, userId], (err) => {
    if (err) return res.status(500).json({ message: "Update error" });
    res.json({ message: "Job updated" });
  });
});

app.delete("/Backend/api/job/:id", authenticateToken, (req, res) => {
  const jobId = req.params.id;
  const userId = req.user.id;
  const sql = "DELETE FROM job WHERE id = ? AND user_id = ?";
  pool.query(sql, [jobId, userId], (err) => {
    if (err) return res.status(500).json({ message: "Delete error" });
    res.json({ message: "Job deleted" });
  });
});

// GET: ดึงรายการวันหยุดพิเศษและวันทำงานพิเศษ
app.get("/Backend/api/special-days", authenticateToken, (req, res) => {
  pool.query("SELECT * FROM special_days ORDER BY date", (err, results) => {
    if (err) return res.status(500).json({ message: "DB error" });
    res.json(results);
  });
});

// POST: เพิ่มวันหยุดหรือวันทำงานพิเศษ
app.post("/Backend/api/special-days", authenticateToken, (req, res) => {
  const { date, name, type } = req.body;
  const create_by = req.user.id;

  if (!date || !type)
    return res.status(400).json({ message: "Missing required fields" });

  const sql =
    "INSERT INTO special_days (date, name, type, create_by) VALUES (?, ?, ?, ?)";
  pool.query(sql, [date, name, type, create_by], (err, result) => {
    if (err)
      return res
        .status(500)
        .json({ message: "Insert error", error: err.message });
    res.json({ message: "Special day added", id: result.insertId });
  });
});

// PUT: แก้ไขรายการวันพิเศษตาม id
app.put("/Backend/api/special-days/:id", authenticateToken, (req, res) => {
  const id = req.params.id;
  const { date, name, type } = req.body;

  const sql =
    "UPDATE special_days SET date = ?, name = ?, type = ? WHERE id = ?";
  pool.query(sql, [date, name, type, id], (err) => {
    if (err) return res.status(500).json({ message: "Update error" });
    res.json({ message: "Special day updated" });
  });
});

// DELETE: ลบวันพิเศษตาม id
app.delete("/Backend/api/special-days/:id", authenticateToken, (req, res) => {
  const id = req.params.id;
  pool.query("DELETE FROM special_days WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ message: "Delete error" });
    res.json({ message: "Special day deleted" });
  });
});

app.get("/Backend/api/works", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const conn = await pool.promise().getConnection();

  try {
    // โหลดงานที่ผู้ใช้สร้างหรือเกี่ยวข้อง
    const [works] = await conn.query(
      `SELECT w.*, u.firstname AS creator_firstname, u.lastname AS creator_lastname
       FROM works w
       JOIN users u ON w.created_by = u.id
       WHERE w.created_by = ? 
         OR w.id IN (
           SELECT work_id FROM work_users WHERE user_id = ?
         )`,
      [userId, userId]
    );

    for (const work of works) {
      const [related] = await conn.query(
        `SELECT u.id, u.firstname, u.lastname FROM work_users wu
         JOIN users u ON wu.user_id = u.id
         WHERE wu.work_id = ?`,
        [work.id]
      );
      work.related_users = related;
      work.creator_name = `${work.creator_firstname} ${work.creator_lastname}`;
    }

    res.json(works);
  } catch (err) {
    console.error("❌ ดึงข้อมูลงานล้มเหลว:", err);
    res.status(500).json({ error: "Failed to fetch works" });
  } finally {
    conn.release();
  }
});


app.post("/Backend/api/works", authenticateToken, async (req, res) => {
  const { title, type, detail, related_users, start_date, end_date, location } =
    req.body;
  const created_by = req.user.id;
  const conn = await pool.promise().getConnection();
  try {
    await conn.beginTransaction();

    const [result] = await conn.query(
      `INSERT INTO works (title, type, detail, created_by, start_date, end_date, location)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [title, type, detail, created_by, start_date, end_date, location]
    );

    const workId = result.insertId;

    for (const userId of related_users) {
      try {
        console.log("🧩 INSERT work_id:", workId, "user_id:", userId);
        await conn.query(
          "INSERT INTO work_users (work_id, user_id) VALUES (?, ?)",
          [workId, userId]
        );
      } catch (err) {
        console.warn(
          "⚠️ INSERT FAILED for user",
          userId,
          err.code,
          err.message
        );
      }
    }

    await conn.commit();
    res.status(201).json({ message: "Work created", id: workId });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    res.status(500).json({ error: "Failed to create work" });
  } finally {
    conn.release();
  }
});

app.get("/Backend/api/job", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { year, month } = req.query;

  function formatDate(dateObj) {
    const y = dateObj.getFullYear();
    const m = String(dateObj.getMonth() + 1).padStart(2, "0");
    const d = String(dateObj.getDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
  }

  if (!year || !month) {
    return res.status(400).json({ message: "Missing year or month" });
  }

  const paddedMonth = String(month).padStart(2, "0");
  const start = `${year}-${paddedMonth}-01`;
  const endDate = new Date(year, parseInt(month), 0);
  const end = formatDate(endDate);

  try {
    const conn = pool.promise();

    // 1️⃣ ดึง job ของผู้ใช้
    const [jobRows] = await conn.query(
      `SELECT date, shift_code FROM job WHERE user_id = ? AND date BETWEEN ? AND ?`,
      [userId, start, end]
    );

    // 2️⃣ ดึง works ที่เกี่ยวข้องกับผู้ใช้ในช่วงเดียวกัน
    const [workRows] = await conn.query(
      `
      SELECT w.title, w.start_date AS date
      FROM works w
      LEFT JOIN work_users wu ON w.id = wu.work_id
      WHERE (w.created_by = ? OR wu.user_id = ?)
        AND w.start_date BETWEEN ? AND ?
      `,
      [userId, userId, start, end]
    );

    // 3️⃣ รวมข้อมูล
    const shiftsByDate = {};
    jobRows.forEach(({ date, shift_code }) => {
      if (!shiftsByDate[date]) shiftsByDate[date] = [];
      shiftsByDate[date].push({ shift_code, title: null }); // ยังไม่มี title
    });

    // 4️⃣ ใส่ title จาก works เข้าไป
    workRows.forEach(({ date, title }) => {
      if (!shiftsByDate[date]) shiftsByDate[date] = [];
      shiftsByDate[date].push({ shift_code: null, title }); // ไม่รู้ shift_code แต่มี title
    });

    // 5️⃣ เติม shift A09 ให้วันธรรมดาที่ยังไม่มีอะไรเลย
    for (let d = 1; d <= endDate.getDate(); d++) {
      const day = new Date(
        `${year}-${paddedMonth}-${String(d).padStart(2, "0")}`
      );
      const dateStr = formatDate(day);
      const dow = day.getDay();
      if (dow >= 1 && dow <= 5 && !shiftsByDate[dateStr]) {
        shiftsByDate[dateStr] = [{ shift_code: "A09", title: null }];
      }
    }

    // 6️⃣ แปลงเป็น array สำหรับส่งออก
    const output = [];
    for (const [date, entries] of Object.entries(shiftsByDate)) {
      entries.forEach(({ shift_code, title }) => {
        output.push({ date, shift_code, title });
      });
    }

    res.json(output);
  } catch (err) {
    console.error("❌ job API error:", err);
    res.status(500).json({ message: "DB error" });
  }
});

const PORT = process.env.PORT || 3000;
pool.getConnection((err, connection) => {
  if (err) {
    log("Database connection failed:", err.message);
    process.exit(1); // ถ้าต้องการให้แอปหยุดทำงานเมื่อ DB เชื่อมไม่ติด
  } else {
    log("Database connected successfully");
    connection.release();

    // ถ้าเชื่อม DB สำเร็จ จึงเริ่มฟังพอร์ต
    app.listen(PORT, () => {
      log(`Server started on port ${PORT}`);
    });
  }
});
