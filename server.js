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
const fs = require("fs");

function log(...args) {
  const msg = args
    .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
    .join(" ");
  const ts = new Date().toLocaleString("en-US", { timeZone: "Asia/Bangkok" });
  console.log(`[${ts}] ${msg}`);
}


// โฟลเดอร์สำหรับเก็บรูปข่าวประกาศ
const announcementsDir = path.join(__dirname, "uploads", "announcements");
if (!fs.existsSync(announcementsDir)) {
  fs.mkdirSync(announcementsDir, { recursive: true });
}

const announcementStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, announcementsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname || "");
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, "ann-" + unique + ext.toLowerCase());
  },
});

const announcementUpload = multer({
  storage: announcementStorage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
});

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
    [localDate, title, detail, type, req.user.id, related_user],
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
  pool.query(sql, [title, detail, type, related_user, req.user.id, id], (err) =>
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

// ==== Multer config for work chat uploads (images/files/videos) ====
const chatStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    let baseDir = path.join(__dirname, "uploads", "work_chat");

    if (file.mimetype && file.mimetype.startsWith("image/")) {
      baseDir = path.join(baseDir, "images");
    } else if (file.mimetype && file.mimetype.startsWith("video/")) {
      baseDir = path.join(baseDir, "videos");
    } else {
      baseDir = path.join(baseDir, "files");
    }

    cb(null, baseDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    const name = path.basename(file.originalname || "file", ext);
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, `${name}-${unique}${ext}`);
  }
});



const uploadChat = multer({
  storage: chatStorage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB ต่อไฟล์
  }
});


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

// แชทงาน
app.use(
  "/Backend/uploads/work_chat",
  express.static(path.join(__dirname, "uploads", "work_chat"))
);

// ปกงาน
app.use(
  "/Backend/uploads/work_covers",
  express.static(path.join(__dirname, "uploads", "work_covers"))
);

// รูปข่าวประกาศ
app.use(
  "/Backend/uploads/announcements",
  express.static(path.join(__dirname, "uploads", "announcements"))
);

// เสิร์ฟไฟล์ปกงานแบบตรง ๆ รองรับทั้งไฟล์เก่า/ใหม่
app.get("/Backend/uploads/work_covers/:filename", (req, res) => {
  const filename = req.params.filename;
  const dir = path.join(__dirname, "uploads", "work_covers");

  // 1) ลองชื่อเต็มก่อน (กรณีไฟล์ใหม่มีนามสกุล)
  let filePath = path.join(dir, filename);
  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }

app.use("/Backend/uploads", express.static(path.join(__dirname, "uploads")));


  // 2) ถ้าไม่เจอ และชื่อมีจุด → ลองตัดนามสกุล (กรณีไฟล์เก่าที่ไม่มี .jpg/.png)
  const dot = filename.lastIndexOf(".");
  if (dot !== -1) {
    const noExt = filename.slice(0, dot);
    const altPath = path.join(dir, noExt);
    if (fs.existsSync(altPath)) {
      // บอก browser ว่าเป็นรูป
      res.type("image/jpeg");
      return res.sendFile(altPath);
    }
  }

  return res.status(404).send("work_covers file not found");
});


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

// ดึงตารางกะ + งาน (works) มาทำเป็นรายวัน ให้ Calendar ใช้
app.get("/Backend/api/job", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { year, month } = req.query;

  // format date เป็น YYYY-MM-DD
  function formatDate(dateObj) {
    const y = dateObj.getFullYear();
    const m = String(dateObj.getMonth() + 1).padStart(2, "0");
    const d = String(dateObj.getDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
  }

  // แปลงช่วง start_date/end_date -> list รายวัน
  function expandDateRange(startStr, endStr) {
    if (!startStr || !endStr) return [];
    const out = [];
    let cur = new Date(startStr);
    const end = new Date(endStr);

    // ป้องกัน loop เพี้ยนกรณีวันที่ผิด
    if (isNaN(cur.getTime()) || isNaN(end.getTime())) return out;

    while (cur <= end) {
      out.push(formatDate(cur));
      cur.setDate(cur.getDate() + 1);
    }
    return out;
  }

  if (!year || !month) {
    return res.status(400).json({ message: "Missing year or month" });
  }

  const paddedMonth = String(month).padStart(2, "0");
  const start = `${year}-${paddedMonth}-01`;
  const endDate = new Date(parseInt(year, 10), parseInt(month, 10), 0); // วันสุดท้ายของเดือน
  const end = formatDate(endDate);

  try {
    const conn = pool.promise();

    // 1) ดึงกะจากตาราง job ของ user นี้ ในช่วงเดือนที่ขอ
    const [jobRows] = await conn.query(
      `SELECT date, shift_code
       FROM job
       WHERE user_id = ?
         AND date BETWEEN ? AND ?`,
      [userId, start, end]
    );

    // 2) ดึงงาน (works) ที่ user นี้เป็นคนสร้างหรือเป็นผู้เกี่ยวข้อง
    //    และช่วงวันที่ทับซ้อนกับเดือนนี้
    const [workRows] = await conn.query(
      `
  SELECT DISTINCT
    w.id,
    w.title,
    w.start_date,
    w.end_date
  FROM works w
  LEFT JOIN work_users wu ON wu.work_id = w.id
  WHERE (w.created_by = ? OR wu.user_id = ?)
    AND w.end_date >= ?
    AND w.start_date <= ?
    AND (w.is_closed IS NULL OR w.is_closed = 0)
  `,
      [userId, userId, start, end]
    );

    // 3) เตรียม object grouped[date] = [ { shift_code, title }, ... ]
    const grouped = {};

    // เตรียมทุกวันในเดือนไว้ก่อน
    const lastDay = endDate.getDate();
    for (let d = 1; d <= lastDay; d++) {
      const day = new Date(parseInt(year, 10), parseInt(month, 10) - 1, d);
      const dateStr = formatDate(day);
      grouped[dateStr] = [];
    }

    // 4) ใส่ job (กะจริง) ลงใน grouped
    jobRows.forEach((row) => {
      const dateStr =
        typeof row.date === "string" ? row.date : formatDate(row.date);
      if (!grouped[dateStr]) grouped[dateStr] = [];
      grouped[dateStr].push({
        shift_code: row.shift_code,
        title: null, // ยังไม่ผูกกับชื่อ work
      });
    });

    // 5) ใส่ works (ขยายช่วงหลายวันเป็นรายวัน) ลงใน grouped
    workRows.forEach((w) => {
      const dates = expandDateRange(w.start_date, w.end_date);
      dates.forEach((dStr) => {
        // เอาเฉพาะวันที่อยู่ในเดือนนี้
        if (dStr < start || dStr > end) return;
        if (!grouped[dStr]) grouped[dStr] = [];
        grouped[dStr].push({
          shift_code: null,     // งานนี้อาจไม่มีรหัสกะ
          title: w.title || "", // ชื่อ work
        });
      });
    });

    // โหลดวันพิเศษทั้งหมด + map เป็น index
    const [specialRows] = await conn.query(
      "SELECT date, type FROM special_days"
    );
    const specialMap = {};
    specialRows.forEach((row) => {
      specialMap[row.date] = row.type; // holiday หรือ workday
    });

    // 6) เติมกะเริ่มต้น A09 ให้ "วันทำงาน" ที่ไม่มี shift จริงเลย
    for (let d = 1; d <= lastDay; d++) {
      const day = new Date(parseInt(year, 10), parseInt(month, 10) - 1, d);
      const dateStr = formatDate(day);
      const dow = day.getDay(); // 0=อา,1=จ,...,6=ส

      const entries = grouped[dateStr] || [];

      const hasRealShift = entries.some((s) =>
        ["A00", "A09", "A15", "H00", "H09", "H15"].includes(s.shift_code)
      );

      const specialType = specialMap[dateStr];  // holiday / workday / undefined

      const isHolidaySpecial = specialType === "holiday";
      const isSpecialWorkday = specialType === "workday";
      const isNormalWeekday = dow >= 1 && dow <= 5; // จ.-ศ. ปกติ

      // ❌ วันหยุดพิเศษ ไม่ต้อง auto A09
      if (isHolidaySpecial) {
        continue;
      }

      // ✅ วันทำงานปกติ หรือวันที่ถูกกำหนดเป็น workday → auto A09 ถ้ายังไม่มี shift จริง
      if ((isNormalWeekday || isSpecialWorkday) && !hasRealShift) {
        const firstTitle = entries.find((s) => s.title)?.title || null;
        entries.unshift({
          shift_code: "A09",
          title: firstTitle,
        });
        grouped[dateStr] = entries;
      }
    }


    // 7) แปลง grouped -> array สำหรับส่งให้ frontend
    //    1 วันสามารถมีหลายแถวได้ (หลายงานใน 1 วัน)
    const output = [];
    for (const [date, entries] of Object.entries(grouped)) {
      if (!entries || entries.length === 0) {
        // ไม่มีทั้งกะและงาน -> ให้ส่งแถวว่างไป 1 แถว (จะใช้/ไม่ใช้ก็แล้วแต่ฝั่งแอป)
        output.push({ date, shift_code: null, title: null });
      } else {
        entries.forEach(({ shift_code, title }) => {
          output.push({
            date,
            shift_code: shift_code || null,
            title: title || null,
          });
        });
      }
    }

    // เรียงตามวันที่ก่อนส่งออก (กัน frontend ได้ลำดับแปลก ๆ)
    output.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));

    res.json(output);
  } catch (err) {
    console.error("❌ /Backend/api/job error:", err);
    res.status(500).json({ message: "DB error" });
  }
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

// PUT /Backend/api/job/:id  -> แก้ไขชื่อ, รายละเอียด, กำหนดการ, ผู้เกี่ยวข้อง
app.put("/Backend/api/job/:id", authenticateToken, async (req, res) => {
  const jobId = req.params.id;
  const { title, description, schedule_text, assigneeIds } = req.body;

  const conn = await pool.promise().getConnection();
  try {
    await conn.beginTransaction();

    await conn.query(
      "UPDATE job SET title = ?, description = ?, schedule_text = ? WHERE id = ?",
      [title, description, schedule_text, jobId]
    );

    if (Array.isArray(assigneeIds)) {
      await conn.query("DELETE FROM job_users WHERE job_id = ?", [jobId]);
      if (assigneeIds.length > 0) {
        const values = assigneeIds.map((uid) => [jobId, uid]);
        await conn.query(
          "INSERT INTO job_users (job_id, user_id) VALUES ?",
          [values]
        );
      }
    }

    await conn.commit();
    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    res.status(500).json({ error: "update job failed" });
  } finally {
    conn.release();
  }
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

// POST /Backend/api/job/:id/cover  -> อัปโหลดรูปปก
const uploadimg = multer({ dest: path.join(__dirname, "uploads/job_covers") });

app.post(
  "/Backend/api/job/:id/cover",
  authenticateToken,
  uploadimg.single("cover"),
  async (req, res) => {
    const jobId = req.params.id;
    const file = req.file;
    if (!file) {
      return res.status(400).json({ error: "no file" });
    }

    const relativePath = `/uploads/job_covers/${file.filename}`;

    try {
      await pool
        .promise()
        .query("UPDATE job SET cover_url = ? WHERE id = ?", [
          relativePath,
          jobId,
        ]);

      res.json({ ok: true, cover_url: relativePath });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "update cover failed" });
    }
  }
);

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

// GET: ดึงรายละเอียดงานตาม id (ใช้ตอนเปิดจาก Notification)
app.get("/Backend/api/works/:id", authenticateToken, async (req, res) => {
  const workId = parseInt(req.params.id, 10);
  const userId = req.user.id;

  if (Number.isNaN(workId)) {
    return res.status(400).json({ message: "Invalid work id" });
  }

  try {
    // 1) โหลดงานหลัก
    const [rows] = await pool
      .promise()
      .query(
        `SELECT w.*, u.firstname AS creator_firstname, u.lastname AS creator_lastname
         FROM works w
         JOIN users u ON w.created_by = u.id
         WHERE w.id = ?`,
        [workId]
      );

    if (!rows.length) {
      return res.status(404).json({ message: "Work not found" });
    }

    const work = rows[0];
    work.creator_name = `${work.creator_firstname} ${work.creator_lastname}`;

    // 2) โหลดผู้เกี่ยวข้อง
    const [related] = await pool
      .promise()
      .query(
        `SELECT u.id, u.firstname, u.lastname
         FROM work_users wu
         JOIN users u ON u.id = wu.user_id
         WHERE wu.work_id = ?`,
        [workId]
      );

    work.related_users = related;

    // 3) เช็คสิทธิ์ผู้ใช้ (ต้องเป็น creator หรืออยู่ใน related_users)
    const isCreator = work.created_by === userId;
    const isRelated = related.some((r) => r.id === userId);

    if (!isCreator && !isRelated) {
      return res.status(403).json({ message: "คุณไม่มีสิทธิ์ในงานนี้" });
    }

    return res.json({ work });
  } catch (err) {
    console.error("❌ GET /Backend/api/works/:id error:", err);
    return res.status(500).json({ message: "DB error" });
  }
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
      // ผู้เกี่ยวข้อง
      const [related] = await conn.query(
        `SELECT u.id, u.firstname, u.lastname
         FROM work_users wu
         JOIN users u ON wu.user_id = u.id
         WHERE wu.work_id = ?`,
        [work.id]
      );
      work.related_users = related;
      work.creator_name = `${work.creator_firstname} ${work.creator_lastname}`;

      // เวลาข้อความล่าสุดในงานนี้
      const [lastRows] = await conn.query(
        `SELECT MAX(created_at) AS last_msg_at
         FROM work_messages
         WHERE work_id = ?`,
        [work.id]
      );

      const lastMsgAt = lastRows[0]?.last_msg_at || null;

      // fallback: ถ้าไม่มีแชทเลย ใช้เวลาจากคอลัมน์ใน works แทน
      const fallback =
        work.updated_at ||
        work.created_at ||
        work.end_date ||
        work.start_date ||
        null;

      const lastActivity = lastMsgAt || fallback;

      // เก็บเป็น ISO string (frontend ใช้ได้ง่าย ถ้าอยากใช้)
      work.last_activity = lastActivity
        ? new Date(lastActivity).toISOString()
        : null;
    }

    // เรียงงานตามเวลาเคลื่อนไหวล่าสุด งานที่มีความเปลี่ยนแปลงล่าสุดอยู่บนสุด
    works.sort((a, b) => {
      const ta = a.last_activity ? new Date(a.last_activity).getTime() : 0;
      const tb = b.last_activity ? new Date(b.last_activity).getTime() : 0;
      return tb - ta;
    });

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

// ==== Helper: check that user belongs to this work (creator or in work_users) ====
async function ensureUserInWork(workId, userId) {
  const [rows] = await pool
    .promise()
    .query(
      `SELECT 1
       FROM works w
       LEFT JOIN work_users wu ON wu.work_id = w.id
       WHERE w.id = ?
         AND (w.created_by = ? OR wu.user_id = ?)
       LIMIT 1`,
      [workId, userId, userId]
    );
  return rows.length > 0;
}

// ==== Work chat APIs ====

// GET: โหลดข้อความแชทของงาน (มี pagination)
app.get("/Backend/api/works/:workId/messages", authenticateToken, async (req, res) => {
  const workId = parseInt(req.params.workId, 10);
  const userId = req.user.id;

  if (Number.isNaN(workId)) {
    return res.status(400).json({ message: "Invalid work id" });
  }

  // --- เช็คสิทธิ์ก่อนเหมือนเดิม ---
  try {
    const hasAccess = await ensureUserInWork(workId, userId);
    if (!hasAccess) {
      return res.status(403).json({ message: "คุณไม่มีสิทธิ์ในงานนี้" });
    }
  } catch (err) {
    console.error("❌ ensureUserInWork error:", err);
    return res.status(500).json({ message: "DB error" });
  }

  const conn = await pool.promise().getConnection();

  try {
    // ---- ดึงทุกข้อความในงานนี้ (ไม่มี LIMIT / beforeId แล้ว) ----
    const sqlMessages = `
      SELECT
        wm.*,
        u.firstname,
        u.lastname,
        u.imageUrl AS user_image
      FROM work_messages wm
      JOIN users u ON wm.user_id = u.id
      WHERE wm.work_id = ?
      ORDER BY wm.id DESC
    `;

    const [msgRows] = await conn.query(sqlMessages, [workId]);

    if (!msgRows.length) {
      return res.json({ messages: [] });
    }

    const msgIds = msgRows.map((m) => m.id);

    // ---- โหลด images / files / videos ของ message เหล่านี้ ----
    const [imgRows] = await conn.query(
      "SELECT * FROM work_message_images WHERE message_id IN (?)",
      [msgIds]
    );
    const [fileRows] = await conn.query(
      "SELECT * FROM work_message_files WHERE message_id IN (?)",
      [msgIds]
    );
    const [videoRows] = await conn.query(
      "SELECT * FROM work_message_videos WHERE message_id IN (?)",
      [msgIds]
    );

    // map รวมผล
    const msgMap = {};
    for (const row of msgRows) {
      msgMap[row.id] = {
        id: row.id,
        work_id: row.work_id,
        user_id: row.user_id,
        type: row.type,
        message: row.message,
        is_edited: !!row.is_edited,
        created_at: row.created_at,
        updated_at: row.updated_at,
        user: {
          id: row.user_id,
          firstname: row.firstname,
          lastname: row.lastname,
          imageUrl: row.user_image
        },
        images: [],
        files: [],
        video: null
      };
    }

    for (const img of imgRows) {
      if (msgMap[img.message_id]) {
        msgMap[img.message_id].images.push({
          id: img.id,
          url: img.image_url,
          width: img.width,
          height: img.height
        });
      }
    }

    for (const f of fileRows) {
      if (msgMap[f.message_id]) {
        msgMap[f.message_id].files.push({
          id: f.id,
          url: f.file_url,
          name: f.file_name,
          size: f.file_size,
          mime_type: f.mime_type
        });
      }
    }

    for (const v of videoRows) {
      if (msgMap[v.message_id]) {
        msgMap[v.message_id].video = {
          id: v.id,
          url: v.video_url,
          thumbnail_url: v.thumbnail_url,
          duration: v.duration,
          width: v.width,
          height: v.height
        };
      }
    }

    const messages = msgRows.map((m) => msgMap[m.id]);

    // ---- ไม่ต้อง hasMore / nextBeforeId แล้ว ----
    res.json({ messages });
  } catch (err) {
    console.error("❌ GET work messages error:", err);
    res.status(500).json({ message: "DB error" });
  } finally {
    conn.release();
  }
});


// POST: ส่งข้อความแชท (text / image / file / video)
// helper ส่ง push ไป Expo (บนสุดของไฟล์ server.js ก็ได้)
async function sendExpoPushToUsers({ users, title, body, data, excludeUserId, excludeToken }) {
  try {
    const messages = users
      .filter(u =>
        u.push_token &&
        (!excludeUserId || u.id !== excludeUserId) &&
        (!excludeToken || u.push_token !== excludeToken)
      )
      .map(u => ({
        to: u.push_token,
        sound: "default",
        title,
        body,
        data
      }));

    if (!messages.length) {
      console.log("🔕 No targets to push");
      return;
    }

    await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Accept-encoding": "gzip, deflate",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(messages)
    });
  } catch (err) {
    console.error("❌ sendExpoPushToUsers error:", err);
  }
}



// POST: ส่งข้อความแชท (text / image / file / video)
// POST: ส่งข้อความแชท (text / image / file / video)

// POST: ส่งข้อความแชท (text / image / file / video)
app.post(
  "/Backend/api/works/:workId/messages",
  authenticateToken,
  uploadChat.fields([
    { name: "images", maxCount: 10 },
    { name: "files", maxCount: 10 },
    { name: "video", maxCount: 1 }
  ]),
  async (req, res) => {
    const workId = parseInt(req.params.workId, 10);
    const userId = req.user.id;
    let { type, message } = req.body;

    if (Number.isNaN(workId)) {
      return res.status(400).json({ message: "Invalid work id" });
    }

    type = (type || "").toLowerCase();
    if (!["text", "image", "file", "video"].includes(type)) {
      return res.status(400).json({ message: "Invalid type" });
    }

    try {
      const hasAccess = await ensureUserInWork(workId, userId);
      if (!hasAccess) {
        return res.status(403).json({ message: "คุณไม่มีสิทธิ์ในงานนี้" });
      }
    } catch (err) {
      console.error("❌ ensureUserInWork error:", err);
      return res.status(500).json({ message: "DB error" });
    }

    const images = (req.files && req.files["images"]) || [];
    const files = (req.files && req.files["files"]) || [];
    const videoFiles = (req.files && req.files["video"]) || [];

    if (type === "text" && (!message || !message.trim())) {
      return res.status(400).json({ message: "ข้อความว่าง" });
    }
    if (type === "image" && !images.length)
      return res.status(400).json({ message: "ต้องมีรูปอย่างน้อย 1 รูป" });
    if (type === "file" && !files.length)
      return res.status(400).json({ message: "ต้องมีไฟล์อย่างน้อย 1 ไฟล์" });
    if (type === "video" && !videoFiles.length)
      return res.status(400).json({ message: "ต้องมีวิดีโอ" });

    const conn = await pool.promise().getConnection();

    try {
      await conn.beginTransaction();

      // 1) INSERT message
      const [result] = await conn.query(
        `INSERT INTO work_messages
         (work_id, user_id, type, message, is_edited, created_at)
         VALUES (?, ?, ?, ?, 0, UTC_TIMESTAMP())`,
        [workId, userId, type, message || null]
      );
      const msgId = result.insertId;

      // 2) INSERT attachments
      for (const img of images) {
        const url = `https://himtang.com/Backend/uploads/work_chat/images/${img.filename}`;
        await conn.query(
          `INSERT INTO work_message_images (message_id, image_url)
           VALUES (?, ?)`,
          [msgId, url]
        );
      }

      for (const f of files) {
        const url = `https://himtang.com/Backend/uploads/work_chat/files/${f.filename}`;
        await conn.query(
          `INSERT INTO work_message_files
           (message_id, file_url, file_name, file_size, mime_type)
           VALUES (?, ?, ?, ?, ?)`,
          [msgId, url, f.originalname, f.size, f.mimetype]
        );
      }

      if (videoFiles.length) {
        const v = videoFiles[0];
        const url = `https://himtang.com/Backend/uploads/work_chat/videos/${v.filename}`;
        await conn.query(
          `INSERT INTO work_message_videos
           (message_id, video_url, thumbnail_url)
           VALUES (?, ?, '')`,
          [msgId, url]
        );
      }

      await conn.commit();

      // 3) โหลด message ที่เพิ่งสร้างเพื่อตอบกลับ
      const [baseRows] = await conn.query(
        `SELECT wm.*, u.firstname, u.lastname, u.imageUrl AS user_image
         FROM work_messages wm
         JOIN users u ON wm.user_id = u.id
         WHERE wm.id = ?`,
        [msgId]
      );
      const base = baseRows[0];

      const [imgRows] = await conn.query(
        `SELECT * FROM work_message_images WHERE message_id = ?`,
        [msgId]
      );
      const [fileRows] = await conn.query(
        `SELECT * FROM work_message_files WHERE message_id = ?`,
        [msgId]
      );
      const [videoRows] = await conn.query(
        `SELECT * FROM work_message_videos WHERE message_id = ?`,
        [msgId]
      );

      const messageObj = {
        id: base.id,
        work_id: base.work_id,
        user_id: base.user_id,
        type: base.type,
        message: base.message,
        is_edited: !!base.is_edited,
        created_at: base.created_at,
        updated_at: base.updated_at,
        user: {
          id: base.user_id,
          firstname: base.firstname,
          lastname: base.lastname,
          imageUrl: base.user_image
        },
        images: imgRows.map(img => ({
          id: img.id,
          url: img.image_url,
          width: img.width,
          height: img.height
        })),
        files: fileRows.map(f => ({
          id: f.id,
          url: f.file_url,
          name: f.file_name,
          size: f.file_size,
          mime_type: f.mime_type
        })),
        video: videoRows.length
          ? {
            id: videoRows[0].id,
            url: videoRows[0].video_url,
            thumbnail_url: videoRows[0].thumbnail_url,
            duration: videoRows[0].duration,
            width: videoRows[0].width,
            height: videoRows[0].height
          }
          : null
      };

      // 4) PUSH NOTIFICATION (กรองคนส่งและ token คนส่งออก)
      try {
        // token ของคนส่ง
        const [[senderRow = {}]] = await conn.query(
          "SELECT push_token FROM users WHERE id = ?",
          [userId]
        );
        const senderToken = senderRow.push_token || null;

        // ผู้ใช้ทั้งหมดในงานนี้ (creator + related_users)
        const [targets] = await conn.query(
          `
          SELECT DISTINCT u.id, u.push_token
          FROM users u
          LEFT JOIN work_users wu ON wu.user_id = u.id
          LEFT JOIN works w ON w.id = ? AND w.created_by = u.id
          WHERE (wu.work_id = ? OR w.id IS NOT NULL)
            AND u.push_token IS NOT NULL
          `,
          [workId, workId]
        );

        // กรองทิ้ง: คนส่ง + device เดียวกับคนส่ง
        const notifyUsers = targets.filter(
          (t) =>
            t.id !== userId &&
            (!senderToken || t.push_token !== senderToken)
        );

        if (notifyUsers.length) {
          const senderName = `${base.firstname} ${base.lastname}`.trim();
          const [workRows] = await conn.query(
            "SELECT title FROM works WHERE id = ?",
            [workId]
          );
          const work = workRows[0] || { title: `งาน #${workId}` };

          let body = "";
          if (type === "text") {
            const t = (message || "").trim();
            body = t
              ? `${senderName}: ${t.slice(0, 60)}`
              : `${senderName} ส่งข้อความใหม่`;
          } else if (type === "image") {
            body = `${senderName} ส่งรูปภาพ`;
          } else if (type === "file") {
            body = `${senderName} ส่งไฟล์แนบ`;
          } else if (type === "video") {
            body = `${senderName} ส่งวิดีโอ`;
          }

          const payloads = notifyUsers.map((u) => ({
            to: u.push_token,
            sound: "default",
            title: `แชทในงาน: ${work.title}`,
            body,
            data: { type: "work_chat", workId }
          }));

          await fetch("https://exp.host/--/api/v2/push/send", {
            method: "POST",
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json"
            },
            body: JSON.stringify(payloads)
          });
        } else {
          console.log("🔕 No targets after filter (no push sent).");
        }
      } catch (pushErr) {
        console.error("❌ push error:", pushErr);
        // ไม่ให้ส่งผลกับการส่งข้อความหลัก
      }

      res.status(201).json({ message: messageObj });
    } catch (err) {
      await conn.rollback();
      console.error("❌ POST message error:", err);
      res.status(500).json({ message: "DB error" });
    } finally {
      conn.release();
    }
  }
);



/*app.get("/Backend/api/job", authenticateToken, async (req, res) => {
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
});*/

// ✅ ดึงเฉพาะข้อความที่ใหม่กว่า afterId
app.get("/Backend/api/works/:workId/messages/new", authenticateToken, async (req, res) => {
  const workId = parseInt(req.params.workId, 10);
  const userId = req.user.id;
  const afterId = parseInt(req.query.afterId || "0", 10);

  if (Number.isNaN(workId)) {
    return res.status(400).json({ message: "Invalid work id" });
  }

  try {
    const hasAccess = await ensureUserInWork(workId, userId);
    if (!hasAccess) {
      return res.status(403).json({ message: "คุณไม่มีสิทธิ์ในงานนี้" });
    }
  } catch (err) {
    console.error("❌ ensureUserInWork error:", err);
    return res.status(500).json({ message: "DB error" });
  }

  const conn = await pool.promise().getConnection();

  try {
    // ดึงเฉพาะข้อความใหม่กว่า afterId
    const sqlMessages = `
      SELECT
        wm.*,
        u.firstname,
        u.lastname,
        u.imageUrl AS user_image
      FROM work_messages wm
      JOIN users u ON wm.user_id = u.id
      WHERE wm.work_id = ? AND wm.id > ?
      ORDER BY wm.id ASC   -- เก่า -> ใหม่
    `;

    const [msgRows] = await conn.query(sqlMessages, [workId, afterId]);

    if (!msgRows.length) {
      return res.json({ messages: [] });
    }

    const msgIds = msgRows.map((m) => m.id);

    const [imgRows] = await conn.query(
      "SELECT * FROM work_message_images WHERE message_id IN (?)",
      [msgIds]
    );
    const [fileRows] = await conn.query(
      "SELECT * FROM work_message_files WHERE message_id IN (?)",
      [msgIds]
    );
    const [videoRows] = await conn.query(
      "SELECT * FROM work_message_videos WHERE message_id IN (?)",
      [msgIds]
    );

    const msgMap = {};
    for (const row of msgRows) {
      msgMap[row.id] = {
        id: row.id,
        work_id: row.work_id,
        user_id: row.user_id,
        type: row.type,
        message: row.message,
        is_edited: !!row.is_edited,
        created_at: row.created_at,
        updated_at: row.updated_at,
        user: {
          id: row.user_id,
          firstname: row.firstname,
          lastname: row.lastname,
          imageUrl: row.user_image
        },
        images: [],
        files: [],
        video: null
      };
    }

    for (const img of imgRows) {
      if (msgMap[img.message_id]) {
        msgMap[img.message_id].images.push({
          id: img.id,
          url: img.image_url,
          width: img.width,
          height: img.height
        });
      }
    }

    for (const f of fileRows) {
      if (msgMap[f.message_id]) {
        msgMap[f.message_id].files.push({
          id: f.id,
          url: f.file_url,
          name: f.file_name,
          size: f.file_size,
          mime_type: f.mime_type
        });
      }
    }

    for (const v of videoRows) {
      if (msgMap[v.message_id]) {
        msgMap[v.message_id].video = {
          id: v.id,
          url: v.video_url,
          thumbnail_url: v.thumbnail_url,
          duration: v.duration,
          width: v.width,
          height: v.height
        };
      }
    }

    const messages = msgRows.map((m) => msgMap[m.id]);
    res.json({ messages });
  } catch (err) {
    console.error("❌ GET work messages/new error:", err);
    res.status(500).json({ message: "DB error" });
  } finally {
    conn.release();
  }
});


app.post("/Backend/api/register-push-token", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { token } = req.body;

  if (!token) return res.status(400).json({ message: "Missing token" });

  try {
    const conn = await pool.promise().getConnection();
    try {
      // 1) เคลียร์ token นี้ออกจาก user คนอื่นก่อน
      await conn.query(
        "UPDATE users SET push_token = NULL WHERE push_token = ? AND id <> ?",
        [token, userId]
      );

      // 2) เซฟ token ให้ user ปัจจุบัน
      await conn.query(
        "UPDATE users SET push_token = ? WHERE id = ?",
        [token, userId]
      );

      res.json({ message: "Token saved" });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("❌ Token save error:", err);
    res.status(500).json({ message: "Failed to save token" });
  }
});


app.post("/Backend/api/test-push", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [[{ push_token } = {}]] = await pool
      .promise()
      .query("SELECT push_token FROM users WHERE id = ?", [userId]);

    if (!push_token) {
      return res.status(400).json({ message: "ยังไม่มี push token ในระบบ" });
    }

    const { Expo } = require("expo-server-sdk");
    const expo = new Expo();

    const message = {
      to: push_token,
      sound: "default",
      title: "🔔 ทดสอบแจ้งเตือน",
      body: "Push นี้ส่งจากปุ่ม Test Push",
      data: { test: true },
    };

    const result = await expo.sendPushNotificationsAsync([message]);
    console.log("✅ Push result:", result);

    res.json({ message: "ส่งแจ้งเตือนแล้ว", result });
  } catch (err) {
    console.error("❌ Push error:", err);
    res.status(500).json({ message: "เกิดข้อผิดพลาดในการส่งแจ้งเตือน" });
  }
});

// PUT: แก้ไขข้อความ (เฉพาะข้อความ type="text" และเจ้าของข้อความเท่านั้น)
app.put(
  "/Backend/api/works/:workId/messages/:messageId",
  authenticateToken,
  async (req, res) => {
    const workId = parseInt(req.params.workId, 10);
    const messageId = parseInt(req.params.messageId, 10);
    const userId = req.user.id;
    const { message } = req.body;

    if (Number.isNaN(workId) || Number.isNaN(messageId)) {
      return res.status(400).json({ message: "Invalid id" });
    }
    if (!message || !message.trim()) {
      return res.status(400).json({ message: "ข้อความว่าง" });
    }

    const conn = await pool.promise().getConnection();
    try {
      // ตรวจสอบว่าข้อความนี้เป็นของ user นี้ และเป็นงานที่ user มีสิทธิ์
      const [rows] = await conn.query(
        `SELECT wm.*, w.created_by
         FROM work_messages wm
         JOIN works w ON wm.work_id = w.id
         WHERE wm.id = ? AND wm.work_id = ?`,
        [messageId, workId]
      );

      if (!rows.length) {
        return res.status(404).json({ message: "ไม่พบข้อความ" });
      }

      const msg = rows[0];
      if (msg.user_id !== userId) {
        return res.status(403).json({ message: "คุณไม่มีสิทธิ์แก้ไขข้อความนี้" });
      }
      if (msg.type !== "text") {
        return res
          .status(400)
          .json({ message: "อนุญาตให้แก้ไขได้เฉพาะข้อความตัวอักษรเท่านั้น" });
      }

      await conn.query(
        `UPDATE work_messages
         SET message = ?, is_edited = 1, updated_at = UTC_TIMESTAMP()
         WHERE id = ?`,
        [message.trim(), messageId]
      );

      // ดึงข้อมูลข้อความที่อัปเดตแล้วกลับไปในรูปแบบเดียวกับตอน POST
      const [baseRows] = await conn.query(
        `SELECT wm.*, u.firstname, u.lastname, u.imageUrl AS user_image
         FROM work_messages wm
         JOIN users u ON wm.user_id = u.id
         WHERE wm.id = ?`,
        [messageId]
      );
      const base = baseRows[0];

      const [imgRows] = await conn.query(
        "SELECT * FROM work_message_images WHERE message_id = ?",
        [messageId]
      );
      const [fileRows] = await conn.query(
        "SELECT * FROM work_message_files WHERE message_id = ?",
        [messageId]
      );
      const [videoRows] = await conn.query(
        "SELECT * FROM work_message_videos WHERE message_id = ?",
        [messageId]
      );

      const messageObj = {
        id: base.id,
        work_id: base.work_id,
        user_id: base.user_id,
        type: base.type,
        message: base.message,
        is_edited: !!base.is_edited,
        created_at: base.created_at,
        updated_at: base.updated_at,
        user: {
          id: base.user_id,
          firstname: base.firstname,
          lastname: base.lastname,
          imageUrl: base.user_image
        },
        images: imgRows.map((img) => ({
          id: img.id,
          url: img.image_url,
          width: img.width,
          height: img.height
        })),
        files: fileRows.map((f) => ({
          id: f.id,
          url: f.file_url,
          name: f.file_name,
          size: f.file_size,
          mime_type: f.mime_type
        })),
        video: videoRows.length
          ? {
            id: videoRows[0].id,
            url: videoRows[0].video_url,
            thumbnail_url: videoRows[0].thumbnail_url,
            duration: videoRows[0].duration,
            width: videoRows[0].width,
            height: videoRows[0].height
          }
          : null
      };

      res.json({ message: messageObj });
    } catch (err) {
      console.error("❌ PUT work message error:", err);
      res.status(500).json({ message: "DB error" });
    } finally {
      conn.release();
    }
  }
);

// DELETE: ลบข้อความ (เฉพาะเจ้าของข้อความเท่านั้น)
app.delete(
  "/Backend/api/works/:workId/messages/:messageId",
  authenticateToken,
  async (req, res) => {
    const workId = parseInt(req.params.workId, 10);
    const messageId = parseInt(req.params.messageId, 10);
    const userId = req.user.id;

    if (Number.isNaN(workId) || Number.isNaN(messageId)) {
      return res.status(400).json({ message: "Invalid id" });
    }

    const conn = await pool.promise().getConnection();
    try {
      const [rows] = await conn.query(
        `SELECT wm.*, w.created_by
         FROM work_messages wm
         JOIN works w ON wm.work_id = w.id
         WHERE wm.id = ? AND wm.work_id = ?`,
        [messageId, workId]
      );

      if (!rows.length) {
        return res.status(404).json({ message: "ไม่พบข้อความ" });
      }

      const msg = rows[0];
      if (msg.user_id !== userId) {
        return res.status(403).json({ message: "คุณไม่มีสิทธิ์ลบข้อความนี้" });
      }

      // ลบ attachments ก่อน (ถ้ามี)
      await conn.query(
        "DELETE FROM work_message_images WHERE message_id = ?",
        [messageId]
      );
      await conn.query(
        "DELETE FROM work_message_files WHERE message_id = ?",
        [messageId]
      );
      await conn.query(
        "DELETE FROM work_message_videos WHERE message_id = ?",
        [messageId]
      );

      // ลบตัวข้อความ
      await conn.query("DELETE FROM work_messages WHERE id = ?", [messageId]);

      return res.sendStatus(204);
    } catch (err) {
      console.error("❌ DELETE work message error:", err);
      res.status(500).json({ message: "DB error" });
    } finally {
      conn.release();
    }
  }
);

// อัปเดตงาน (ใช้ได้ทั้งปิดงาน และแก้รายละเอียด)
app.put("/Backend/api/works/:id", authenticateToken, async (req, res) => {
  const workId = parseInt(req.params.id, 10);
  const userId = req.user.id;

  if (Number.isNaN(workId)) {
    return res.status(400).json({ message: "workId ไม่ถูกต้อง" });
  }

  const {
    title,
    type,
    detail,
    location,
    start_date,
    end_date,
    related_users,   // array ของ user_id
    is_closed,
  } = req.body;

  const conn = await pool.promise().getConnection();

  try {
    await conn.beginTransaction();

    // โหลดงานและเช็คสิทธิ์
    const [rows] = await conn.query("SELECT * FROM works WHERE id = ?", [
      workId,
    ]);
    if (!rows.length) {
      await conn.rollback();
      return res.status(404).json({ message: "ไม่พบงาน" });
    }
    const work = rows[0];

    if (work.created_by !== userId) {
      await conn.rollback();
      return res
        .status(403)
        .json({ message: "คุณไม่มีสิทธิ์แก้ไขงานนี้ (ต้องเป็นคนสร้างงาน)" });
    }

    // สร้าง list field ที่จะอัปเดตแบบ dynamic
    const fields = [];
    const params = [];

    if (title !== undefined) {
      fields.push("title = ?");
      params.push(title);
    }
    if (type !== undefined) {
      fields.push("type = ?");
      params.push(type);
    }
    if (detail !== undefined) {
      fields.push("detail = ?");
      params.push(detail);
    }
    if (location !== undefined) {
      fields.push("location = ?");
      params.push(location);
    }
    if (start_date !== undefined) {
      fields.push("start_date = ?");
      params.push(start_date || null);
    }
    if (end_date !== undefined) {
      fields.push("end_date = ?");
      params.push(end_date || null);
    }
    if (is_closed !== undefined) {
      fields.push("is_closed = ?");
      params.push(is_closed ? 1 : 0);
    }

    if (fields.length > 0) {
      params.push(workId);
      await conn.query(
        `UPDATE works SET ${fields.join(", ")} WHERE id = ?`,
        params
      );
    }

    // อัปเดตรายชื่อผู้เกี่ยวข้องถ้ามีส่งมา
    if (Array.isArray(related_users)) {
      await conn.query("DELETE FROM work_users WHERE work_id = ?", [workId]);

      for (const uid of related_users) {
        await conn.query(
          "INSERT INTO work_users (work_id, user_id) VALUES (?, ?)",
          [workId, uid]
        );
      }
    }

    await conn.commit();
    res.json({ message: "อัปเดตงานเรียบร้อยแล้ว" });
  } catch (err) {
    console.error("❌ PUT /Backend/api/works/:id error:", err);
    await conn.rollback();
    res.status(500).json({ message: "DB error" });
  } finally {
    conn.release();
  }
});

const uploadWorkCover = multer({
  storage: multer.memoryStorage(),
});

// ==== ข่าวประกาศ ====
// POST /Backend/api/announcements  -> เพิ่มข่าวประกาศ (มีรูป/ไม่มีรูปก็ได้)
app.post(
  "/Backend/api/announcements",
  authenticateToken,
  announcementUpload.single("image"),
  async (req, res) => {
    const { title, content, bg_color, start_date, end_date } = req.body;
    const file = req.file;

    if (!title || !title.trim()) {
      return res.status(400).json({ message: "missing title" });
    }

    const filename = file ? file.filename : null;

    const startDate =
      typeof start_date === "string" && start_date.trim() !== ""
        ? start_date.trim()
        : null;
    const endDate =
      typeof end_date === "string" && end_date.trim() !== ""
        ? end_date.trim()
        : null;
    const bgColor =
      typeof bg_color === "string" && bg_color.trim() !== ""
        ? bg_color.trim()
        : null;

    try {
      const conn = pool.promise();
      const [r] = await conn.query(
        `
        INSERT INTO announcements
          (title, content, bg_color, start_date, end_date, image_url, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [title.trim(), content || "", bgColor, startDate, endDate, filename, req.user.id]
      );

      res.json({
        id: r.insertId,
        title: title.trim(),
        content: content || "",
        bg_color: bgColor,
        start_date: startDate,
        end_date: endDate,
        image_url: filename
          ? "https://himtang.com/Backend/uploads/announcements/" + filename
          : null,
      });
    } catch (err) {
      console.error("❌ POST /announcements error:", err);
      res.status(500).json({ message: "DB error" });
    }
  }
);

// GET /Backend/api/announcements
// ดึงรายการข่าวประกาศ (รองรับ limit + ฟิลเตอร์ช่วงวัน start/end)
// ถ้าไม่ส่ง start/end มาเลย → ใช้เงื่อนไข "กำลังประกาศอยู่วันนี้" เหมือนเดิม
app.get(
  "/Backend/api/announcements",
  authenticateToken,
  async (req, res) => {
    try {
      const limit = parseInt(req.query.limit || 20, 10);
      const { start, end } = req.query; // YYYY-MM-DD

      let where = "1=1";
      const params = [];

      if (start || end) {
        // filter ตามช่วงวันที่ที่ทับซ้อนกับ start/end ที่ส่งมา
        if (start) {
          // ข่าวที่ยังไม่จบก่อนวันที่ start
          where += " AND (a.end_date IS NULL OR a.end_date >= ?)";
          params.push(start);
        }
        if (end) {
          // ข่าวที่เริ่มไม่หลังจาก end
          where += " AND (a.start_date IS NULL OR a.start_date <= ?)";
          params.push(end);
        }
      } else {
        // โหมดเดิม: เอาเฉพาะที่กำลังประกาศวันนี้
        where +=
          " AND (a.start_date IS NULL OR a.start_date <= CURDATE())" +
          " AND (a.end_date IS NULL OR a.end_date >= CURDATE())";
      }

      params.push(limit);

      const conn = await pool.promise();
      const [rows] = await conn.query(
        `
        SELECT a.id, a.title, a.content, a.bg_color, a.start_date, a.end_date,
               a.image_url, a.created_at,
               u.firstname, u.lastname
        FROM announcements a
        JOIN users u ON u.id = a.created_by
        WHERE ${where}
        ORDER BY a.created_at DESC
        LIMIT ?
        `,
        params
      );

      const out = rows.map((r) => ({
        id: r.id,
        title: r.title,
        content: r.content,
        bg_color: r.bg_color,
        start_date: r.start_date,
        end_date: r.end_date,
        image_url: r.image_url
          ? "https://himtang.com/Backend/uploads/announcements/" + r.image_url
          : null,
        created_at: r.created_at,
        created_by_name:
          r.firstname && r.lastname ? `${r.firstname} ${r.lastname}` : null,
      }));

      res.json(out);
    } catch (err) {
      console.error("❌ GET /announcements error:", err);
      res.status(500).json({ message: "Failed to load announcements" });
    }
  }
);

// GET /Backend/api/announcements/:id
// ดึงข่าวประกาศทีละอัน (ใช้เปิดดูรายละเอียดเต็ม)
app.get(
  "/Backend/api/announcements/:id",
  authenticateToken,
  async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (Number.isNaN(id)) {
        return res.status(400).json({ message: "Invalid id" });
      }

      const conn = await pool.promise();
      const [rows] = await conn.query(
        `
        SELECT a.id, a.title, a.content, a.bg_color, a.start_date, a.end_date,
               a.image_url, a.created_at,
               u.firstname, u.lastname, a.created_by
        FROM announcements a
        JOIN users u ON u.id = a.created_by
        WHERE a.id = ?
        `,
        [id]
      );

      if (!rows.length) {
        return res.status(404).json({ message: "Announcement not found" });
      }

      const r = rows[0];
      const item = {
        id: r.id,
        title: r.title,
        content: r.content,
        bg_color: r.bg_color,
        start_date: r.start_date,
        end_date: r.end_date,
        image_url: r.image_url
          ? "https://himtang.com/Backend/uploads/announcements/" + r.image_url
          : null,
        created_at: r.created_at,
        created_by: r.created_by,
        created_by_name:
          r.firstname && r.lastname ? `${r.firstname} ${r.lastname}` : null,
      };

      res.json(item);
    } catch (err) {
      console.error("❌ GET /announcements/:id error:", err);
      res.status(500).json({ message: "DB error" });
    }
  }
);

// DELETE /Backend/api/announcements/:id
// ลบข่าว (อนุญาตเฉพาะคนที่เป็นคนสร้าง)
app.delete(
  "/Backend/api/announcements/:id",
  authenticateToken,
  async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (Number.isNaN(id)) {
        return res.status(400).json({ message: "Invalid id" });
      }

      const conn = await pool.promise();

      // หาเจ้าของ + ชื่อไฟล์รูปเดิม
      const [rows] = await conn.query(
        "SELECT image_url, created_by FROM announcements WHERE id = ?",
        [id]
      );

      if (!rows.length) {
        return res.status(404).json({ message: "Announcement not found" });
      }

      const row = rows[0];

      if (row.created_by !== req.user.id) {
        return res.status(403).json({ message: "Forbidden" });
      }

      await conn.query("DELETE FROM announcements WHERE id = ?", [id]);

      // ลบไฟล์รูปออกจากดิสก์ถ้ามี
      if (row.image_url) {
        const filePath = path.join(announcementsDir, row.image_url);
        fs.unlink(filePath, (err) => {
          if (err && err.code !== "ENOENT") {
            console.error("❌ delete announcement image error:", err);
          }
        });
      }

      res.json({ message: "Announcement deleted" });
    } catch (err) {
      console.error("❌ DELETE /announcements/:id error:", err);
      res.status(500).json({ message: "DB error" });
    }
  }
);

app.put("/Backend/api/works/:id/restore", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await pool
      .promise()
      .query(
        "UPDATE works SET is_closed = 0 WHERE id = ?",
        [id]
      );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Work not found" });
    }

    res.json({ message: "Work restored", id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
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
