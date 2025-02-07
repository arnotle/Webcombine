require('dotenv').config();
const express = require('express');
const mysql = require('mysql2'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// Set EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'Public')));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

db.connect((err) => {
    if (err) {
        console.error('เกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล: ', err);
    } else {
        console.log('เชื่อมต่อกับฐานข้อมูลสำเร็จ');
    }
});

// ✅ Middleware ตรวจสอบ JWT Token
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.redirect('/login');
        req.user = user;
        next();
    });
};

// ✅ Middleware ตรวจสอบสิทธิ์ Admin
const authenticateAdmin = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.redirect('/login');

        // ดึงข้อมูล role จากฐานข้อมูล
        db.query("SELECT role FROM users WHERE id = ?", [user.userId], (error, results) => {
            if (error || results.length === 0 || results[0].role !== 'admin') {
                return res.redirect('/home'); // ถ้าไม่ใช่ admin กลับไปหน้า home
            }
            req.user = user;
            next();
        });
    });
};

// ✅ หน้า home ต้องล็อกอินก่อนถึงเข้าได้
app.get('/home', authenticateToken, (req, res) => {
    res.render('home', { user: req.user });
});

// ✅ หน้า dashboard (Admin เท่านั้น)
app.get('/dashboard', authenticateAdmin, (req, res) => {
    res.render('dashboard', { user: req.user });
});


// ✅ อนุญาตให้เข้าถึงหน้าเหล่านี้ได้เมื่อมี JWT Token
const protectedPages = ['contact', 'information', 'information2', 'information3', 'homelog','add'];
protectedPages.forEach(page => {
    app.get(`/${page}`, authenticateToken, (req, res) => res.render(page, { user: req.user }));
});

// ✅ หน้า login & register ไม่ต้องใช้ JWT
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));

// ✅ หน้า Profile ต้องล็อกอิน
app.get('/profile', authenticateToken, (req, res) => {
    res.render('profile', { userId: req.user.userId });
});

// ✅ Register
app.post('/register', async (req, res) => {
    const { firstname, lastname, email, phone, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = "INSERT INTO users (firstname, lastname, email, phone, password, role) VALUES (?, ?, ?, ?, ?, 'user')";
        db.query(sql, [firstname, lastname, email, phone, hashedPassword], (err, result) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            res.json({ message: 'User registered successfully!' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// ✅ Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = results[0];
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });

        res.json({ message: 'Login successful', redirect: '/home' });
    });
});

// ✅ Logout
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

// ✅ ดึงข้อมูลผู้ใช้ทั้งหมด
app.get('/api/users', authenticateAdmin, (req, res) => {
    db.query("SELECT id, firstname, lastname, email, phone FROM users", (err, results) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        res.json(results);
    });
});

// ✅ อัปเดตข้อมูลผู้ใช้
app.put('/api/users/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    const { firstname, lastname, phone } = req.body;
    db.query("UPDATE users SET firstname=?, lastname=?, phone=? WHERE id=?", 
        [firstname, lastname, phone, id], 
        (err, result) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            res.json({ message: 'User updated successfully' });
        }
    );
});

// ✅ ลบผู้ใช้
app.delete('/api/users/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query("DELETE FROM users WHERE id=?", [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        res.json({ message: 'User deleted successfully' });
    });
});

// กำหนดเส้นทาง '/some-path' ให้ดึงข้อมูลเครื่องจักรจากฐานข้อมูล
app.get('/some-path', (req, res) => {
    // ดึงข้อมูลเครื่องจักรจากฐานข้อมูล
    db.query("SELECT * FROM machines", (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.sqlMessage });
        }
        // ตรวจสอบผลลัพธ์ที่ได้จากฐานข้อมูล
        console.log(results);  // ตรวจสอบใน console ว่าข้อมูลที่ได้ถูกต้องหรือไม่

        // ส่งข้อมูลเครื่องจักรไปยังเทมเพลต add.ejs
        res.render('add', { machines: results });
    });
});


const multer = require('multer');

// ตั้งค่าการอัปโหลดไฟล์
const storage = multer.diskStorage({
    destination: './Public/uploads/', // โฟลเดอร์เก็บไฟล์
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage });

// เส้นทางรับข้อมูลจากฟอร์ม
app.post('/add-machine', upload.single('image'), (req, res) => {
    const { name } = req.body;
    const image = req.file.filename; // ชื่อไฟล์รูป

    db.query("INSERT INTO machines (name, image) VALUES (?, ?)", 
        [name, image], 
        (err, result) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            res.redirect('/some-path'); // กลับไปหน้ารายการ
        }
    );
});

app.set('views', path.join(__dirname, 'views')); // ควรเป็นโฟลเดอร์ views ที่อยู่ในโฟลเดอร์หลักของโปรเจค
app.get('/new', authenticateAdmin, (req, res) => {
    res.render('add-new-machine'); // ฟอร์มสำหรับเพิ่มเครื่องจักร
});



// ✅ เส้นทางบันทึกข้อมูลเครื่องจักร (เพิ่มใหม่)
app.post('/add-new-machine', upload.single('image'), (req, res) => {
    const { name } = req.body;
    const image = req.file.filename; // ชื่อไฟล์ของรูปภาพที่อัปโหลด

    db.query("INSERT INTO machines (name, image, created_by) VALUES (?, ?, ?)", 
        [name, image, req.user.userId], // ใช้ userId ของผู้ที่ล็อกอินเป็น creator
        (err, result) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            res.redirect('/list-machines'); // กลับไปหน้ารายการเครื่องจักร
        }
    );
});

// เส้นทางสำหรับบันทึกโพสต์ใหม่
app.post('/list-machines', upload.single('image'), (req, res) => {
    const { title, content } = req.body;
    const image = req.file ? req.file.path : null;  // ถ้ามีไฟล์จะใช้ path ของไฟล์

    // ที่นี่จะนำข้อมูลไปบันทึกในฐานข้อมูลหรือประมวลผลตามที่ต้องการ
    console.log('Title:', title);
    console.log('Content:', content);
    console.log('Image:', image);

    res.send('โพสต์ของคุณถูกบันทึกแล้ว!');
});

// ให้ Express เข้าถึงไฟล์ในโฟลเดอร์ 'uploads'
app.use('/uploads', express.static('Public/uploads'));

app.get('/list-machines', (req, res) => {
    db.query("SELECT * FROM machines", (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.sqlMessage });
        }
        res.render('list-machines', { machines: results }); // ส่งข้อมูลเครื่องจักรไปที่เทมเพลต
    });
});

// รับข้อมูลจากฟอร์มและอัปโหลดไฟล์
app.post('/add-new-machine', upload.single('image'), (req, res) => {
    const { name } = req.body;
    const image = req.file.filename; // ชื่อไฟล์ของรูปภาพที่อัปโหลด
    const createdBy = req.user.userId; // ใช้ userId ที่ได้จาก JWT token ของผู้ใช้งานที่ล็อกอินอยู่

    // เพิ่มข้อมูลเครื่องจักรพร้อมทั้งสร้างความสัมพันธ์กับผู้ใช้งาน
    db.query("INSERT INTO machines (name, image, created_by) VALUES (?, ?, ?)", 
        [name, image, createdBy], 
        (err, result) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            res.redirect('/list-machines'); // กลับไปหน้ารายการเครื่องจักร
        }
    );
});

app.get('/machines', (req, res) => {
    db.query("SELECT * FROM machines", (err, results) => {
        if (err) return res.status(500).send('Database query error');
        res.render('machines', { machines: results });
    });
});

({
    storage,
    fileFilter: (req, file, cb) => {
        const fileTypes = /jpeg|jpg|png/;
        const mimeType = fileTypes.test(file.mimetype);
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());

        if (mimeType && extname) {
            return cb(null, true);
        } else {
            cb('Error: Images only!');
        }
    }
});

upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Please upload an image' });
    }
    // เพิ่มการประมวลผลต่อไป
}



// ✅ Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}/home`);
});
