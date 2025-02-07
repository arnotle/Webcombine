# WebSite Combine
สมาชิก
66021432 นายณปภัช แก้วปรีชา Full-stack
66022073 นายวงศพัทร์ ชิตท้วม Full-stack

# การจัดโฟล์เดอร์
Open floder เลือกโฟล์เดอร์ Webcombine
# install
npm install express nodemon ejs mysql2 bcryptjs jsonwebtoken cookie-parser body-parser
# Run server
Run terminal: npm run wstart

เริ่มหน้าlogin ต้องทำการสมัครก่อน 
เราได้แบ่ง Role ไว้คือ Admin user
http://localhost:3000/login
หน้าHome
http://localhost:3000/home

# DataBase
ที่ต้องสร้าง
สร้าง Database Name
Smart_combine

Table users
CREATE TABLE users (
    id INT PRIMARY KEY,
    firstname VARCHAR(50),
    lastname VARCHAR(50),
    email VARCHAR(100) UNIQUE,
    phone VARCHAR(20),
    password VARCHAR(255),
    created_at DATETIME,
    role VARCHAR(10)
);

Table contact_messages
CREATE TABLE contact_messages (
    id INT PRIMARY KEY,
    name VARCHAR(100),
    phone VARCHAR(20),
    email VARCHAR(255),
    message TEXT,
    created_at DATETIME
);

Table machines
CREATE TABLE machines (
    id INT PRIMARY KEY,
    name VARCHAR(100),
    image_url VARCHAR(255),
    created_by INT,
    created_at DATETIME,
    image VARCHAR(255)
);

# .env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_DATABASE=smart_combine
JWT_SECRET=your_jwt_secret

# Admin 
แอดมินจะสามารถเข้าหน้า Admin dashboard ได้ เพื่อแก้ไขข้อมูล
http://localhost:3000/dashboard

# User
Register แล้ว login ใช้งานเว็ปไซต์ได้ปกติ


# ขอบคุณครับ
