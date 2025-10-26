# 🔐 Secure Login System

A modern **Secure Login System** built with **Flask** that provides **role-based access control (RBAC)**, **JWT authentication**, and **account protection features**.  
This project ensures a secure and scalable login flow for both **Admin** and **User** roles with strong password encryption, session security, and rate-limiting mechanisms.

---

## 📘 Project Overview

The Secure Login System is a **Flask-based web application** that implements best security practices for authentication and user management.  
It offers:

- Role-based access (Admin / User)
- JWT-based stateless authentication
- Secure password hashing (Argon2)
- Account lockout after failed attempts
- Admin dashboard for user management
- API rate-limiting and secure CORS configuration

---

## 🛡️ Security Highlights

- **Password Hashing:** Argon2 (via `argon2-cffi`)
- **Session Security:** JSON Web Tokens (JWT)
- **Rate Limiting:** `Flask-Limiter` to prevent brute-force attacks
- **CORS:** Configured using `Flask-CORS` for controlled frontend access
- **Role-based Access:** Admin vs. User authorization
- **Account Lockout:** 5 failed attempts lock account for 15 minutes
- **Token Expiry:** JWT tokens expire in 1 hour (auto-refresh supported)

---

## ⚙️ Technology Stack

| Category | Tools & Libraries |
|-----------|------------------|
| **Backend Framework** | Flask (Python) |
| **Authentication** | Flask-JWT-Extended |
| **Password Hashing** | Argon2 (`argon2-cffi`) |
| **Database** | SQLite (lightweight, file-based) |
| **Rate Limiting** | Flask-Limiter |
| **CORS Handling** | Flask-CORS |
| **Environment Variables** | python-dotenv |
| **Frontend** | HTML (Jinja2 Templates) + Vanilla JavaScript (Fetch API) |

---

## 🚀 Features

✅ **User Registration** — Strong password validation and Argon2 hashing  
✅ **JWT Authentication** — Stateless and secure login flow  
✅ **Role-Based Access** — Separate Admin/User privileges  
✅ **Admin Dashboard** — Manage, delete, or unlock users  
✅ **Account Lockout** — Protects from brute-force attempts  
✅ **Token Expiry & Refresh** — Enforced with Flask-JWT-Extended  
✅ **API Rate Limiting** — Prevents abuse and rapid requests  
✅ **CORS Configuration** — Secure frontend-backend communication  

---

## 🧩 Project Structure

```
├── app.py                  # Main Flask backend application
├── secure_login.db         # SQLite database file (auto-generated)
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (excluded from Git)
├── templates/              # Frontend templates (Jinja2)
│   ├── base.html
│   ├── admin.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── index.html
└── static/                 # Static assets (CSS, JS, etc.)
```

---

## 🧰 Installation & Setup

### 🧾 Pre-requisites

- Python **3.10+**
- `pip` (Python package manager)
- (Optional) `virtualenv` for isolated environments

---

### ⚙️ Step 1: Clone the Repository

```bash
git clone https://github.com/technical-param/secure-login-system.git
cd secure-login-system
```

---

### ⚙️ Step 2: Create & Activate Virtual Environment

#### On Linux/Mac:
```bash
python3 -m venv venv
source venv/bin/activate
```

#### On Windows CMD:
```bash
python -m venv venv
venv\Scripts\activate
```

---

### ⚙️ Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

---

### ⚙️ Step 4: Setup Environment Variables

Create a `.env` file in the root directory:

```
SECRET_KEY=your-random-secret-for-flask
JWT_SECRET_KEY=your-random-jwt-secret-key
FLASK_ENV=development
FLASK_DEBUG=True
DATABASE_URL=sqlite:///secure_login.db
```

Generate secure keys using Python:

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > .env
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))" >> .env
echo "FLASK_ENV=development" >> .env
echo "FLASK_DEBUG=True" >> .env
echo "DATABASE_URL=sqlite:///secure_login.db" >> .env
```

---

### ⚙️ Step 5: Run the Application

```bash
python app.py
```

Application runs at:  
👉 **http://127.0.0.1:5000**

---

### 🧑‍💼 Default Admin Credentials

| Field | Value |
|--------|--------|
| **Email** | `admin@example.com` |
| **Password** | `Admin@1234` |

---

## 🧠 How It Works

1. **Registration API:**  
   Accepts username, email, and password → validates → stores hashed password.

2. **Login API:**  
   Issues JWT containing user role and username claims upon successful authentication.

3. **JWT Protected Routes:**  
   Use `@jwt_required()` decorator to ensure valid token in `Authorization` header.

4. **Admin API Controls:**  
   Admin-only routes to list, delete, unlock, and manage users.

5. **Frontend Logic:**  
   Browser fetches use JWT stored in `localStorage` for authenticated requests.

6. **Security Controls:**  
   - Argon2 password hashing  
   - Account lockout on 5 failed logins  
   - 1-hour token expiry  
   - Rate-limited login attempts  

---

## 🧩 Troubleshooting Tips

- 🔄 **Clear localStorage & cache** after secret key changes.  
- 🌐 **CORS errors?** Ensure correct frontend origin in Flask-CORS setup.  
- 🧩 **422 JWT error?** Verify token integrity and secret key.  
- 🐍 **Check Flask logs** for JWT or database errors.  
- 📦 **Dependencies outdated?** Upgrade Flask & Flask-JWT-Extended versions.

---

## 📦 Requirements

```
Flask==3.0.0
Flask-Cors==4.0.0
Flask-JWT-Extended==4.6.0
Flask-Limiter==3.5.0
argon2-cffi==23.1.0
python-dotenv==1.0.0
```

Install via:
```bash
pip install -r requirements.txt
```

---

## 🧑‍💻 Author

**Parmeshwar Ware**  
_Cybersecurity Intern_  
📧 [parmeshwar.ware@outlook.com](mailto:parmeshwar.ware@outlook.com)

---

## 🛡️ License

This project is open-source and available under the **MIT License**.

---

> ⚡ *"Secure coding isn't just a skill — it's a mindset."*
