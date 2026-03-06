"""
AWS Internal Audit - Authentication Backend
MySQL-based user management with bcrypt password hashing.
Supports: registration, login, forgot password (security Q + email OTP),
           admin panel, user profiles, audit history, login rate limiting.
"""

import os
import re
import json
import secrets
import hashlib
import smtplib
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from contextlib import contextmanager

import mysql.connector
import pyotp

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

# ─── Paths ────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SMTP_CONFIG_PATH = os.path.join(DATA_DIR, "smtp_config.json")

# ─── MySQL Config ─────────────────────────────────────────────────────────
MYSQL_CONFIG = {
    "host": os.environ.get("MYSQL_HOST", "localhost"),
    "user": os.environ.get("MYSQL_USER", "aws_audit"),
    "password": os.environ.get("MYSQL_PASSWORD", "AWSAudit@2026"),
    "database": os.environ.get("MYSQL_DATABASE", "aws_audit"),
}

# ─── Security Questions ──────────────────────────────────────────────────
SECURITY_QUESTIONS = [
    "What is your mother's maiden name?",
    "What was the name of your first pet?",
    "In what city were you born?",
    "What is your favorite movie?",
    "What was the name of your first school?",
    "What is your childhood nickname?",
    "What street did you grow up on?",
    "What was your first car?",
]

# ─── Password Hashing ────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    if HAS_BCRYPT:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"pbkdf2${salt}${h.hex()}"


def _verify_password(password: str, hashed: str) -> bool:
    if HAS_BCRYPT and hashed.startswith("$2"):
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    if hashed.startswith("pbkdf2$"):
        _, salt, stored_hash = hashed.split("$", 2)
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
        return h.hex() == stored_hash
    return False


# ─── Validators ───────────────────────────────────────────────────────────

def validate_username(username: str) -> tuple:
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(username) > 30:
        return False, "Username must be under 30 characters."
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, "Username can only contain letters, numbers, _ . -"
    return True, ""


def validate_email(email: str) -> tuple:
    if not email:
        return False, "Email is required."
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False, "Invalid email format."
    return True, ""


def validate_password(password: str) -> tuple:
    issues = []
    if len(password) < 8:
        issues.append("at least 8 characters")
    if not re.search(r'[A-Z]', password):
        issues.append("one uppercase letter")
    if not re.search(r'[a-z]', password):
        issues.append("one lowercase letter")
    if not re.search(r'[0-9]', password):
        issues.append("one digit")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        issues.append("one special character")
    if issues:
        return False, "Password must contain: " + ", ".join(issues) + "."
    return True, ""


def password_strength(password: str) -> tuple:
    """Returns (score 0-5, label, color)."""
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[0-9]', password):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    labels = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
    colors = ["#e74c3c", "#e67e22", "#f1c40f", "#27ae60", "#2ecc71", "#1abc9c"]
    return score, labels[score], colors[score]


# ─── AuthManager ──────────────────────────────────────────────────────────

class AuthManager:
    def __init__(self, db_config=None):
        self.db_config = db_config or MYSQL_CONFIG
        self._init_db()

    @contextmanager
    def _get_db(self):
        conn = mysql.connector.connect(**self.db_config)
        conn.autocommit = False
        cursor = conn.cursor(dictionary=True)
        try:
            yield conn, cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    def _init_db(self):
        conn = mysql.connector.connect(**self.db_config)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(255) DEFAULT '',
                role VARCHAR(20) DEFAULT 'user',
                security_question VARCHAR(255) NOT NULL,
                security_answer_hash VARCHAR(255) NOT NULL,
                is_active TINYINT DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                login_count INT DEFAULT 0,
                avatar_color VARCHAR(20) DEFAULT '#2F5496',
                totp_secret VARCHAR(64) DEFAULT NULL,
                totp_enabled TINYINT DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                ip_address VARCHAR(50) DEFAULT '',
                success TINYINT DEFAULT 0,
                attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                otp VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                used TINYINT DEFAULT 0,
                expires_at DATETIME NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                accounts_audited TEXT NOT NULL,
                total_accounts INT DEFAULT 0,
                audit_year INT,
                audit_month INT,
                total_cost DOUBLE DEFAULT 0,
                total_resources INT DEFAULT 0,
                active_regions INT DEFAULT 0,
                errors INT DEFAULT 0,
                report_path TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                `key` VARCHAR(255) PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description VARCHAR(500) DEFAULT '',
                created_by INT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS company_members (
                id INT AUTO_INCREMENT PRIMARY KEY,
                company_id INT NOT NULL,
                user_id INT NOT NULL,
                role VARCHAR(20) DEFAULT 'member',
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (company_id) REFERENCES companies(id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE KEY unique_membership (company_id, user_id)
            )
        """)
        # Add totp columns if missing (migration)
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64) DEFAULT NULL")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_enabled TINYINT DEFAULT 0")
        except mysql.connector.Error:
            pass

        conn.commit()
        cursor.close()
        conn.close()

    # ── User Registration ─────────────────────────────────────────────

    def register(self, username, email, password, full_name,
                 security_question, security_answer):
        ok, msg = validate_username(username)
        if not ok:
            return False, msg
        ok, msg = validate_email(email)
        if not ok:
            return False, msg
        ok, msg = validate_password(password)
        if not ok:
            return False, msg
        if not security_question or not security_answer:
            return False, "Security question and answer are required."

        pw_hash = _hash_password(password)
        sa_hash = _hash_password(security_answer.strip().lower())

        colors = ["#2F5496", "#E74C3C", "#27AE60", "#8E44AD",
                  "#F39C12", "#1ABC9C", "#E67E22", "#3498DB"]
        avatar_color = secrets.choice(colors)

        with self._get_db() as (conn, cur):
            cur.execute("SELECT COUNT(*) as cnt FROM users")
            count = cur.fetchone()["cnt"]
            role = "admin" if count == 0 else "user"

            try:
                cur.execute(
                    """INSERT INTO users
                       (username, email, password_hash, full_name, role,
                        security_question, security_answer_hash, avatar_color)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (username.strip(), email.strip().lower(), pw_hash,
                     full_name.strip(), role, security_question, sa_hash,
                     avatar_color)
                )
                role_msg = " You are the first user and have been assigned Admin role." if role == "admin" else ""
                return True, f"Registration successful!{role_msg}"
            except mysql.connector.IntegrityError as e:
                if "username" in str(e):
                    return False, "Username already taken."
                if "email" in str(e):
                    return False, "Email already registered."
                return False, f"Registration failed: {e}"

    # ── Login ─────────────────────────────────────────────────────────

    def login(self, username, password):
        with self._get_db() as (conn, cur):
            cutoff = (datetime.utcnow() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
            cur.execute(
                """SELECT COUNT(*) as cnt FROM login_attempts
                   WHERE username = %s AND success = 0 AND attempted_at > %s""",
                (username, cutoff)
            )
            fails = cur.fetchone()["cnt"]

            if fails >= 5:
                return False, None, "Account temporarily locked. Too many failed attempts. Try again in 15 minutes."

            cur.execute(
                "SELECT * FROM users WHERE username = %s OR email = %s",
                (username, username.lower())
            )
            user = cur.fetchone()

            if not user:
                cur.execute(
                    "INSERT INTO login_attempts (username, success) VALUES (%s, 0)",
                    (username,)
                )
                return False, None, "Invalid username or password."

            if not user["is_active"]:
                return False, None, "Account is disabled. Contact administrator."

            if not _verify_password(password, user["password_hash"]):
                cur.execute(
                    "INSERT INTO login_attempts (username, success) VALUES (%s, 0)",
                    (username,)
                )
                remaining = 5 - fails - 1
                if remaining <= 2:
                    return False, None, f"Invalid password. {remaining} attempt(s) remaining before lockout."
                return False, None, "Invalid username or password."

            # Success
            cur.execute(
                "INSERT INTO login_attempts (username, success) VALUES (%s, 1)",
                (username,)
            )
            cur.execute(
                """UPDATE users SET last_login = NOW(),
                   login_count = login_count + 1 WHERE id = %s""",
                (user["id"],)
            )

            user_dict = dict(user)
            del user_dict["password_hash"]
            del user_dict["security_answer_hash"]
            return True, user_dict, "Login successful!"

    # ── Forgot Password: Security Question ────────────────────────────

    def get_security_question(self, email):
        with self._get_db() as (conn, cur):
            cur.execute(
                "SELECT security_question FROM users WHERE email = %s",
                (email.strip().lower(),)
            )
            user = cur.fetchone()
            if user:
                return user["security_question"]
        return None

    def verify_security_answer(self, email, answer):
        with self._get_db() as (conn, cur):
            cur.execute(
                "SELECT security_answer_hash FROM users WHERE email = %s",
                (email.strip().lower(),)
            )
            user = cur.fetchone()
            if not user:
                return False
            return _verify_password(answer.strip().lower(), user["security_answer_hash"])

    def reset_password(self, email, new_password):
        ok, msg = validate_password(new_password)
        if not ok:
            return False, msg

        pw_hash = _hash_password(new_password)
        with self._get_db() as (conn, cur):
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE email = %s",
                (pw_hash, email.strip().lower())
            )
            if cur.rowcount == 0:
                return False, "Email not found."
            return True, "Password reset successfully! You can now log in."

    # ── Forgot Password: Email OTP ────────────────────────────────────

    def generate_otp(self, email):
        with self._get_db() as (conn, cur):
            cur.execute(
                "SELECT id FROM users WHERE email = %s",
                (email.strip().lower(),)
            )
            user = cur.fetchone()
            if not user:
                return None

            otp = ''.join(secrets.choice(string.digits) for _ in range(6))
            expires = (datetime.utcnow() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')

            cur.execute(
                "UPDATE password_resets SET used = 1 WHERE email = %s AND used = 0",
                (email.strip().lower(),)
            )
            cur.execute(
                "INSERT INTO password_resets (email, otp, expires_at) VALUES (%s, %s, %s)",
                (email.strip().lower(), _hash_password(otp), expires)
            )
            return otp

    def verify_otp(self, email, otp):
        with self._get_db() as (conn, cur):
            cur.execute(
                """SELECT * FROM password_resets
                   WHERE email = %s AND used = 0
                   ORDER BY created_at DESC LIMIT 1""",
                (email.strip().lower(),)
            )
            resets = cur.fetchone()

            if not resets:
                return False, "No reset request found."

            expires_at = resets["expires_at"]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            if expires_at < datetime.utcnow():
                return False, "OTP has expired. Request a new one."

            if not _verify_password(otp, resets["otp"]):
                return False, "Invalid OTP."

            cur.execute(
                "UPDATE password_resets SET used = 1 WHERE id = %s",
                (resets["id"],)
            )
            return True, "OTP verified!"

    def send_reset_email(self, email):
        otp = self.generate_otp(email)
        if not otp:
            return False, "Email not found."

        smtp_cfg = self.get_smtp_config()
        if not smtp_cfg or not smtp_cfg.get("host"):
            return False, "SMTP not configured. Use security question reset instead."

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = "AWS Audit - Password Reset OTP"
            msg["From"] = smtp_cfg.get("from_email", smtp_cfg.get("username", ""))
            msg["To"] = email

            html = f"""
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto;
                        border: 1px solid #e0e0e0; border-radius: 10px; overflow: hidden;">
                <div style="background: linear-gradient(135deg, #1a1a2e, #0f3460);
                            padding: 20px; text-align: center;">
                    <h2 style="color: white; margin: 0;">AWS Internal Audit</h2>
                    <p style="color: #ccc; margin: 5px 0 0 0; font-size: 14px;">Password Reset</p>
                </div>
                <div style="padding: 30px;">
                    <p>Your password reset OTP is:</p>
                    <div style="background: #f0f4ff; border: 2px dashed #2F5496;
                                border-radius: 8px; padding: 20px; text-align: center;
                                margin: 20px 0;">
                        <span style="font-size: 32px; font-weight: bold;
                                     letter-spacing: 8px; color: #1a1a2e;">{otp}</span>
                    </div>
                    <p style="color: #666; font-size: 13px;">
                        This OTP expires in <strong>10 minutes</strong>.<br>
                        If you didn't request this, ignore this email.
                    </p>
                </div>
            </div>
            """
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(smtp_cfg["host"], int(smtp_cfg.get("port", 587))) as server:
                server.ehlo()
                if smtp_cfg.get("use_tls", True):
                    server.starttls()
                if smtp_cfg.get("username") and smtp_cfg.get("password"):
                    server.login(smtp_cfg["username"], smtp_cfg["password"])
                server.sendmail(msg["From"], [email], msg.as_string())

            return True, f"OTP sent to {email[:3]}***{email[email.index('@'):]}"
        except Exception as e:
            return False, f"Failed to send email: {e}"

    # ── User Profile ──────────────────────────────────────────────────

    def get_user(self, user_id):
        with self._get_db() as (conn, cur):
            cur.execute(
                "SELECT * FROM users WHERE id = %s", (user_id,)
            )
            user = cur.fetchone()
            if user:
                d = dict(user)
                del d["password_hash"]
                del d["security_answer_hash"]
                return d
        return None

    def update_profile(self, user_id, full_name=None, email=None):
        with self._get_db() as (conn, cur):
            if full_name is not None:
                cur.execute("UPDATE users SET full_name = %s WHERE id = %s",
                           (full_name.strip(), user_id))
            if email is not None:
                ok, msg = validate_email(email)
                if not ok:
                    return False, msg
                try:
                    cur.execute("UPDATE users SET email = %s WHERE id = %s",
                               (email.strip().lower(), user_id))
                except mysql.connector.IntegrityError:
                    return False, "Email already in use."
            return True, "Profile updated."

    def change_password(self, user_id, old_password, new_password):
        with self._get_db() as (conn, cur):
            cur.execute(
                "SELECT password_hash FROM users WHERE id = %s", (user_id,)
            )
            user = cur.fetchone()
            if not user:
                return False, "User not found."
            if not _verify_password(old_password, user["password_hash"]):
                return False, "Current password is incorrect."
            ok, msg = validate_password(new_password)
            if not ok:
                return False, msg
            pw_hash = _hash_password(new_password)
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                       (pw_hash, user_id))
            return True, "Password changed successfully!"

    # ── Admin: User Management ────────────────────────────────────────

    def list_users(self):
        with self._get_db() as (conn, cur):
            cur.execute(
                """SELECT id, username, email, full_name, role, is_active,
                          created_at, last_login, login_count, avatar_color
                   FROM users ORDER BY created_at DESC"""
            )
            return [dict(u) for u in cur.fetchall()]

    def toggle_user_active(self, user_id, is_active):
        with self._get_db() as (conn, cur):
            cur.execute("UPDATE users SET is_active = %s WHERE id = %s",
                       (1 if is_active else 0, user_id))
            return True

    def set_user_role(self, user_id, role):
        if role not in ("admin", "user"):
            return False, "Invalid role."
        with self._get_db() as (conn, cur):
            cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
            return True, f"Role updated to {role}."

    def delete_user(self, user_id):
        with self._get_db() as (conn, cur):
            cur.execute("DELETE FROM audit_history WHERE user_id = %s", (user_id,))
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            return True

    def admin_reset_password(self, user_id, new_password):
        ok, msg = validate_password(new_password)
        if not ok:
            return False, msg
        pw_hash = _hash_password(new_password)
        with self._get_db() as (conn, cur):
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                       (pw_hash, user_id))
            return True, "Password reset by admin."

    # ── Audit History ─────────────────────────────────────────────────

    def save_audit_log(self, user_id, accounts_audited, total_accounts,
                       audit_year, audit_month, total_cost, total_resources,
                       active_regions, errors, report_path=None):
        with self._get_db() as (conn, cur):
            cur.execute(
                """INSERT INTO audit_history
                   (user_id, accounts_audited, total_accounts, audit_year, audit_month,
                    total_cost, total_resources, active_regions, errors, report_path)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (user_id, accounts_audited, total_accounts, audit_year, audit_month,
                 total_cost, total_resources, active_regions, errors, report_path)
            )

    def delete_audit_log(self, audit_id):
        with self._get_db() as (conn, cur):
            cur.execute(
                "SELECT report_path FROM audit_history WHERE id = %s", (audit_id,)
            )
            row = cur.fetchone()
            if row and row["report_path"]:
                try:
                    import os as _os
                    if _os.path.exists(row["report_path"]):
                        _os.remove(row["report_path"])
                except Exception:
                    pass
            cur.execute("DELETE FROM audit_history WHERE id = %s", (audit_id,))
            return True

    def get_audit_history(self, user_id=None, limit=50):
        with self._get_db() as (conn, cur):
            if user_id:
                cur.execute(
                    """SELECT ah.*, u.username FROM audit_history ah
                       JOIN users u ON ah.user_id = u.id
                       WHERE ah.user_id = %s
                       ORDER BY ah.created_at DESC LIMIT %s""",
                    (user_id, limit)
                )
            else:
                cur.execute(
                    """SELECT ah.*, u.username FROM audit_history ah
                       JOIN users u ON ah.user_id = u.id
                       ORDER BY ah.created_at DESC LIMIT %s""",
                    (limit,)
                )
            return [dict(r) for r in cur.fetchall()]

    # ── Company / Team Management ────────────────────────────────────

    def create_company(self, name, description, created_by):
        with self._get_db() as (conn, cur):
            cur.execute(
                "INSERT INTO companies (name, description, created_by) VALUES (%s, %s, %s)",
                (name.strip(), description.strip(), created_by)
            )
            company_id = cur.lastrowid
            # Creator becomes owner
            cur.execute(
                "INSERT INTO company_members (company_id, user_id, role) VALUES (%s, %s, 'owner')",
                (company_id, created_by)
            )
            return True, company_id, "Company created successfully!"

    def get_company(self, company_id):
        with self._get_db() as (conn, cur):
            cur.execute("SELECT * FROM companies WHERE id = %s", (company_id,))
            return cur.fetchone()

    def list_companies(self):
        with self._get_db() as (conn, cur):
            cur.execute("""
                SELECT c.*, u.username as creator_name,
                       (SELECT COUNT(*) FROM company_members WHERE company_id = c.id) as member_count
                FROM companies c
                JOIN users u ON c.created_by = u.id
                ORDER BY c.created_at DESC
            """)
            return [dict(r) for r in cur.fetchall()]

    def get_user_company(self, user_id):
        """Get the company a user belongs to (returns first one)."""
        with self._get_db() as (conn, cur):
            cur.execute("""
                SELECT c.*, cm.role as member_role
                FROM companies c
                JOIN company_members cm ON c.id = cm.company_id
                WHERE cm.user_id = %s
                LIMIT 1
            """, (user_id,))
            return cur.fetchone()

    def get_company_members(self, company_id):
        with self._get_db() as (conn, cur):
            cur.execute("""
                SELECT u.id, u.username, u.email, u.full_name, u.role as system_role,
                       u.avatar_color, u.is_active, cm.role as company_role, cm.joined_at
                FROM users u
                JOIN company_members cm ON u.id = cm.user_id
                WHERE cm.company_id = %s
                ORDER BY cm.role DESC, cm.joined_at ASC
            """, (company_id,))
            return [dict(r) for r in cur.fetchall()]

    def get_company_member_ids(self, company_id):
        with self._get_db() as (conn, cur):
            cur.execute(
                "SELECT user_id FROM company_members WHERE company_id = %s",
                (company_id,)
            )
            return [r["user_id"] for r in cur.fetchall()]

    def add_company_member(self, company_id, user_id, role="member"):
        with self._get_db() as (conn, cur):
            # Check if user is already in another company
            cur.execute(
                "SELECT company_id FROM company_members WHERE user_id = %s",
                (user_id,)
            )
            existing = cur.fetchone()
            if existing:
                if existing["company_id"] == company_id:
                    return False, "User is already a member of this company."
                return False, "User already belongs to another company."
            try:
                cur.execute(
                    "INSERT INTO company_members (company_id, user_id, role) VALUES (%s, %s, %s)",
                    (company_id, user_id, role)
                )
                return True, "Member added successfully!"
            except mysql.connector.IntegrityError:
                return False, "User is already a member."

    def remove_company_member(self, company_id, user_id):
        with self._get_db() as (conn, cur):
            # Don't allow removing the owner
            cur.execute(
                "SELECT role FROM company_members WHERE company_id = %s AND user_id = %s",
                (company_id, user_id)
            )
            member = cur.fetchone()
            if not member:
                return False, "User is not a member."
            if member["role"] == "owner":
                return False, "Cannot remove the company owner."
            cur.execute(
                "DELETE FROM company_members WHERE company_id = %s AND user_id = %s",
                (company_id, user_id)
            )
            return True, "Member removed."

    def set_company_member_role(self, company_id, user_id, role):
        if role not in ("owner", "admin", "member"):
            return False, "Invalid role."
        with self._get_db() as (conn, cur):
            cur.execute(
                "UPDATE company_members SET role = %s WHERE company_id = %s AND user_id = %s",
                (role, company_id, user_id)
            )
            return True, f"Role updated to {role}."

    def delete_company(self, company_id):
        with self._get_db() as (conn, cur):
            cur.execute("DELETE FROM company_members WHERE company_id = %s", (company_id,))
            cur.execute("DELETE FROM companies WHERE id = %s", (company_id,))
            return True, "Company deleted."

    def get_users_without_company(self):
        with self._get_db() as (conn, cur):
            cur.execute("""
                SELECT id, username, email, full_name
                FROM users
                WHERE id NOT IN (SELECT user_id FROM company_members)
                AND is_active = 1
                ORDER BY username
            """)
            return [dict(r) for r in cur.fetchall()]

    def get_company_audit_history(self, company_id, limit=50):
        """Get audit history for all members of a company."""
        with self._get_db() as (conn, cur):
            cur.execute("""
                SELECT ah.*, u.username FROM audit_history ah
                JOIN users u ON ah.user_id = u.id
                WHERE ah.user_id IN (SELECT user_id FROM company_members WHERE company_id = %s)
                ORDER BY ah.created_at DESC LIMIT %s
            """, (company_id, limit))
            return [dict(r) for r in cur.fetchall()]

    # ── Two-Factor Authentication (TOTP) ────────────────────────────

    def generate_totp_secret(self, user_id):
        secret = pyotp.random_base32()
        with self._get_db() as (conn, cur):
            cur.execute("UPDATE users SET totp_secret = %s WHERE id = %s",
                       (secret, user_id))
        return secret

    def get_totp_uri(self, user_id):
        with self._get_db() as (conn, cur):
            cur.execute("SELECT username, totp_secret FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user or not user["totp_secret"]:
                return None, None
            totp = pyotp.TOTP(user["totp_secret"])
            uri = totp.provisioning_uri(name=user["username"], issuer_name="AWS Internal Audit")
            return uri, user["totp_secret"]

    def enable_totp(self, user_id, otp_code):
        with self._get_db() as (conn, cur):
            cur.execute("SELECT totp_secret FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user or not user["totp_secret"]:
                return False, "2FA secret not generated. Please set up 2FA first."
            totp = pyotp.TOTP(user["totp_secret"])
            if totp.verify(otp_code):
                cur.execute("UPDATE users SET totp_enabled = 1 WHERE id = %s", (user_id,))
                return True, "2FA enabled successfully!"
            return False, "Invalid OTP code. Please try again."

    def disable_totp(self, user_id):
        with self._get_db() as (conn, cur):
            cur.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = %s",
                       (user_id,))
            return True, "2FA disabled."

    def verify_totp(self, user_id, otp_code):
        with self._get_db() as (conn, cur):
            cur.execute("SELECT totp_secret, totp_enabled FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user or not user["totp_enabled"] or not user["totp_secret"]:
                return True  # 2FA not enabled, skip
            totp = pyotp.TOTP(user["totp_secret"])
            return totp.verify(otp_code)

    def is_totp_enabled(self, user_id):
        with self._get_db() as (conn, cur):
            cur.execute("SELECT totp_enabled FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            return bool(user and user["totp_enabled"])

    def is_totp_enabled_by_username(self, username):
        with self._get_db() as (conn, cur):
            cur.execute("SELECT id, totp_enabled FROM users WHERE username = %s OR email = %s",
                       (username, username.lower()))
            user = cur.fetchone()
            if not user:
                return False, None
            return bool(user["totp_enabled"]), user["id"]

    # ── SMTP Config ───────────────────────────────────────────────────

    def get_smtp_config(self):
        if os.path.exists(SMTP_CONFIG_PATH):
            with open(SMTP_CONFIG_PATH) as f:
                return json.load(f)
        return {}

    def save_smtp_config(self, host, port, username, password,
                         from_email, use_tls=True):
        cfg = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "from_email": from_email,
            "use_tls": use_tls,
        }
        os.makedirs(os.path.dirname(SMTP_CONFIG_PATH), exist_ok=True)
        with open(SMTP_CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
        return True

    def test_smtp(self, email):
        smtp_cfg = self.get_smtp_config()
        if not smtp_cfg or not smtp_cfg.get("host"):
            return False, "SMTP not configured."
        try:
            msg = MIMEText("This is a test email from AWS Audit Dashboard.")
            msg["Subject"] = "AWS Audit - SMTP Test"
            msg["From"] = smtp_cfg.get("from_email", smtp_cfg.get("username", ""))
            msg["To"] = email

            with smtplib.SMTP(smtp_cfg["host"], int(smtp_cfg.get("port", 587))) as server:
                server.ehlo()
                if smtp_cfg.get("use_tls", True):
                    server.starttls()
                if smtp_cfg.get("username") and smtp_cfg.get("password"):
                    server.login(smtp_cfg["username"], smtp_cfg["password"])
                server.sendmail(msg["From"], [email], msg.as_string())
            return True, "Test email sent successfully!"
        except Exception as e:
            return False, f"SMTP test failed: {e}"

    # ── Stats ─────────────────────────────────────────────────────────

    def get_dashboard_stats(self):
        with self._get_db() as (conn, cur):
            cur.execute("SELECT COUNT(*) as c FROM users")
            total_users = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) as c FROM users WHERE is_active = 1"
            )
            active_users = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) as c FROM audit_history"
            )
            total_audits = cur.fetchone()["c"]
            cur.execute(
                """SELECT username, last_login FROM users
                   WHERE last_login IS NOT NULL
                   ORDER BY last_login DESC LIMIT 1"""
            )
            recent_login = cur.fetchone()

            return {
                "total_users": total_users,
                "active_users": active_users,
                "total_audits": total_audits,
                "recent_login": dict(recent_login) if recent_login else None,
            }
