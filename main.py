from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import Request
from contextlib import asynccontextmanager
from pydantic import BaseModel, EmailStr
from pydantic_settings import BaseSettings
from passlib.context import CryptContext
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
import os
import csv
import io
import secrets
# logging imports
import logging
from logging.handlers import RotatingFileHandler
import json
from functools import wraps
from typing import Optional

#setup logging files
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure main application logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            'logs/app.log',
            maxBytes=10485760,  # 10MB
            backupCount=10
        ),
        logging.StreamHandler()  # Also log to console
    ]
)

logger = logging.getLogger('inventory_app')

# Create separate loggers for different purposes
audit_logger = logging.getLogger('audit')
audit_handler = RotatingFileHandler('logs/audit.log', maxBytes=10485760, backupCount=10)
audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

error_logger = logging.getLogger('errors')
error_handler = RotatingFileHandler('logs/errors.log', maxBytes=10485760, backupCount=10)
error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
error_logger.addHandler(error_handler)
error_logger.setLevel(logging.ERROR)

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    SMTP_SERVER: str
    SMTP_PORT: int
    SMTP_USERNAME: str
    SMTP_PASSWORD: str
    FRONTEND_URL: str

    class Config:
        env_file = ".env"

settings = Settings()

DATABASE = settings.DATABASE_URL
SECRET_KEY = settings.SECRET_KEY
SMTP_SERVER = settings.SMTP_SERVER
SMTP_PORT = settings.SMTP_PORT
SMTP_USERNAME = settings.SMTP_USERNAME
SMTP_PASSWORD = settings.SMTP_PASSWORD
FRONTEND_URL = settings.FRONTEND_URL

# Database setup
def init_db():
    """Initialize the database with tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'engineer',
            territory TEXT,
            session_token TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Stores table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            location TEXT,
            assigned_user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assigned_user_id) REFERENCES users (id)
        )
    ''')
    
    # Work Orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS work_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            work_order_number TEXT UNIQUE NOT NULL,
            customer_name TEXT,
            description TEXT,
            status TEXT DEFAULT 'open',
            assigned_engineer_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assigned_engineer_id) REFERENCES users (id)
        )
    ''')
    
    # Parts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS parts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            part_number TEXT UNIQUE NOT NULL,
            description TEXT,
            category TEXT,
            unit_cost REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Inventory table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_id INTEGER NOT NULL,
            part_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0,
            min_threshold INTEGER DEFAULT 0,
            work_order_id TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (store_id) REFERENCES stores (id),
            FOREIGN KEY (part_id) REFERENCES parts (id),
            FOREIGN KEY (work_order_id) REFERENCES work_orders (id),
            UNIQUE(store_id, part_id, work_order_id)
        )
    ''')
    
    # Movements table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_store_id INTEGER,
            to_store_id INTEGER,
            part_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            movement_type TEXT NOT NULL,
            work_order_id INTEGER,
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (from_store_id) REFERENCES stores (id),
            FOREIGN KEY (to_store_id) REFERENCES stores (id),
            FOREIGN KEY (part_id) REFERENCES parts (id),
            FOREIGN KEY (work_order_id) REFERENCES work_orders (id),
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')

    # Activity Logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id INTEGER,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            status TEXT DEFAULT 'success',
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create indexes for better query performance
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_activity_user 
        ON activity_logs(user_id)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_activity_action 
        ON activity_logs(action)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_activity_created 
        ON activity_logs(created_at)
    ''')
    
    # System Logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            component TEXT,
            message TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data
    insert_sample_data(cursor)
    
    conn.commit()
    conn.close()

def insert_sample_data(cursor):
    """Insert sample data for testing"""
    
    # Sample users
    users_data = [
        ('valentine.opiyo@varian.com', 'Valentine Opiyo', hash_password('admin123'), 'admin', 'Kenya'),
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO users (email, name, password_hash, role, territory)
        VALUES (?, ?, ?, ?, ?)
    ''', users_data)

def hash_password(password: str) -> str:
    """Hash password for storage"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_access_token(data: dict):
    """Create JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def check_admin(user_id: int) -> bool:
    """Check if the user is an admin"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user['role'] == 'admin':
        return True
    return False

def send_reset_email(email: str, token: str):
    """Send password reset email"""
    reset_link = f"{FRONTEND_URL}/static/reset-password.html?token={token}"
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Password Reset Request"
    msg['From'] = SMTP_USERNAME
    msg['To'] = email
    
    html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #f8f9fa; padding: 30px; border-radius: 8px;">
            <h2 style="color: #333;">Password Reset Request</h2>
            <p>You requested to reset your password for the Inventory Management System.</p>
            <p>Click the button below to reset your password:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_link}" 
                   style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                          color: white; 
                          padding: 12px 30px; 
                          text-decoration: none; 
                          border-radius: 8px;
                          display: inline-block;">
                    Reset Password
                </a>
            </div>
            <p style="color: #666; font-size: 14px;">
                This link will expire in 1 hour.<br>
                If you didn't request this, please ignore this email.
            </p>
        </div>
      </body>
    </html>
    """
    
    part = MIMEText(html, 'html')
    msg.attach(part)
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send reset email")

# ============ LOGGING UTILITIES ============

def log_activity(user_id: int, username: str, action: str, resource_type: str = None, 
                 resource_id: int = None, details: dict = None, status: str = 'success',
                 error_message: str = None, ip_address: str = None, user_agent: str = None):
    """Log user activity to database and audit log file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        details_json = json.dumps(details) if details else None
        
        cursor.execute("""
            INSERT INTO activity_logs 
            (user_id, username, action, resource_type, resource_id, details, 
             ip_address, user_agent, status, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, action, resource_type, resource_id, details_json,
              ip_address, user_agent, status, error_message))
        
        conn.commit()
        conn.close()
        
        # Also log to audit file
        audit_logger.info(
            f"USER={username}({user_id}) ACTION={action} "
            f"RESOURCE={resource_type}/{resource_id} STATUS={status}"
        )
        
    except Exception as e:
        error_logger.error(f"Failed to log activity: {str(e)}")

def log_system_event(level: str, component: str, message: str, details: dict = None):
    """Log system events to database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        details_json = json.dumps(details) if details else None
        
        cursor.execute("""
            INSERT INTO system_logs (level, component, message, details)
            VALUES (?, ?, ?, ?)
        """, (level, component, message, details_json))
        
        conn.commit()
        conn.close()
        
        # Also log to application log
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{component}] {message}")
        
    except Exception as e:
        error_logger.error(f"Failed to log system event: {str(e)}")

# ============ LOGGING DECORATOR ============

def log_endpoint(action: str, resource_type: str = None):
    """Decorator to automatically log API endpoint calls"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract parameters
            user_id = kwargs.get('user_id')
            request = None
            
            # Find Request object in kwargs or args
            for key, value in kwargs.items():
                if isinstance(value, Request):
                    request = value
                    break
            
            # Get IP and user agent if request is available
            ip_address = None
            user_agent = None
            if request:
                ip_address = request.client.host if hasattr(request, 'client') else None
                user_agent = request.headers.get('user-agent', '')[:200]
            
            username = "Unknown"
            resource_id = None
            details = {}
            status = 'success'
            error_message = None
            
            try:
                # Get username if user_id is available
                if user_id:
                    try:
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT name FROM users WHERE id = ?", (user_id,))
                        user = cursor.fetchone()
                        conn.close()
                        if user:
                            username = user['name']
                    except Exception as e:
                        logger.error(f"Failed to get username: {e}")
                
                # Execute the endpoint function
                result = await func(*args, **kwargs)
                
                # Extract resource_id from result if it's a dict
                if isinstance(result, dict):
                    resource_id = result.get('id')
                    # Create a safe copy of details without sensitive data
                    details = {k: v for k, v in result.items() 
                              if k not in ['password_hash', 'session_token', 'reset_token']}
                
                return result
                
            except HTTPException as e:
                status = 'error'
                error_message = e.detail
                error_logger.error(
                    f"HTTPException in {func.__name__}: {e.detail}",
                    extra={'user_id': user_id, 'status_code': e.status_code}
                )
                raise
                
            except Exception as e:
                status = 'error'
                error_message = str(e)
                error_logger.exception(
                    f"Exception in {func.__name__}: {str(e)}",
                    extra={'user_id': user_id}
                )
                raise
                
            finally:
                # Log the activity
                if user_id:
                    try:
                        log_activity(
                            user_id=user_id,
                            username=username,
                            action=action,
                            resource_type=resource_type,
                            resource_id=resource_id,
                            details=details,
                            status=status,
                            error_message=error_message,
                            ip_address=ip_address,
                            user_agent=user_agent
                        )
                    except Exception as log_error:
                        # Don't fail the request if logging fails
                        error_logger.error(f"Failed to log activity: {log_error}")
        
        return wrapper
    return decorator

# Lifespan event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Starting up...")
    logger.info("Application starting up")
    log_system_event('INFO', 'startup', 'Application initialized')

    init_db()
    print("✅ Database initialized")
    logger.info("Database initialized successfully")
    yield

    # Shutdown (if needed)
    print("⏹️ Shutting down...")
    logger.info("Application shutting down")
    log_system_event('INFO', 'shutdown', 'Application shut down gracefully')

# Initialize FastAPI app with lifespan
app = FastAPI(
    title="Inventory Management API", 
    version="1.0.0",
    lifespan=lifespan
)

# Security
security = HTTPBearer()

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (your HTML frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Pydantic models

#----User Mangaement Models----
class UserProfileUpdate(BaseModel):
    email: Optional[EmailStr] = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
#-------------------------------

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    role: str
    territory: Optional[str]

class StoreResponse(BaseModel):
    id: int
    name: str
    type: str
    location: Optional[str]
    assigned_user_id: Optional[int]

class PartResponse(BaseModel):
    id: int
    part_number: str
    description: str
    category: str
    unit_cost: float

class InventoryResponse(BaseModel):
    id: int
    part_number: str
    description: str
    store_name: str
    store_type: str
    store_owner: Optional[int]
    quantity: int
    min_threshold: int
    work_order: Optional[str]

class AddStockRequest(BaseModel):
    part_id: int
    store_id: int
    quantity: int
    work_order_number: Optional[str] = None

class CreateStoreRequest(BaseModel):
    name: str
    type: str
    location: Optional[str] = None
    assigned_user_id: Optional[int] = None

class UpdateStoreRequest(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    location: Optional[str] = None
    assigned_user_id: Optional[int] = None

class CreatePartRequest(BaseModel):
    part_number: str
    description: str
    category: str
    unit_cost: float

class UpdatePartRequest(BaseModel):
    part_number: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    unit_cost: Optional[float] = None

class MovementResponse(BaseModel):
    id: int
    from_store_name: Optional[str]
    to_store_name: Optional[str]
    part_number: str
    quantity: int
    movement_type: str
    work_order: Optional[str]
    created_by_name: str
    created_at: str

class UpdateStockRequest(BaseModel):
    inventory_id: int
    new_quantity: int

class TransferStockRequest(BaseModel):
    inventory_id: int
    to_store_id: int
    quantity: int

class CreateUserRequest(BaseModel):
    email: str
    name: str
    password: str
    role: str
    territory: Optional[str] = None

class UpdateUserRequest(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    territory: Optional[str] = None
    password: Optional[str] = None

class WorkOrderResponse(BaseModel):
    id: int
    work_order_number: str
    customer_name: Optional[str]
    description: Optional[str]
    status: str
    assigned_engineer_id: Optional[int]
    engineer_name: Optional[str]

class StatsResponse(BaseModel):
    total_parts: int
    total_stores: int
    low_stock: int
    my_parts: int

class ActivityLogResponse(BaseModel):
    id: int
    user_id: int
    username: str
    action: str
    resource_type: Optional[str]
    resource_id: Optional[int]
    details: Optional[str]
    ip_address: Optional[str]
    status: str
    error_message: Optional[str]
    created_at: str

# calibration models
class EquipmentResponse(BaseModel):
    id: int
    equipment_name: str
    make: str
    model: str
    serial_number: str
    assigned_user_id: Optional[int]
    assigned_user_name: Optional[str]
    calibration_cert_number: Optional[str]
    calibration_authority: Optional[str]
    calibration_date: Optional[str]
    next_calibration_date: Optional[str]
    status: str
    notes: Optional[str]
    days_until_calibration: Optional[int]

class CreateEquipmentRequest(BaseModel):
    equipment_name: str
    make: str
    model: str
    serial_number: str
    assigned_user_id: Optional[int] = None
    calibration_cert_number: Optional[str] = None
    calibration_authority: Optional[str] = None
    calibration_date: Optional[str] = None
    next_calibration_date: Optional[str] = None
    notes: Optional[str] = None

class UpdateEquipmentRequest(BaseModel):
    equipment_name: Optional[str] = None
    make: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    assigned_user_id: Optional[int] = None
    calibration_cert_number: Optional[str] = None
    calibration_authority: Optional[str] = None
    calibration_date: Optional[str] = None
    next_calibration_date: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None

class TransferEquipmentRequest(BaseModel):
    to_user_id: Optional[int] = None
    notes: Optional[str] = None

class UpdateCalibrationRequest(BaseModel):
    calibration_cert_number: str
    calibration_authority: str
    calibration_date: str
    next_calibration_date: str
    notes: Optional[str] = None

class EquipmentStatsResponse(BaseModel):
    total_equipment: int
    my_equipment: int
    due_soon: int
    overdue: int

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE session_token = ?", (token,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session.")
    return user['id']

# Routes
#-----------Profile Management Routes-----------
@app.get("/api/profile")
async def get_profile(user_id: int = Depends(get_current_user), request: Request = None):
    """Get current user's profile"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, email, name, role, territory, created_at FROM users WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return dict(user)

@app.put("/api/profile")
async def update_profile(
    profile_update: UserProfileUpdate,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Update user profile (email)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    if profile_update.email:
        # Check if email already exists
        cursor.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?",
            (profile_update.email, user_id)
        )
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Email already in use")
        
        cursor.execute(
            "UPDATE users SET email = ? WHERE id = ?",
            (profile_update.email, user_id)
        )
    
    conn.commit()
    
    # Get updated user info
    cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    return {"message": "Profile updated successfully", "email": user['email']}

@app.post("/api/profile/change-password")
async def change_password(
    password_data: PasswordChange,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Change user password"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get current user
    cursor.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify current password
    if user['password_hash'] != hash_password(password_data.current_password):
        conn.close()
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Validate new password
    if len(password_data.new_password) < 8:
        conn.close()
        raise HTTPException(
            status_code=400, 
            detail="Password must be at least 8 characters long"
        )
    
    # Update password and invalidate session token
    cursor.execute(
        "UPDATE users SET password_hash = ?, session_token = NULL WHERE id = ?",
        (hash_password(password_data.new_password), user_id)
    )
    
    conn.commit()
    conn.close()
    
    return {"message": "Password changed successfully. Please login again."}

@app.post("/api/forgot-password")
async def forgot_password(request_data: ForgotPasswordRequest, request: Request = None):
    """Initiate password reset process"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Find user by email
    cursor.execute(
        "SELECT id FROM users WHERE email = ?",
        (request_data.email,)
    )
    user = cursor.fetchone()
    
    # Always return success to prevent email enumeration
    if not user:
        conn.close()
        return {"message": "If the email exists, a reset link has been sent"}
    
    user_id = user['id']
    
    # Generate reset token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=1)
    
    # Store token in users table (we'll add a column for this)
    cursor.execute(
        """UPDATE users 
           SET reset_token = ?, reset_token_expires = ? 
           WHERE id = ?""",
        (token, expires_at.isoformat(), user_id)
    )
    
    conn.commit()
    conn.close()
    
    # Send email
    try:
        send_reset_email(request_data.email, token)
    except:
        pass  # Fail silently to prevent information disclosure
    
    return {"message": "If the email exists, a reset link has been sent"}

@app.post("/api/reset-password")
async def reset_password(request_data: ResetPasswordRequest, request: Request = None):
    """Reset password using token"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Validate token
    cursor.execute(
        """SELECT id, reset_token_expires 
           FROM users 
           WHERE reset_token = ?""",
        (request_data.token,)
    )
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    # Check if token expired
    expires_at = datetime.fromisoformat(user['reset_token_expires'])
    if datetime.utcnow() > expires_at:
        conn.close()
        raise HTTPException(status_code=400, detail="Token has expired")
    
    # Validate new password
    if len(request_data.new_password) < 8:
        conn.close()
        raise HTTPException(
            status_code=400, 
            detail="Password must be at least 8 characters long"
        )
    
    # Update password and clear token
    cursor.execute(
        """UPDATE users 
           SET password_hash = ?, 
               reset_token = NULL, 
               reset_token_expires = NULL,
               session_token = NULL
           WHERE id = ?""",
        (hash_password(request_data.new_password), user['id'])
    )
    
    conn.commit()
    conn.close()
    
    return {"message": "Password reset successfully"}

@app.get("/api/verify-reset-token/{token}")
async def verify_reset_token(token: str, request: Request = None):
    """Verify if a reset token is valid"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """SELECT reset_token_expires 
           FROM users 
           WHERE reset_token = ?""",
        (token,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    expires_at = datetime.fromisoformat(user['reset_token_expires'])
    if datetime.utcnow() > expires_at:
        raise HTTPException(status_code=400, detail="Token has expired")
    
    return {"valid": True}
#-----------------------------------------------

@app.post("/api/auth/login")
async def login(user_login: UserLogin, request: Request):
    """User login"""
    ip_address = request.client.host if hasattr(request, 'client') else None
    user_agent = request.headers.get('user-agent', '')[:200]  # Truncate long user agents

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, email, name, role, territory, password_hash FROM users WHERE email = ?",
        (user_login.email,)
    )
    user = cursor.fetchone()

    if not user or user['password_hash'] != hash_password(user_login.password):
        # Log failed login attempt
        log_activity(
            user_id=0,
            username=user_login.email,
            action='login_failed',
            status='error',
            error_message='Invalid credentials',
            ip_address=ip_address,
            user_agent=user_agent
        )
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate a new session token
    session_token = secrets.token_urlsafe(32)
    cursor.execute("UPDATE users SET session_token = ? WHERE id = ?", (session_token, user['id']))
    conn.commit()
    conn.close()

    # Log successful login
    log_activity(
        user_id=user['id'],
        username=user['name'],
        action='login',
        details={'role': user['role'], 'territory': user['territory']},
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    logger.info(f"User {user['name']} ({user['id']}) logged in from {ip_address}")

    return {
        "access_token": session_token,
        "token_type": "bearer",
        "user": {
            "id": user['id'],
            "email": user['email'],
            "name": user['name'],
            "role": user['role'],
            "territory": user['territory']
        }
    }

@app.post("/api/auth/logout")
@log_endpoint(action='logout')
async def logout(user_id: int = Depends(get_current_user), request: Request = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET session_token = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/me", response_model=UserResponse)
async def get_current_user_info(user_id: int = Depends(get_current_user), request: Request = None):
    """Get current user information"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, email, name, role, territory FROM users WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return dict(user)

@app.get("/api/stores", response_model=List[StoreResponse])
async def get_stores(user_id: int = Depends(get_current_user), request: Request = None):
    """Get all stores (engineers see all, others see assigned)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user role
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] in ['admin', 'manager']:
        cursor.execute("SELECT id, name, type, location, assigned_user_id FROM stores")
    else:
        # Engineers see all stores for visibility
        cursor.execute("SELECT id, name, type, location, assigned_user_id FROM stores")
    
    stores = cursor.fetchall()
    conn.close()
    
    return [dict(store) for store in stores]

@app.get("/api/parts", response_model=List[PartResponse])
@log_endpoint(action='view_parts', resource_type='parts')
async def get_parts(user_id: int = Depends(get_current_user), request: Request = None):
    """Get all parts"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, part_number, description, category, unit_cost FROM parts")
    parts = cursor.fetchall()
    conn.close()
    
    return [dict(part) for part in parts]

@app.get("/api/inventory", response_model=List[InventoryResponse])
async def get_inventory(user_id: int = Depends(get_current_user), request: Request = None):
    """Get inventory with full visibility for engineers"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT 
            i.id,
            p.part_number,
            p.description,
            s.name as store_name,
            s.type as store_type,
            s.assigned_user_id as store_owner,
            i.quantity,
            i.min_threshold,
            wo.work_order_number as work_order
        FROM inventory i
        JOIN parts p ON i.part_id = p.id
        JOIN stores s ON i.store_id = s.id
        LEFT JOIN work_orders wo ON i.work_order_id = wo.id
        ORDER BY p.part_number, s.name
    '''
    
    cursor.execute(query)
    inventory = cursor.fetchall()
    conn.close()
    
    return [dict(item) for item in inventory]

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats(user_id: int = Depends(get_current_user), request: Request = None):
    """Get dashboard statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total unique parts
    cursor.execute("SELECT COUNT(DISTINCT part_number) FROM parts")
    total_parts = cursor.fetchone()[0]
    
    # Total stores
    cursor.execute("SELECT COUNT(*) FROM stores")
    total_stores = cursor.fetchone()[0]
    
    # Low stock items
    cursor.execute("SELECT COUNT(*) FROM inventory WHERE quantity <= min_threshold")
    low_stock = cursor.fetchone()[0]
    
    # User's parts (stores they own)
    cursor.execute("""
        SELECT COUNT(DISTINCT i.part_id) 
        FROM inventory i 
        JOIN stores s ON i.store_id = s.id 
        WHERE s.assigned_user_id = ?
    """, (user_id,))
    my_parts = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "total_parts": total_parts,
        "total_stores": total_stores,
        "low_stock": low_stock,
        "my_parts": my_parts
    }

@app.post("/api/inventory/add")
@log_endpoint(action='add_stock', resource_type='inventory')
async def add_stock(request_data: AddStockRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Add stock to inventory"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user can edit this store
    cursor.execute("""
        SELECT type, assigned_user_id FROM stores WHERE id = ?
    """, (request_data.store_id,))
    store = cursor.fetchone()
    
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    
    # Check permissions
    if store['type'] not in ['central'] and store['assigned_user_id'] != user_id:
        # Get user role
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Permission denied")
    
    # Get work order ID if provided
    work_order_id = None
    if request_data.work_order_number:
        cursor.execute(
            "SELECT id FROM work_orders WHERE work_order_number = ?",
            (request_data.work_order_number,)
        )
        wo = cursor.fetchone()
        if wo:
            work_order_id = wo['id']
        else:
            # Create new work order
            cursor.execute("""
                INSERT INTO work_orders (work_order_number, assigned_engineer_id)
                VALUES (?, ?)
            """, (request_data.work_order_number, user_id))
            work_order_id = cursor.lastrowid
    
    # Add or update inventory
    cursor.execute("""
        INSERT INTO inventory (store_id, part_id, quantity, work_order_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(store_id, part_id, work_order_id) 
        DO UPDATE SET quantity = quantity + ?
    """, (request_data.store_id, request_data.part_id, request_data.quantity, work_order_id, request_data.quantity))

    # get id of last inserted inventory item
    cursor.execute("""
        SELECT last_insert_rowid()
    """)
    inventory_id = cursor.fetchone()[0]
    
    # Log movement
    cursor.execute("""
        INSERT INTO movements (to_store_id, part_id, quantity, movement_type, work_order_id, created_by)
        VALUES (?, ?, ?, 'add', ?, ?)
    """, (request_data.store_id, request_data.part_id, request_data.quantity, work_order_id, user_id))
    
    conn.commit()
    conn.close()
    # The decorator will automatically log this action
    return {"success": True, "id": inventory_id, "part_id": request_data.part_id, "quantity": request_data.quantity}
    
@app.put("/api/inventory/update")
@log_endpoint(action='update_stock', resource_type='inventory')
async def update_stock(request_data: UpdateStockRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Update inventory quantity"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get inventory item and check permissions
    cursor.execute("""
        SELECT i.*, s.type, s.assigned_user_id, p.part_number
        FROM inventory i
        JOIN stores s ON i.store_id = s.id
        JOIN parts p ON i.part_id = p.id
        WHERE i.id = ?
    """, (request_data.inventory_id,))
    item = cursor.fetchone()
    
    if not item:
        raise HTTPException(status_code=404, detail="Inventory item not found")
    
    # Check permissions
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if (item['type'] not in ['central'] and 
        item['assigned_user_id'] != user_id and 
        user['role'] != 'admin'):
        raise HTTPException(status_code=403, detail="Permission denied")
    
    old_quantity = item['quantity']
    quantity_change = request_data.new_quantity - old_quantity
    
    # Update inventory
    cursor.execute("""
        UPDATE inventory 
        SET quantity = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (request_data.new_quantity, request_data.inventory_id))
    
    # Log movement
    movement_type = 'add' if quantity_change > 0 else 'remove'
    cursor.execute("""
        INSERT INTO movements (to_store_id, part_id, quantity, movement_type, work_order_id, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (item['store_id'], item['part_id'], abs(quantity_change), movement_type, item['work_order_id'], user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Updated {item['part_number']} quantity from {old_quantity} to {request_data.new_quantity}"}

@app.post("/api/inventory/transfer")
@log_endpoint(action='transfer_stock', resource_type='inventory')
async def transfer_stock(request_data: TransferStockRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Transfer stock between stores"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get source inventory item
    cursor.execute("""
        SELECT i.*, s.type as from_store_type, s.assigned_user_id as from_store_owner, p.part_number
        FROM inventory i
        JOIN stores s ON i.store_id = s.id
        JOIN parts p ON i.part_id = p.id
        WHERE i.id = ?
    """, (request_data.inventory_id,))
    source_item = cursor.fetchone()
    
    if not source_item:
        raise HTTPException(status_code=404, detail="Source inventory item not found")
    
    if source_item['quantity'] < request_data.quantity:
        raise HTTPException(status_code=400, detail="Insufficient quantity in source store")
    
    # Get destination store
    cursor.execute("SELECT type, assigned_user_id FROM stores WHERE id = ?", (request_data.to_store_id,))
    dest_store = cursor.fetchone()
    
    if not dest_store:
        raise HTTPException(status_code=404, detail="Destination store not found")
    
    # Check permissions for both stores
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    # Can transfer from stores you can edit
    can_edit_from = (source_item['from_store_type'] == 'central' or 
                     source_item['from_store_owner'] == user_id or 
                     user['role'] == 'admin')
    
    # Can transfer to stores you can edit
    can_edit_to = (dest_store['type'] == 'central' or 
                   dest_store['assigned_user_id'] == user_id or 
                   user['role'] == 'admin')
    
    if not (can_edit_from and can_edit_to):
        raise HTTPException(status_code=403, detail="Permission denied for transfer")
    
    # Update source inventory
    new_source_quantity = source_item['quantity'] - request_data.quantity
    if new_source_quantity == 0:
        # Remove the inventory record if quantity becomes 0
        cursor.execute("DELETE FROM inventory WHERE id = ?", (request_data.inventory_id,))
    else:
        cursor.execute("""
            UPDATE inventory 
            SET quantity = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_source_quantity, request_data.inventory_id))
    
    # Add or update destination inventory
    cursor.execute("""
        INSERT INTO inventory (store_id, part_id, quantity, work_order_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(store_id, part_id, work_order_id) 
        DO UPDATE SET quantity = quantity + ?, updated_at = CURRENT_TIMESTAMP
    """, (request_data.to_store_id, source_item['part_id'], request_data.quantity, 
          source_item['work_order_id'], request_data.quantity))
    
    # Log movement
    cursor.execute("""
        INSERT INTO movements (from_store_id, to_store_id, part_id, quantity, movement_type, work_order_id, created_by)
        VALUES (?, ?, ?, ?, 'transfer', ?, ?)
    """, (source_item['store_id'], request_data.to_store_id, source_item['part_id'], 
          request_data.quantity, source_item['work_order_id'], user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Transferred {request_data.quantity} {source_item['part_number']} successfully"}

@app.get("/api/work-orders", response_model=List[WorkOrderResponse])
async def get_work_orders(user_id: int = Depends(get_current_user), request: Request = None):
    """Get work orders"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user role
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] == 'admin':
        # Admin sees all work orders
        query = """
            SELECT wo.*, u.name as engineer_name
            FROM work_orders wo
            LEFT JOIN users u ON wo.assigned_engineer_id = u.id
            ORDER BY wo.created_at DESC
        """
        cursor.execute(query)
    else:
        # Engineers see only their work orders
        query = """
            SELECT wo.*, u.name as engineer_name
            FROM work_orders wo
            LEFT JOIN users u ON wo.assigned_engineer_id = u.id
            WHERE wo.assigned_engineer_id = ?
            ORDER BY wo.created_at DESC
        """
        cursor.execute(query, (user_id,))
    
    work_orders = cursor.fetchall()
    conn.close()
    
    return [dict(wo) for wo in work_orders]

# User Management (Admin only)
@app.get("/api/users", response_model=List[UserResponse])
@log_endpoint(action='view_users', resource_type='user')
async def get_users(user_id: int = Depends(get_current_user), request: Request = None):
    """Get all users (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    cursor.execute("SELECT id, email, name, role, territory FROM users ORDER BY name")
    users = cursor.fetchall()
    conn.close()
    
    return [dict(user) for user in users]

#-------------Logging Test Endpoint-------------
@app.get("/api/logs/test")
async def test_logging(user_id: int = Depends(get_current_user), request: Request = None):
    """Test endpoint to verify logging is working"""
    try:
        # Test database connection
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='activity_logs'
        """)
        table_exists = cursor.fetchone() is not None
        
        # Get count of logs
        if table_exists:
            cursor.execute("SELECT COUNT(*) as count FROM activity_logs")
            log_count = cursor.fetchone()['count']
        else:
            log_count = 0
        
        # Get user info
        cursor.execute("SELECT name, role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        conn.close()
        
        return {
            "status": "ok",
            "table_exists": table_exists,
            "log_count": log_count,
            "current_user": dict(user) if user else None,
            "can_view_logs": user['role'] == 'admin' if user else False
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

@app.post("/api/users")
@log_endpoint(action='create_user', resource_type='user')
async def create_user(request_data: CreateUserRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Create new user (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if email already exists
    cursor.execute("SELECT id FROM users WHERE email = ?", (request_data.email,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Create user
    cursor.execute("""
        INSERT INTO users (email, name, password_hash, role, territory)
        VALUES (?, ?, ?, ?, ?)
    """, (request_data.email, request_data.name, hash_password(request_data.password), 
          request_data.role, request_data.territory))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"User {request_data.name} created successfully"}

@app.put("/api/users/{target_user_id}")
@log_endpoint(action='update_user', resource_type='user')
async def update_user(target_user_id: int, request_data: UpdateUserRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Update user (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if target user exists
    cursor.execute("SELECT id FROM users WHERE id = ?", (target_user_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="User not found")
    
    # Build update query dynamically
    updates = []
    values = []
    
    if request_data.name is not None:
        updates.append("name = ?")
        values.append(request_data.name)
    
    if request_data.role is not None:
        updates.append("role = ?")
        values.append(request_data.role)
    
    if request_data.territory is not None:
        updates.append("territory = ?")
        values.append(request_data.territory)
    
    if request_data.password is not None:
        updates.append("password_hash = ?")
        values.append(hash_password(request_data.password))
    
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    values.append(target_user_id)
    
    cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", values)
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "User updated successfully"}

@app.delete("/api/users/{target_user_id}")
@log_endpoint(action='delete_user', resource_type='user')
async def delete_user(target_user_id: int, user_id: int = Depends(get_current_user), request: Request = None):
    """Delete user (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Don't allow deleting yourself
    if target_user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Check if user exists
    cursor.execute("SELECT name FROM users WHERE id = ?", (target_user_id,))
    target_user = cursor.fetchone()
    
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete user (this will cascade and update related records)
    cursor.execute("DELETE FROM users WHERE id = ?", (target_user_id,))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"User {target_user['name']} deleted successfully"}

# Store Management
@app.post("/api/stores")
@log_endpoint(action='create_store', resource_type='store')
async def create_store(request_data: CreateStoreRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Create new store (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Validate store type
    valid_types = ['central', 'customer_site', 'engineer', 'fe_consignment']
    if request_data.type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid store type. Must be one of: {', '.join(valid_types)}")
    
    # Create store
    cursor.execute("""
        INSERT INTO stores (name, type, location, assigned_user_id)
        VALUES (?, ?, ?, ?)
    """, (request_data.name, request_data.type, request_data.location, request_data.assigned_user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Store {request_data.name} created successfully"}

# Bulk import stores from CSV (admin only)
@app.post("/api/stores/bulk-import")
@log_endpoint(action='bulk_import_stores', resource_type='store')
async def bulk_import_stores(
    file: UploadFile = File(...),
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Bulk import stores from a CSV file (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    content = await file.read()
    reader = csv.DictReader(io.StringIO(content.decode()))
    added, skipped = 0, 0
    # this should be moved from hardcoded to a db table in future
    valid_types = ['office', 'customer_site', 'engineer', 'fe_consignment', 'self', 'admin', 'manager', 'warehouse']
    for row in reader:
        try:
            # Validate type
            if row['type'] not in valid_types:
                skipped += 1
                continue
            # assigned_user_id can be empty
            assigned_user_id = int(row['assigned_user_id']) if row.get('assigned_user_id') else None
            cursor.execute(
                "INSERT INTO stores (name, type, location, assigned_user_id) VALUES (?, ?, ?, ?)",
                (row['name'], row['type'], row.get('location'), assigned_user_id)
            )
            added += 1
        except Exception as e:
            skipped += 1
            continue
    conn.commit()
    conn.close()
    return {"success": True, "added": added, "skipped": skipped}

@app.put("/api/stores/{store_id}")
@log_endpoint(action='update_store', resource_type='store')
async def update_store(store_id: int, request_data: UpdateStoreRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Update store (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if store exists
    cursor.execute("SELECT id FROM stores WHERE id = ?", (store_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Store not found")
    
    # Build update query dynamically
    updates = []
    values = []
    
    if request_data.name is not None:
        updates.append("name = ?")
        values.append(request_data.name)
    
    if request_data.type is not None:
        # a store can either be at the office, personal or customer_site
        valid_types = ['office', 'customer_site', 'engineer', 'fe_consignment']
        if request_data.type not in valid_types:
            raise HTTPException(status_code=400, detail=f"Invalid store type. Must be one of: {', '.join(valid_types)}")
        updates.append("type = ?")
        values.append(request_data.type)
    
    if request_data.location is not None:
        updates.append("location = ?")
        values.append(request_data.location)
    
    if request_data.assigned_user_id is not None:
        updates.append("assigned_user_id = ?")
        values.append(request_data.assigned_user_id)
    
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    values.append(store_id)
    
    cursor.execute(f"UPDATE stores SET {', '.join(updates)} WHERE id = ?", values)
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Store updated successfully"}

@app.delete("/api/stores/{store_id}")
@log_endpoint(action='delete_store', resource_type='store')
async def delete_store(store_id: int, user_id: int = Depends(get_current_user), request: Request = None):
    """Delete store (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if store exists and get name
    cursor.execute("SELECT name FROM stores WHERE id = ?", (store_id,))
    store = cursor.fetchone()
    
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    
    # Check if store has inventory
    cursor.execute("SELECT COUNT(*) as count FROM inventory WHERE store_id = ?", (store_id,))
    inventory_count = cursor.fetchone()['count']
    
    if inventory_count > 0:
        raise HTTPException(status_code=400, detail=f"Cannot delete store with {inventory_count} inventory items. Please transfer or remove inventory first.")
    
    # Delete store
    cursor.execute("DELETE FROM stores WHERE id = ?", (store_id,))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Store {store['name']} deleted successfully"}

# Parts Management
@app.post("/api/parts")
@log_endpoint(action='create_store', resource_type='store')
async def create_part(request_data: CreatePartRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Create new part (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if part number already exists
    cursor.execute("SELECT id FROM parts WHERE part_number = ?", (request_data.part_number,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Part number already exists")
    
    # Create part
    cursor.execute("""
        INSERT INTO parts (part_number, description, category, unit_cost)
        VALUES (?, ?, ?, ?)
    """, (request_data.part_number, request_data.description, request_data.category, request_data.unit_cost))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Part {request_data.part_number} created successfully"}

# ...existing code...

@app.post("/api/parts/bulk-import")
@log_endpoint(action='bulk_import_stores', resource_type='store')
async def bulk_import_parts(
    file: UploadFile = File(...),
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Bulk import parts from a CSV file (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    content = await file.read()
    reader = csv.DictReader(io.StringIO(content.decode()))
    added, skipped = 0, 0
    for row in reader:
        try:
            cursor.execute(
                "INSERT INTO parts (part_number, description, category, unit_cost) VALUES (?, ?, ?, ?)",
                (row['part_number'], row['description'], row['category'], float(row['unit_cost']))
            )
            added += 1
        except Exception:
            skipped += 1
            continue
    conn.commit()
    conn.close()
    return {"success": True, "added": added, "skipped": skipped}

@app.put("/api/parts/{part_id}")
@log_endpoint(action='update_part', resource_type='part')
async def update_part(part_id: int, request_data: UpdatePartRequest, user_id: int = Depends(get_current_user), request: Request = None):
    """Update part (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if part exists
    cursor.execute("SELECT id FROM parts WHERE id = ?", (part_id,))
    if not cursor.fetchone():
        raise HTTPException(status_code=404, detail="Part not found")
    
    # Build update query dynamically
    updates = []
    values = []
    
    if request_data.part_number is not None:
        # Check if new part number already exists
        cursor.execute("SELECT id FROM parts WHERE part_number = ? AND id != ?", (request_data.part_number, part_id))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Part number already exists")
        updates.append("part_number = ?")
        values.append(request_data.part_number)
    
    if request_data.description is not None:
        updates.append("description = ?")
        values.append(request_data.description)
    
    if request_data.category is not None:
        updates.append("category = ?")
        values.append(request_data.category)
    
    if request_data.unit_cost is not None:
        updates.append("unit_cost = ?")
        values.append(request_data.unit_cost)
    
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    values.append(part_id)
    
    cursor.execute(f"UPDATE parts SET {', '.join(updates)} WHERE id = ?", values)
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Part updated successfully"}

@app.delete("/api/parts/{part_id}")
@log_endpoint(action='delete_part', resource_type='part')
async def delete_part(part_id: int, user_id: int = Depends(get_current_user), request: Request = None):
    """Delete part (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if current user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if part exists and get details
    cursor.execute("SELECT part_number FROM parts WHERE id = ?", (part_id,))
    part = cursor.fetchone()
    
    if not part:
        raise HTTPException(status_code=404, detail="Part not found")
    
    # Check if part has inventory
    cursor.execute("SELECT COUNT(*) as count FROM inventory WHERE part_id = ?", (part_id,))
    inventory_count = cursor.fetchone()['count']
    
    if inventory_count > 0:
        raise HTTPException(status_code=400, detail=f"Cannot delete part with {inventory_count} inventory records. Please remove inventory first.")
    
    # Delete part
    cursor.execute("DELETE FROM parts WHERE id = ?", (part_id,))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Part {part['part_number']} deleted successfully"}

# Movement History
@app.get("/api/movements", response_model=List[MovementResponse])
async def get_movements(
    user_id: int = Depends(get_current_user), 
    limit: int = 100,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    movement_type: Optional[str] = None,
    part_id: Optional[int] = None,
    store_id: Optional[int] = None,
    request: Request = None
):
    """Get movement history with advanced filtering"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    
    query = """
        SELECT 
            m.id,
            s1.name as from_store_name,
            s2.name as to_store_name,
            p.part_number,
            m.quantity,
            m.movement_type,
            wo.work_order_number as work_order,
            u.name as created_by_name,
            m.created_at
        FROM movements m
        LEFT JOIN stores s1 ON m.from_store_id = s1.id
        LEFT JOIN stores s2 ON m.to_store_id = s2.id
        JOIN parts p ON m.part_id = p.id
        LEFT JOIN work_orders wo ON m.work_order_id = wo.id
        JOIN users u ON m.created_by = u.id
        WHERE 1=1
    """
    
    params = []
    
    # query += """
    #     AND (m.created_by = ? 
    #     OR s1.assigned_user_id = ?
    #     OR s2.assigned_user_id = ?)
    #     """
    # params.extend([user_id, user_id, user_id])
    
    # Date range filtering
    if start_date:
        query += " AND m.created_at >= ?"
        params.append(start_date)
    
    if end_date:
        query += " AND m.created_at <= ?"
        params.append(end_date + " 23:59:59")
    
    # Movement type filtering
    if movement_type:
        query += " AND m.movement_type = ?"
        params.append(movement_type)
    
    # Part filtering
    if part_id:
        query += " AND m.part_id = ?"
        params.append(part_id)
    
    # Store filtering (from or to)
    if store_id:
        query += " AND (m.from_store_id = ? OR m.to_store_id = ?)"
        params.extend([store_id, store_id])
    
    query += " ORDER BY m.created_at DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    movements = cursor.fetchall()
    conn.close()
    
    return [dict(movement) for movement in movements]

# ============ LOGGING ENDPOINTS ============

@app.get("/api/logs/activity", response_model=List[ActivityLogResponse])
async def get_activity_logs(
    user_id: int = Depends(get_current_user),
    limit: int = 100,
    action: Optional[str] = None,
    target_user_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    status: Optional[str] = None,
    request: Request = None
):
    """Get activity logs (admin only for all logs, users can see their own)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM activity_logs WHERE 1=1"
    params = []
    
    # Non-admins can only see their own logs
    if check_admin(user_id):
        query += " AND user_id = ?"
        params.append(user_id)
    else:
        # Admins can filter by specific user
        if target_user_id:
            query += " AND user_id = ?"
            params.append(target_user_id)
    
    # Apply filters
    if action:
        query += " AND action = ?"
        params.append(action)
    
    if start_date:
        query += " AND created_at >= ?"
        params.append(start_date)
    
    if end_date:
        query += " AND created_at <= ?"
        params.append(end_date + " 23:59:59")
    
    if status:
        query += " AND status = ?"
        params.append(status)
    
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    logs = cursor.fetchall()
    # conn.close()
    
    try:
        cursor.execute(query, params)
        logs = cursor.fetchall()
        conn.close()
        
        # Convert to list of dicts and ensure all fields are present
        result = []
        for log in logs:
            log_dict = dict(log)
            # Ensure all expected fields exist with defaults
            log_dict.setdefault('details', None)
            log_dict.setdefault('ip_address', None)
            log_dict.setdefault('user_agent', None)
            log_dict.setdefault('error_message', None)
            result.append(log_dict)
        
        return result
    except Exception as e:
        error_logger.error(f"Failed to get activity logs: {e}")
        conn.close()
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {str(e)}")

@app.get("/api/logs/activity/stats")
async def get_activity_stats(
    user_id: int = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    request: Request = None
):
    """Get activity statistics (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Date filter
    date_filter = ""
    params = []
    if start_date:
        date_filter += " AND created_at >= ?"
        params.append(start_date)
    if end_date:
        date_filter += " AND created_at <= ?"
        params.append(end_date + " 23:59:59")
    
    # Total activities
    cursor.execute(f"SELECT COUNT(*) as total FROM activity_logs WHERE 1=1 {date_filter}", params)
    total_activities = cursor.fetchone()['total']
    
    # Activities by action
    cursor.execute(f"""
        SELECT action, COUNT(*) as count 
        FROM activity_logs 
        WHERE 1=1 {date_filter}
        GROUP BY action 
        ORDER BY count DESC 
        LIMIT 10
    """, params)
    by_action = [dict(row) for row in cursor.fetchall()]
    
    # Activities by user (top 10)
    cursor.execute(f"""
        SELECT username, COUNT(*) as count 
        FROM activity_logs 
        WHERE 1=1 {date_filter}
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 10
    """, params)
    by_user = [dict(row) for row in cursor.fetchall()]
    
    # Error rate
    cursor.execute(f"""
        SELECT 
            COUNT(CASE WHEN status = 'error' THEN 1 END) as errors,
            COUNT(CASE WHEN status = 'success' THEN 1 END) as successes
        FROM activity_logs
        WHERE 1=1 {date_filter}
    """, params)
    error_stats = dict(cursor.fetchone())
    
    # Recent logins
    cursor.execute(f"""
        SELECT username, created_at, ip_address
        FROM activity_logs
        WHERE action = 'login' {date_filter}
        ORDER BY created_at DESC
        LIMIT 10
    """, params)
    recent_logins = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return {
        "total_activities": total_activities,
        "by_action": by_action,
        "by_user": by_user,
        "error_rate": error_stats,
        "recent_logins": recent_logins
    }

@app.delete("/api/logs/activity/cleanup")
async def cleanup_old_logs(
    days: int = 90,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Delete activity logs older than specified days (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Delete old logs
    cursor.execute("""
        DELETE FROM activity_logs 
        WHERE created_at < datetime('now', '-' || ? || ' days')
    """, (days,))
    
    deleted_count = cursor.rowcount
    
    conn.commit()
    conn.close()
    
    log_activity(
        user_id=user_id,
        username=user['name'],
        action='cleanup_logs',
        details={'days': days, 'deleted_count': deleted_count}
    )
    
    return {"success": True, "deleted_count": deleted_count, "days": days}

# equipment management routes
@app.get("/api/equipment/statistics", response_model=EquipmentStatsResponse)
async def get_equipment_stats(user_id: int = Depends(get_current_user), request: Request = None):
    """Get equipment statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user role
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    # Total equipment
    cursor.execute("SELECT COUNT(*) as count FROM equipment WHERE status = 'active'")
    total_equipment = cursor.fetchone()['count']
    
    # My equipment
    cursor.execute("""
        SELECT COUNT(*) as count FROM equipment 
        WHERE status = 'active' AND assigned_user_id = ?
    """, (user_id,))
    my_equipment = cursor.fetchone()['count']
    
    # Get calibration reminder days
    cursor.execute("""
        SELECT setting_value FROM system_settings 
        WHERE setting_key = 'calibration_reminder_days'
    """)
    reminder_setting = cursor.fetchone()
    reminder_days = int(reminder_setting['setting_value']) if reminder_setting else 30
    
    # Equipment due soon
    from datetime import datetime, timedelta
    check_date = (datetime.now() + timedelta(days=reminder_days)).strftime('%Y-%m-%d')
    
    if user['role'] == 'admin':
        cursor.execute("""
            SELECT COUNT(*) as count FROM equipment 
            WHERE status = 'active'
            AND next_calibration_date IS NOT NULL
            AND next_calibration_date <= ?
            AND next_calibration_date >= date('now')
        """, (check_date,))
    else:
        cursor.execute("""
            SELECT COUNT(*) as count FROM equipment 
            WHERE status = 'active'
            AND assigned_user_id = ?
            AND next_calibration_date IS NOT NULL
            AND next_calibration_date <= ?
            AND next_calibration_date >= date('now')
        """, (user_id, check_date))
    
    due_soon = cursor.fetchone()['count']
    
    # Overdue equipment
    if user['role'] == 'admin':
        cursor.execute("""
            SELECT COUNT(*) as count FROM equipment 
            WHERE status = 'active'
            AND next_calibration_date IS NOT NULL
            AND next_calibration_date < date('now')
        """)
    else:
        cursor.execute("""
            SELECT COUNT(*) as count FROM equipment 
            WHERE status = 'active'
            AND assigned_user_id = ?
            AND next_calibration_date IS NOT NULL
            AND next_calibration_date < date('now')
        """, (user_id,))
    
    overdue = cursor.fetchone()['count']
    
    conn.close()
    
    return {
        "total_equipment": total_equipment,
        "my_equipment": my_equipment,
        "due_soon": due_soon,
        "overdue": overdue
    }

@app.get("/api/equipment", response_model=List[EquipmentResponse])
@log_endpoint(action='view_equipment', resource_type='equipment')
async def get_equipment(
    user_id: int = Depends(get_current_user),
    show_all: bool = False,
    request: Request = None
):
    """Get equipment list"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user role
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    query = """
        SELECT 
            e.*,
            u.name as assigned_user_name,
            CAST(julianday(e.next_calibration_date) - julianday('now') AS INTEGER) as days_until_calibration
        FROM equipment e
        LEFT JOIN users u ON e.assigned_user_id = u.id
        WHERE e.status = 'active'
    """
    
    if not show_all and user['role'] != 'admin':
        query += " AND e.assigned_user_id = ?"
        cursor.execute(query + " ORDER BY e.next_calibration_date", (user_id,))
    else:
        cursor.execute(query + " ORDER BY e.next_calibration_date")
    
    equipment = cursor.fetchall()
    conn.close()
    
    return [dict(eq) for eq in equipment]

@app.post("/api/equipment")
@log_endpoint(action='create_equipment', resource_type='equipment')
async def create_equipment(
    request_data: CreateEquipmentRequest,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Create new equipment (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user is admin
    if not check_admin(user_id):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if serial number already exists
    cursor.execute("SELECT id FROM equipment WHERE serial_number = ?", (request_data.serial_number,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Serial number already exists")
    
    cursor.execute("""
        INSERT INTO equipment (
            equipment_name, make, model, serial_number, assigned_user_id,
            calibration_cert_number, calibration_authority, calibration_date,
            next_calibration_date, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        request_data.equipment_name, request_data.make, request_data.model,
        request_data.serial_number, request_data.assigned_user_id,
        request_data.calibration_cert_number, request_data.calibration_authority,
        request_data.calibration_date, request_data.next_calibration_date,
        request_data.notes
    ))
    
    equipment_id = cursor.lastrowid
    
    # Log history
    cursor.execute("""
        INSERT INTO equipment_history (equipment_id, action, to_user_id, created_by)
        VALUES (?, 'created', ?, ?)
    """, (equipment_id, request_data.assigned_user_id, user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "id": equipment_id, "message": "Equipment created successfully"}

@app.put("/api/equipment/{equipment_id}")
@log_endpoint(action='update_equipment', resource_type='equipment')
async def update_equipment(
    equipment_id: int,
    request_data: UpdateEquipmentRequest,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Update equipment (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if not check_admin(user_id):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Check if equipment exists
    cursor.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
    equipment = cursor.fetchone()
    if not equipment:
        raise HTTPException(status_code=404, detail="Equipment not found")
    
    # Build update query
    updates = []
    values = []
    
    for field, value in request_data.dict(exclude_unset=True).items():
        updates.append(f"{field} = ?")
        values.append(value)
    
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    updates.append("updated_at = CURRENT_TIMESTAMP")
    values.append(equipment_id)
    
    cursor.execute(
        f"UPDATE equipment SET {', '.join(updates)} WHERE id = ?",
        values
    )
    
    # Log history if assignment changed
    if request_data.assigned_user_id is not None and request_data.assigned_user_id != equipment['assigned_user_id']:
        cursor.execute("""
            INSERT INTO equipment_history (equipment_id, action, from_user_id, to_user_id, created_by)
            VALUES (?, 'transferred', ?, ?, ?)
        """, (equipment_id, equipment['assigned_user_id'], request_data.assigned_user_id, user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Equipment updated successfully"}

@app.post("/api/equipment/{equipment_id}/transfer")
@log_endpoint(action='transfer_equipment', resource_type='equipment')
async def transfer_equipment(
    equipment_id: int,
    request_data: TransferEquipmentRequest,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Transfer equipment to another user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get equipment
    cursor.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
    equipment = cursor.fetchone()
    if not equipment:
        raise HTTPException(status_code=404, detail="Equipment not found")
    
    # Check permissions
    if not check_admin(user_id) and equipment['assigned_user_id'] != user_id:
        raise HTTPException(status_code=403, detail="Permission denied")
    
    # Update equipment
    cursor.execute("""
        UPDATE equipment 
        SET assigned_user_id = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (request_data.to_user_id, equipment_id))
    
    # Log history
    cursor.execute("""
        INSERT INTO equipment_history (equipment_id, action, from_user_id, to_user_id, notes, created_by)
        VALUES (?, 'transferred', ?, ?, ?, ?)
    """, (equipment_id, equipment['assigned_user_id'], request_data.to_user_id, 
          request_data.notes, user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Equipment transferred successfully"}

@app.post("/api/equipment/{equipment_id}/calibrate")
@log_endpoint(action='calibrate_equipment', resource_type='equipment')
async def update_calibration(
    equipment_id: int,
    request_data: UpdateCalibrationRequest,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Update equipment calibration"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get equipment
    cursor.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
    equipment = cursor.fetchone()
    if not equipment:
        raise HTTPException(status_code=404, detail="Equipment not found")
    
    # Check permissions - admin or assigned user
    if not check_admin(user_id) and equipment['assigned_user_id'] != user_id:
        raise HTTPException(status_code=403, detail="Permission denied")
    
    # Update calibration
    cursor.execute("""
        UPDATE equipment 
        SET calibration_cert_number = ?,
            calibration_authority = ?,
            calibration_date = ?,
            next_calibration_date = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (
        request_data.calibration_cert_number,
        request_data.calibration_authority,
        request_data.calibration_date,
        request_data.next_calibration_date,
        equipment_id
    ))
    
    # Log history
    cursor.execute("""
        INSERT INTO equipment_history (
            equipment_id, action, calibration_date, notes, created_by
        ) VALUES (?, 'calibrated', ?, ?, ?)
    """, (equipment_id, request_data.calibration_date, request_data.notes, user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Calibration updated successfully"}

@app.delete("/api/equipment/{equipment_id}")
@log_endpoint(action='delete_equipment', resource_type='equipment')
async def delete_equipment(
    equipment_id: int,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Delete/deactivate equipment (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if not check_admin(user_id):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get equipment
    cursor.execute("SELECT equipment_name FROM equipment WHERE id = ?", (equipment_id,))
    equipment = cursor.fetchone()
    if not equipment:
        raise HTTPException(status_code=404, detail="Equipment not found")
    
    # Soft delete
    cursor.execute("""
        UPDATE equipment 
        SET status = 'deleted', updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (equipment_id,))
    
    # Log history
    cursor.execute("""
        INSERT INTO equipment_history (equipment_id, action, created_by)
        VALUES (?, 'deleted', ?)
    """, (equipment_id, user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Equipment {equipment['equipment_name']} deleted successfully"}

@app.get("/api/equipment/{equipment_id}/history")
async def get_equipment_history(
    equipment_id: int,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Get equipment history"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            eh.*,
            u1.name as from_user_name,
            u2.name as to_user_name,
            u3.name as created_by_name
        FROM equipment_history eh
        LEFT JOIN users u1 ON eh.from_user_id = u1.id
        LEFT JOIN users u2 ON eh.to_user_id = u2.id
        LEFT JOIN users u3 ON eh.created_by = u3.id
        WHERE eh.equipment_id = ?
        ORDER BY eh.created_at DESC
    """, (equipment_id,))
    
    history = cursor.fetchall()
    conn.close()
    
    return [dict(h) for h in history]

# System Settings endpoint
@app.get("/api/settings/calibration-reminder-days")
async def get_calibration_reminder_days(
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Get calibration reminder days setting"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT setting_value FROM system_settings 
        WHERE setting_key = 'calibration_reminder_days'
    """)
    result = cursor.fetchone()
    conn.close()
    
    return {"days": int(result['setting_value']) if result else 30}

@app.put("/api/settings/calibration-reminder-days")
async def update_calibration_reminder_days(
    days: int,
    user_id: int = Depends(get_current_user),
    request: Request = None
):
    """Update calibration reminder days setting (admin only)"""
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Days must be between 1 and 365")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if not check_admin(user_id):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    cursor.execute("""
        UPDATE system_settings 
        SET setting_value = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
        WHERE setting_key = 'calibration_reminder_days'
    """, (str(days), user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": f"Calibration reminder set to {days} days"}

@app.get("/")
async def root():
    """Serve the main application"""
    return {"message": "Inventory Management API", "docs": "/docs", "frontend": "/static/index.html"}

if __name__ == "__main__":
    import uvicorn
    print("🎯 Starting Inventory Management API...")
    print("📊 Frontend: http://localhost:8000/static/index.html")
    print("📚 API Docs: http://localhost:8000/docs")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)