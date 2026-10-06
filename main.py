from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi import Cookie
from fastapi import Header
from fastapi.responses import FileResponse

from contextlib import asynccontextmanager, contextmanager, closing
from pydantic import BaseModel, EmailStr, Field, validator, field_validator
from pydantic_settings import BaseSettings
from passlib.context import CryptContext
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List, Literal
import sqlite3
import hashlib
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

# rate limiting imports
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from jose import JWTError, jwt
from itsdangerous import URLSafeTimedSerializer


import shutil
from stock_audit import balance_snapshot, change_after, record_stock_audit, STOCK_AUDIT_ACTIONS, PROTECTED_AUDIT_SQL

# setup password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# setup logging files
if not os.path.exists("logs"):
    os.makedirs("logs")

# Configure main application logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler(
            "logs/app.log",
            maxBytes=10485760,  # 10MB
            backupCount=10,
        ),
        logging.StreamHandler(),  # Also log to console
    ],
)

logger = logging.getLogger("inventory_app")

# Create separate loggers for different purposes
audit_logger = logging.getLogger("audit")
audit_handler = RotatingFileHandler("logs/audit.log", maxBytes=10485760, backupCount=10)
audit_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

error_logger = logging.getLogger("errors")
error_handler = RotatingFileHandler(
    "logs/errors.log", maxBytes=10485760, backupCount=10
)
error_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
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
    CSRF_SECRET: str
    COOKIE_SECURE: bool = True
    CORS_ALLOWED_ORIGINS: List[str] = ["https://sparesinventory-production.up.railway.app"]

    @field_validator("CORS_ALLOWED_ORIGINS")
    @classmethod
    def reject_wildcard_origins(cls, origins):
        if any("*" in origin for origin in origins):
            raise ValueError("Credentialed CORS requires exact origins; wildcards are not allowed")
        return origins

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
CSRF_SECRET = settings.CSRF_SECRET

# authentication andlogin variables
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
SESSION_DURATION_HOURS = 24
REMEMBER_ME_DURATION_DAYS = 30

# csrf configuration
# CSRF_SECRET = os.getenv("CSRF_SECRET", SECRET_KEY)
csrf_serializer = URLSafeTimedSerializer(CSRF_SECRET)


# Database setup
from backend.database import connect_database, initialize_database, DEFAULT_SETTINGS


def database_defaults():
    return {**DEFAULT_SETTINGS,
        'max_login_attempts':str(MAX_LOGIN_ATTEMPTS),
        'lockout_duration_minutes':str(LOCKOUT_DURATION_MINUTES),
        'session_duration_hours':str(SESSION_DURATION_HOURS),
        'remember_me_duration_days':str(REMEMBER_ME_DURATION_DAYS)}


def init_db():
    """Apply explicit migrations and preserve configured bootstrap defaults."""
    initialize_database(DATABASE,defaults=database_defaults())


# ============ CSRF UTILITIES ============
def generate_csrf_token() -> str:
    """Generate CSRF token"""
    return csrf_serializer.dumps(secrets.token_urlsafe(32))


def verify_csrf_token(token: str, max_age: int = 3600) -> bool:
    """Verify CSRF token (valid for 1 hour by default)"""
    try:
        csrf_serializer.loads(token, max_age=max_age)
        return True
    except:
        return False


# ============ AUTHENTICATION UTILITIES ============
def hash_password(password: str) -> str:
    """Hash password for storage"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash"""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict):
    """Create JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")


def get_db_connection():
    """Open a configured connection using the application database path."""
    return connect_database(DATABASE)


def check_admin(user_id: int, conn=None) -> bool:
    """Check current authority, borrowing an owning mutation connection."""
    close = conn is None
    if close:
        conn = get_db_connection()
    try:
        user = conn.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
        return bool(user and user['role'] in {'admin', 'superadmin'})
    finally:
        if close:
            conn.close()


def require_archive_admin(conn,user_id):
    actor=conn.execute('SELECT role FROM users WHERE id=? AND archived_at IS NULL',(user_id,)).fetchone()
    if not actor or actor['role'] not in ('admin','superadmin'):
        raise HTTPException(status_code=403,detail='Admin access required')


from backend.services.stock_access import (
    require_active_record as _require_active_record,
    require_stock_access as _require_stock_access,
)
from backend.services.inventory import add_inventory_quantity as _add_inventory_quantity


def require_active_record(conn,table,identifier):
    return _require_active_record(conn,table,identifier)


def archive_record(table,identifier,user_id,restore=False, *, session_token):
    if table not in ('users','stores','parts'):
        raise ValueError('Unsupported archive type')
    with authenticated_write_transaction(user_id, session_token, busy_detail="Stock is busy; no changes saved. Try again") as conn:
        require_archive_admin(conn,user_id)
        if table=='users':
            require_user_management(user_id,target_user_id=identifier,conn=conn)
            if identifier==user_id and not restore:
                raise HTTPException(status_code=400,detail='Cannot archive your own account')
        row=conn.execute(f'SELECT * FROM {table} WHERE id=?',(identifier,)).fetchone()
        if not row:
            raise HTTPException(status_code=404,detail='Record not found')
        if bool(row['archived_at']) != restore:
            raise HTTPException(status_code=409,detail='Record is already active' if restore else 'Record is already archived')
        if not restore:
            require_no_pending_transfer(conn,{'users':'user','stores':'store','parts':'part'}[table],identifier)
            if table in ('parts','stores'):
                column='part_id' if table=='parts' else 'store_id'
                if conn.execute(f'SELECT 1 FROM inventory WHERE {column}=? AND quantity>0 LIMIT 1',(identifier,)).fetchone():
                    raise HTTPException(status_code=400,detail='Cannot archive a record with stock; transfer or consume it first')
            if table=='users':
                if conn.execute('SELECT 1 FROM stores WHERE assigned_user_id=? AND archived_at IS NULL LIMIT 1',(identifier,)).fetchone() or conn.execute('SELECT 1 FROM equipment WHERE assigned_user_id=? LIMIT 1',(identifier,)).fetchone():
                    raise HTTPException(status_code=400,detail='Reassign stores and equipment before archiving this user')
                conn.execute('UPDATE sessions SET is_active=0 WHERE user_id=?',(identifier,))
                conn.execute('UPDATE users SET session_token=NULL,session_expires=NULL,reset_token=NULL,reset_token_expires=NULL WHERE id=?',(identifier,))
        elif table=='stores' and row['assigned_user_id'] is not None:
            require_active_record(conn,'users',row['assigned_user_id'])
        if table=='users' and restore:
            conn.execute('UPDATE sessions SET is_active=0 WHERE user_id=?',(identifier,))
            conn.execute('UPDATE users SET session_token=NULL,session_expires=NULL,reset_token=NULL,reset_token_expires=NULL WHERE id=?',(identifier,))
        conn.execute(f'UPDATE {table} SET archived_at='+('NULL' if restore else 'CURRENT_TIMESTAMP')+' WHERE id=?',(identifier,))
        action='restore' if restore else 'archive'
        conn.execute('INSERT INTO activity_logs(user_id,username,action,resource_type,resource_id) SELECT id,name,?,?,? FROM users WHERE id=?',
                     (action,table,identifier,user_id))
        return {'success':True,'message':f'Record {"restored" if restore else "archived"}; history preserved'}


def require_user_management(user_id: int, requested_role=None, target_user_id=None, *, conn=None):
    """Protect privileged role assignment and existing superadmin accounts."""
    close = conn is None
    if close:
        conn = get_db_connection()
    try:
        actor = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        target = (conn.execute("SELECT role FROM users WHERE id = ?", (target_user_id,)).fetchone()
                  if target_user_id is not None else None)
    finally:
        if close:
            conn.close()
    if not actor or actor["role"] not in {"admin", "superadmin"}:
        raise HTTPException(status_code=403, detail="Admin access required")
    if actor["role"] != "superadmin" and (
        requested_role == "superadmin" or (target and target["role"] == "superadmin")
    ):
        raise HTTPException(status_code=403, detail="Superadmin access required")


def add_inventory_quantity(conn, store_id, part_id, quantity, work_order_id):
    return _add_inventory_quantity(conn,store_id,part_id,quantity,work_order_id)


from backend.services.stock_transactions import write_stock_transaction


@contextmanager
def stock_write_transaction():
    """Use the current application connection factory for atomic stock writes."""
    with write_stock_transaction(get_db_connection) as conn:
        yield conn

from backend.services.session_access import require_session
from backend.services.authenticated_transactions import (
    authenticated_write_transaction as _authenticated_write_transaction,
    GENERIC_BUSY_DETAIL,
)


def authenticated_write_transaction(user_id: int, session_token: str | None, *, busy_detail=GENERIC_BUSY_DETAIL):
    return _authenticated_write_transaction(get_db_connection, user_id=user_id,
        session_token=session_token, busy_detail=busy_detail)


def require_stock_access(conn, user_id, store_type, store_owner):
    return _require_stock_access(conn,user_id,store_type,store_owner)


def get_security_config() -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT setting_key, setting_value
        FROM system_settings
        WHERE setting_key IN (
            'max_login_attempts', 'lockout_duration_minutes',
            'session_duration_hours', 'remember_me_duration_days'
        )
    """)
    rows = {r["setting_key"]: int(r["setting_value"]) for r in cursor.fetchall()}
    conn.close()
    return {
        "max_login_attempts":        rows.get("max_login_attempts",        MAX_LOGIN_ATTEMPTS),
        "lockout_duration_minutes":  rows.get("lockout_duration_minutes",  LOCKOUT_DURATION_MINUTES),
        "session_duration_hours":    rows.get("session_duration_hours",    SESSION_DURATION_HOURS),
        "remember_me_duration_days": rows.get("remember_me_duration_days", REMEMBER_ME_DURATION_DAYS),
    }


def send_reset_email(email: str, token: str):
    """Send password reset email"""
    reset_link = f"{FRONTEND_URL}/reset_password.html?token={token}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Password Reset Request - Inventory System"
    msg["From"] = SMTP_USERNAME
    msg["To"] = email

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
                Or copy and paste this link into your browser:<br>
                <a href="{reset_link}">{reset_link}</a>
            </p>
            <p style="color: #666; font-size: 14px;">
                This link will expire in 1 hour.<br>
                If you didn't request this, please ignore this email.
            </p>
        </div>
      </body>
    </html>
    """

    part = MIMEText(html, "html")
    msg.attach(part)

    try:
        logger.info(f"Attempting to send password reset email to {email}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"Password reset email sent successfully to {email}")
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication failed: {e}")
        raise HTTPException(
            status_code=500,
            detail="Email configuration error. Please contact administrator.",
        )
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send reset email.")
    except Exception as e:
        logger.error(f"Unexpected error sending email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send reset email.")


# ============ LOGGING UTILITIES ============


def log_activity(
    user_id: int,
    username: str,
    action: str,
    resource_type: str = None,
    resource_id: int = None,
    details: dict = None,
    status: str = "success",
    error_message: str = None,
    ip_address: str = None,
    user_agent: str = None,
    conn=None,
):
    """Log user activity to database and audit log file"""
    if conn is not None:
        record_activity(conn, user_id=user_id, username=username, action=action,
            resource_type=resource_type, resource_id=resource_id, details=details,
            status=status, error_message=error_message, ip_address=ip_address,
            user_agent=user_agent)
        return
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        details_json = json.dumps(details) if details else None

        cursor.execute(
            """
            INSERT INTO activity_logs 
            (user_id, username, action, resource_type, resource_id, details, 
             ip_address, user_agent, status, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                user_id if user_id else None,
                username,
                action,
                resource_type,
                resource_id,
                details_json,
                ip_address,
                user_agent,
                status,
                error_message,
            ),
        )

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

        cursor.execute(
            """
            INSERT INTO system_logs (level, component, message, details)
            VALUES (?, ?, ?, ?)
        """,
            (level, component, message, details_json),
        )

        conn.commit()
        conn.close()

        # Also log to application log
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{component}] {message}")

    except Exception as e:
        error_logger.error(f"Failed to log system event: {str(e)}")


from backend.services.activity import record_activity


def log_authenticated_activity(user_id: int, session_token: str | None, **activity):
    """Best-effort read/maintenance evidence; never write with a stale session."""
    try:
        with authenticated_write_transaction(user_id, session_token) as conn:
            record_activity(conn, user_id=user_id, **activity)
    except HTTPException:
        # A completed read remains usable; expired request credentials cannot audit it.
        return
    except Exception:
        error_logger.exception('Failed to record authenticated activity')


def _record_mutation_activity(conn, user_id, action, resource_type, result, request):
    actor = conn.execute('SELECT name FROM users WHERE id=?', (user_id,)).fetchone()
    details = {k: v for k, v in result.items() if k not in {'password_hash', 'session_token', 'reset_token'}} if isinstance(result, dict) else {}
    record_activity(conn, user_id=user_id, username=actor['name'] if actor else 'Unknown',
        action=action, resource_type=resource_type,
        resource_id=result.get('id') if isinstance(result, dict) else None,
        details=details, ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get('user-agent', '')[:200] if request else None)


# ============ LOGGING DECORATOR ============


def log_endpoint(action: str, resource_type: str = None, *, transactional: bool = False):
    """Decorator to automatically log API endpoint calls"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract parameters
            user_id = kwargs.get("user_id")
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
                ip_address = request.client.host if hasattr(request, "client") else None
                user_agent = request.headers.get("user-agent", "")[:200]

            username = "Unknown"
            resource_id = None
            details = {}
            status = "success"
            error_message = None

            try:
                # Get username if user_id is available
                if user_id:
                    try:
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT name FROM users WHERE id = ?", (user_id,)
                        )
                        user = cursor.fetchone()
                        conn.close()
                        if user:
                            username = user["name"]
                    except Exception as e:
                        logger.error(f"Failed to get username: {e}")

                # Execute the endpoint function
                result = await func(*args, **kwargs)

                # Extract resource_id from result if it's a dict
                if isinstance(result, dict):
                    resource_id = result.get("id")
                    # Create a safe copy of details without sensitive data
                    details = {
                        k: v
                        for k, v in result.items()
                        if k not in ["password_hash", "session_token", "reset_token"]
                    }

                return result

            except HTTPException as e:
                status = "error"
                error_message = e.detail
                error_logger.error(
                    f"HTTPException in {func.__name__}: {e.detail}",
                    extra={"user_id": user_id, "status_code": e.status_code},
                )
                raise

            except Exception as e:
                status = "error"
                error_message = str(e)
                error_logger.exception(
                    f"Exception in {func.__name__}: {str(e)}",
                    extra={"user_id": user_id},
                )
                raise

            finally:
                # Log the activity
                if user_id and not transactional and not (status == "success" and action in STOCK_AUDIT_ACTIONS):
                    try:
                        log_authenticated_activity(
                            user_id=user_id,
                            session_token=request.cookies.get("session_token") if request else None,
                            username=username,
                            action=action,
                            resource_type=resource_type,
                            resource_id=resource_id,
                            details=details,
                            status=status,
                            error_message=error_message,
                            ip_address=ip_address,
                            user_agent=user_agent,
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
    init_db()
    log_system_event("INFO", "startup", "Application initialized")
    print("✅ Database initialized")
    logger.info("Database initialized successfully")
    yield

    # Shutdown (if needed)
    print("⏹️ Shutting down...")
    logger.info("Application shutting down")
    log_system_event("INFO", "shutdown", "Application shut down gracefully")


# Initialize FastAPI app with lifespan
app = FastAPI(title="Inventory Management API", version="1.0.0", lifespan=lifespan)

@app.exception_handler(sqlite3.IntegrityError)
async def database_integrity_error(request: Request, exc):
    if getattr(exc,'sqlite_errorcode',None) not in (sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY,sqlite3.SQLITE_CONSTRAINT_UNIQUE,sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY):
        raise exc
    return JSONResponse(status_code=409,content={'detail':'Invalid database reference or duplicate record; no changes saved'})


# rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security
security = HTTPBearer()

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)

# Serve static files - frontend
app.mount("/static", StaticFiles(directory="static"), name="static")
# -----------------------------------------------------------
# Pydantic models


# ----User Management Models----
from backend.schemas.auth import (
    UserProfileUpdate, PasswordChange, ForgotPasswordRequest, ResetPasswordRequest,
    UserLogin, UserResponse,
)


from backend.schemas.stores import (
    StoreResponse, StoreTypeResponse, CreateStoreTypeRequest, UpdateStoreTypeRequest,
    CreateStoreRequest, UpdateStoreRequest,
)








from backend.schemas.parts import PartResponse, CreatePartRequest, UpdatePartRequest


class InventoryResponse(BaseModel):
    part_id: int
    is_allocated: bool
    id: int
    store_id: int
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
    quantity: int = Field(gt=0, strict=True)
    work_order_number: Optional[str] = None


class ImportBalanceRow(BaseModel):
    part_number: str = Field(min_length=1, max_length=200)
    quantity: int = Field(ge=0, le=9007199254740991, strict=True)
    expected_quantity: Optional[int] = Field(..., ge=0, le=9007199254740991, strict=True)


class ImportBalancesRequest(BaseModel):
    store_id: int
    rows: List[ImportBalanceRow] = Field(min_length=1, max_length=1000)










class MovementResponse(BaseModel):
    transfer_status: Optional[str] = None
    completed_by_name: Optional[str] = None
    completed_at: Optional[str] = None
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
    new_quantity: int = Field(ge=0, strict=True)


class TransferConfirmationRequest(BaseModel):
    confirmed: bool = Field(strict=True)
    notes: Optional[str] = Field(default=None, max_length=1000)


class TransferStockRequest(BaseModel):
    replenishment: bool = Field(default=False, strict=True)
    inventory_id: int
    to_store_id: int
    quantity: int = Field(gt=0, strict=True)




from backend.schemas.users import UserRole, CreateUserRequest, UpdateUserRequest

from backend.schemas.work_orders import WorkOrderResponse

class StatsResponse(BaseModel):
    in_transit_quantity: int = 0
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


class ConsumeStockRequest(BaseModel):
    inventory_id: int
    quantity: int = Field(gt=0, strict=True)
    work_order_number: str
    notes: Optional[str] = None


# -----------------------------------------------------------


# Authentication dependency
async def get_current_user(session_token: str = Cookie(None)):
    """Validate and update activity within one short writer transaction."""
    with write_stock_transaction(get_db_connection, busy_detail=GENERIC_BUSY_DETAIL) as conn:
        session = require_session(conn, session_token)
        conn.execute('UPDATE sessions SET last_activity=CURRENT_TIMESTAMP WHERE id=?',
                     (session['session_id'],))
        return session['user_id']


# csrf middleware
async def verify_csrf(x_csrf_token: str = Header(None)):
    """Verify CSRF token for state-changing operations"""
    if not x_csrf_token:
        raise HTTPException(status_code=403, detail="CSRF token missing")

    if not verify_csrf_token(x_csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    return True


from backend.routes.auth import create_auth_router

app.include_router(create_auth_router(
    get_connection=lambda: get_db_connection(),
    authenticated_writer=lambda user_id, session_token: authenticated_write_transaction(user_id, session_token),
    stock_writer=lambda: stock_write_transaction(),
    current_user=get_current_user,
    csrf_dependency=verify_csrf,
    csrf_token_factory=lambda: generate_csrf_token(),
    password_hash=lambda password: hash_password(password),
    password_verify=lambda plain, hashed: verify_password(plain, hashed),
    security_config=lambda: get_security_config(),
    reset_email=lambda email, token: send_reset_email(email, token),
    activity_log=lambda **kwargs: log_activity(**kwargs),
    endpoint_log=log_endpoint,
    mutation_activity=lambda *args: _record_mutation_activity(*args),
    limiter=limiter,
    logger=logger,
    cookie_secure=lambda: settings.COOKIE_SECURE,
))


from backend.routes.stores import create_stores_router

app.include_router(create_stores_router(
    get_connection=lambda: get_db_connection(),
    authenticated_writer=lambda *args, **kwargs: authenticated_write_transaction(*args, **kwargs),
    current_user=get_current_user,
    csrf_dependency=verify_csrf,
    admin_guard=lambda *args, **kwargs: check_admin(*args, **kwargs),
    active_record_guard=lambda *args, **kwargs: require_active_record(*args, **kwargs),
    archive_admin_guard=lambda *args, **kwargs: require_archive_admin(*args, **kwargs),
    archive_service=lambda *args, **kwargs: archive_record(*args, **kwargs),
    endpoint_log=lambda *args, **kwargs: log_endpoint(*args, **kwargs),
    mutation_activity=lambda *args, **kwargs: _record_mutation_activity(*args, **kwargs),
))


from backend.routes.parts import create_parts_router

app.include_router(create_parts_router(
    get_connection=lambda: get_db_connection(),
    authenticated_writer=lambda *args, **kwargs: authenticated_write_transaction(*args, **kwargs),
    current_user=get_current_user,
    csrf_dependency=verify_csrf,
    admin_guard=lambda *args, **kwargs: check_admin(*args, **kwargs),
    archive_admin_guard=lambda *args, **kwargs: require_archive_admin(*args, **kwargs),
    archive_service=lambda *args, **kwargs: archive_record(*args, **kwargs),
    endpoint_log=lambda *args, **kwargs: log_endpoint(*args, **kwargs),
    mutation_activity=lambda *args, **kwargs: _record_mutation_activity(*args, **kwargs),
))


@app.get("/api/inventory", response_model=List[InventoryResponse])
async def get_inventory(
    user_id: int = Depends(get_current_user), request: Request = None
):
    """Get inventory with full visibility for engineers"""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT 
            i.id,
            i.store_id,
            i.part_id,
            (i.work_order_id IS NOT NULL) AS is_allocated,
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
        WHERE p.archived_at IS NULL AND s.archived_at IS NULL
        ORDER BY p.part_number, s.name
    """

    cursor.execute(query)
    inventory = cursor.fetchall()
    conn.close()

    return [dict(item) for item in inventory]


@app.post("/api/inventory/consume")
@log_endpoint(action="consume_stock", resource_type="inventory", transactional=True)
async def consume_stock(
    request_data: ConsumeStockRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Consume stock from inventory (requires work order)"""
    with authenticated_write_transaction(user_id, request.cookies.get("session_token"), busy_detail="Stock is busy; no changes saved. Try again") as conn:
        cursor = conn.cursor()

        # Get inventory item
        cursor.execute(
            """
            SELECT i.*, s.type, s.assigned_user_id, s.name as store_name,
                   p.part_number, p.description
            FROM inventory i
            JOIN stores s ON i.store_id = s.id
            JOIN parts p ON i.part_id = p.id
            WHERE i.id = ?
        """,
            (request_data.inventory_id,),
        )
        item = cursor.fetchone()

        if not item:
            raise HTTPException(status_code=404, detail="Inventory item not found")

        require_stock_access(conn, user_id, item["type"], item["assigned_user_id"])
        require_active_record(conn,"stores",item["store_id"])
        require_active_record(conn,"parts",item["part_id"])

        before = balance_snapshot(conn,item["store_id"],item["part_id"],item["work_order_id"])

        # Check sufficient quantity
        if item["quantity"] < request_data.quantity:
            raise HTTPException(
                status_code=400,
                detail=f"Insufficient quantity. Available: {item['quantity']}, Requested: {request_data.quantity}",
            )

        # Validate work order number
        if not request_data.work_order_number or not request_data.work_order_number.strip():
            raise HTTPException(status_code=400, detail="Work order number is required")

        # Get or create work order
        cursor.execute(
            "SELECT id FROM work_orders WHERE work_order_number = ?",
            (request_data.work_order_number,),
        )
        wo = cursor.fetchone()

        if wo:
            work_order_id = wo["id"]
        else:
            cursor.execute(
                """
                INSERT INTO work_orders (work_order_number, assigned_engineer_id, status)
                VALUES (?, ?, 'in_progress')
            """,
                (request_data.work_order_number, user_id),
            )
            work_order_id = cursor.lastrowid

        # Update inventory
        new_quantity = item["quantity"] - request_data.quantity

        if new_quantity == 0 and not item["min_threshold"]:
            cursor.execute(
                "DELETE FROM inventory WHERE id = ?", (request_data.inventory_id,)
            )
        else:
            cursor.execute(
                """
                UPDATE inventory
                SET quantity = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (new_quantity, request_data.inventory_id),
            )

        # Log movement
        cursor.execute(
            """
            INSERT INTO movements (
                from_store_id, part_id, quantity, movement_type,
                work_order_id, created_by, notes
            ) VALUES (?, ?, ?, 'consume', ?, ?, ?)
        """,
            (
                item["store_id"],
                item["part_id"],
                request_data.quantity,
                work_order_id,
                user_id,
                request_data.notes,
            ),
        )

        record_stock_audit(conn,user_id,"consume_stock",[change_after(conn,before)],[cursor.lastrowid],resource_id=item["id"],request=request,extra={"consumed_work_order_id":work_order_id,"consumed_work_order":request_data.work_order_number,"notes":request_data.notes})

        return {
            "success": True,
            "message": f"Consumed {request_data.quantity} x {item['part_number']} for WO #{request_data.work_order_number}",
            "remaining_quantity": new_quantity,
        }


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats(user_id: int = Depends(get_current_user), request: Request = None):
    """Get dashboard statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total unique parts
    cursor.execute("SELECT COUNT(DISTINCT part_number) FROM parts WHERE archived_at IS NULL")
    total_parts = cursor.fetchone()[0]

    # Total stores
    cursor.execute("SELECT COUNT(*) FROM stores WHERE archived_at IS NULL")
    total_stores = cursor.fetchone()[0]

    # Low stock items
    cursor.execute("SELECT COUNT(*) FROM inventory i JOIN parts p ON p.id=i.part_id JOIN stores s ON s.id=i.store_id WHERE i.min_threshold > 0 AND i.quantity < i.min_threshold AND i.work_order_id IS NULL AND p.archived_at IS NULL AND s.archived_at IS NULL")
    low_stock = cursor.fetchone()[0]

    # User's parts (stores they own)
    cursor.execute(
        """
        SELECT COUNT(DISTINCT i.part_id) 
        FROM inventory i 
        JOIN stores s ON i.store_id = s.id 
        WHERE s.assigned_user_id = ?
    """,
        (user_id,),
    )
    my_parts = cursor.fetchone()[0]

    in_transit_quantity = conn.execute("SELECT COALESCE(SUM(m.quantity),0) FROM stock_transfers t JOIN movements m ON m.id=t.movement_id WHERE t.status='in_transit'").fetchone()[0]
    conn.close()

    return {
        "in_transit_quantity": in_transit_quantity,
        "total_parts": total_parts,
        "total_stores": total_stores,
        "low_stock": low_stock,
        "my_parts": my_parts,
    }


@app.post("/api/inventory/import-balances")
@log_endpoint(action="import_stock_balances", resource_type="inventory", transactional=True)
async def import_stock_balances(
    request_data: ImportBalancesRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Set previewed unallocated stock balances as one transaction."""
    with authenticated_write_transaction(user_id, request.cookies.get('session_token'),
            busy_detail='Database busy; no balances saved. Try again') as conn:
        store = conn.execute("SELECT type,assigned_user_id FROM stores WHERE id=?",
                             (request_data.store_id,)).fetchone()
        if not store:
            raise HTTPException(status_code=404, detail="Store not found")
        require_stock_access(conn, user_id, store["type"], store["assigned_user_id"])
        require_active_record(conn,"stores",request_data.store_id)
        seen, changes = set(), []
        for row in request_data.rows:
            number = row.part_number.strip()
            if not number or number in seen:
                raise HTTPException(status_code=400, detail="Resolve duplicate part numbers before importing")
            seen.add(number)
            part = conn.execute("SELECT id FROM parts WHERE part_number=? AND archived_at IS NULL", (number,)).fetchone()
            if not part:
                raise HTTPException(status_code=400, detail=f"Part {number} not found in catalog")
            stock = conn.execute("SELECT id,quantity FROM inventory WHERE store_id=? AND part_id=? AND work_order_id IS NULL",
                                 (request_data.store_id, part["id"])).fetchall()
            if len(stock) > 1:
                raise HTTPException(status_code=409, detail=f"Existing duplicate stock for {number}; reconcile it first")
            current = stock[0]["quantity"] if stock else None
            if current != row.expected_quantity:
                raise HTTPException(status_code=409, detail=f"Stock changed for {number}. Cancel and upload again to refresh the preview")
            changes.append((row, part["id"], stock[0] if stock else None))
        audit_changes, movement_ids = [], []
        added = updated = unchanged = 0
        for row, part_id, stock in changes:
            before = balance_snapshot(conn,request_data.store_id,part_id,None)
            old = stock["quantity"] if stock else 0
            if stock:
                if old == row.quantity:
                    unchanged += 1
                    continue
                conn.execute("UPDATE inventory SET quantity=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                             (row.quantity, stock["id"]))
                updated += 1
            else:
                conn.execute("INSERT INTO inventory(store_id,part_id,quantity) VALUES(?,?,?)",
                             (request_data.store_id, part_id, row.quantity))
                added += 1
            delta = row.quantity - old
            if delta:
                conn.execute("INSERT INTO movements(to_store_id,part_id,quantity,movement_type,created_by,notes) VALUES(?,?,?,?,?,?)",
                             (request_data.store_id, part_id, abs(delta), "add" if delta > 0 else "remove",
                              user_id, f"CSV balance import: {old} -> {row.quantity}"))
                movement_ids.append(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            audit_changes.append(change_after(conn,before))
        record_stock_audit(conn,user_id,"import_stock_balances",audit_changes,movement_ids,resource_id=request_data.store_id,resource_type="store",request=request,extra={"added":added,"updated":updated,"unchanged":unchanged})
        return {"success": True, "added": added, "updated": updated, "unchanged": unchanged}


@app.post("/api/inventory/add")
@log_endpoint(action="add_stock", resource_type="inventory", transactional=True)
async def add_stock(
    request_data: AddStockRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Add stock to inventory"""
    with authenticated_write_transaction(user_id, request.cookies.get("session_token"), busy_detail="Stock is busy; no changes saved. Try again") as conn:
        cursor = conn.cursor()

        # Check if user can edit this store
        cursor.execute(
            """
            SELECT type, assigned_user_id FROM stores WHERE id = ?
        """,
            (request_data.store_id,),
        )
        store = cursor.fetchone()

        if not store:
            raise HTTPException(status_code=404, detail="Store not found")

        require_stock_access(conn, user_id, store["type"], store["assigned_user_id"])

        # Get work order ID if provided
        work_order_id = None
        if request_data.work_order_number:
            cursor.execute(
                "SELECT id FROM work_orders WHERE work_order_number = ?",
                (request_data.work_order_number,),
            )
            wo = cursor.fetchone()
            if wo:
                work_order_id = wo["id"]
            else:
                # Create new work order
                cursor.execute(
                    """
                    INSERT INTO work_orders (work_order_number, assigned_engineer_id)
                    VALUES (?, ?)
                """,
                    (request_data.work_order_number, user_id),
                )
                work_order_id = cursor.lastrowid

        before = balance_snapshot(conn,request_data.store_id,request_data.part_id,work_order_id)
        inventory_id = add_inventory_quantity(
            conn, request_data.store_id, request_data.part_id,
            request_data.quantity, work_order_id,
        )

        # Log movement
        cursor.execute(
            """
            INSERT INTO movements (to_store_id, part_id, quantity, movement_type, work_order_id, created_by)
            VALUES (?, ?, ?, 'add', ?, ?)
        """,
            (
                request_data.store_id,
                request_data.part_id,
                request_data.quantity,
                work_order_id,
                user_id,
            ),
        )

        record_stock_audit(conn,user_id,"add_stock",[change_after(conn,before)],[cursor.lastrowid],resource_id=inventory_id,request=request)
        return {
            "success": True,
            "id": inventory_id,
            "part_id": request_data.part_id,
            "quantity": request_data.quantity,
        }

@app.put("/api/inventory/update")
@log_endpoint(action="update_stock", resource_type="inventory", transactional=True)
async def update_stock(
    request_data: UpdateStockRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Update inventory quantity"""
    with authenticated_write_transaction(user_id, request.cookies.get("session_token"), busy_detail="Stock is busy; no changes saved. Try again") as conn:
        cursor = conn.cursor()

        # Get inventory item
        cursor.execute(
            """
            SELECT i.*, s.type, s.assigned_user_id, p.part_number
            FROM inventory i
            JOIN stores s ON i.store_id = s.id
            JOIN parts p ON i.part_id = p.id
            WHERE i.id = ?
        """,
            (request_data.inventory_id,),
        )
        item = cursor.fetchone()

        if not item:
            raise HTTPException(status_code=404, detail="Inventory item not found")

        require_stock_access(conn, user_id, item["type"], item["assigned_user_id"])
        require_active_record(conn,"stores",item["store_id"])
        require_active_record(conn,"parts",item["part_id"])

        before = balance_snapshot(conn,item["store_id"],item["part_id"],item["work_order_id"])
        old_quantity = item["quantity"]
        quantity_change = request_data.new_quantity - old_quantity

        # Update inventory
        cursor.execute(
            """
            UPDATE inventory
            SET quantity = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """,
            (request_data.new_quantity, request_data.inventory_id),
        )

        # Log movement
        movement_type = "add" if quantity_change > 0 else "remove"
        cursor.execute(
            """
            INSERT INTO movements (to_store_id, part_id, quantity, movement_type, work_order_id, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                item["store_id"],
                item["part_id"],
                abs(quantity_change),
                movement_type,
                item["work_order_id"],
                user_id,
            ),
        )

        record_stock_audit(conn,user_id,"update_stock",[change_after(conn,before)],[cursor.lastrowid],resource_id=item["id"],request=request)

        return {
            "success": True,
            "message": f"Updated {item['part_number']} quantity from {old_quantity} to {request_data.new_quantity}",
        }


@app.post("/api/inventory/transfer")
@log_endpoint(action="transfer_stock", resource_type="inventory", transactional=True)
async def transfer_stock(
    request_data: TransferStockRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Dispatch stock; destination stock becomes available only on receipt."""
    with authenticated_write_transaction(user_id, request.cookies.get("session_token"), busy_detail="Stock is busy; no changes saved. Try again") as conn:
        item = conn.execute("SELECT i.*,s.type,s.assigned_user_id,p.part_number FROM inventory i JOIN stores s ON s.id=i.store_id JOIN parts p ON p.id=i.part_id WHERE i.id=?",
                            (request_data.inventory_id,)).fetchone()
        if not item:
            raise HTTPException(status_code=404, detail="Source inventory item not found")
        require_stock_access(conn,user_id,item['type'],item['assigned_user_id'])
        if item['store_id']==request_data.to_store_id:
            raise HTTPException(status_code=400, detail="Source and destination stores must differ")
        if item['quantity']<request_data.quantity:
            raise HTTPException(status_code=400, detail="Insufficient quantity in source store")
        if not conn.execute('SELECT id FROM stores WHERE id=?',(request_data.to_store_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Destination store not found")
        require_active_record(conn,'stores',request_data.to_store_id)
        require_active_record(conn,'stores',item['store_id'])
        require_active_record(conn,'parts',item['part_id'])
        if request_data.replenishment:
            require_planned_dispatch(conn,user_id,item['id'],request_data.to_store_id,request_data.quantity)
        before=balance_snapshot(conn,item['store_id'],item['part_id'],item['work_order_id'])
        remaining=item['quantity']-request_data.quantity
        if remaining or item['min_threshold']:
            conn.execute('UPDATE inventory SET quantity=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(remaining,item['id']))
        else:
            conn.execute('DELETE FROM inventory WHERE id=?',(item['id'],))
        mid=conn.execute("INSERT INTO movements(from_store_id,to_store_id,part_id,quantity,movement_type,work_order_id,created_by,notes) VALUES(?,?,?,?,'transfer',?,?,?)",
                         (item['store_id'],request_data.to_store_id,item['part_id'],request_data.quantity,item['work_order_id'],user_id,'Dispatched; awaiting receipt')).lastrowid
        conn.execute('INSERT INTO stock_transfers(movement_id,source_min_threshold) VALUES(?,?)',(mid,item['min_threshold'] or 0))
        record_stock_audit(conn,user_id,'transfer_stock',[change_after(conn,before)],[mid],resource_id=item['id'],request=request,extra={'transfer_id':mid,'before_status':None,'after_status':'in_transit','to_store_id':request_data.to_store_id,'to_store_name':conn.execute('SELECT name FROM stores WHERE id=?',(request_data.to_store_id,)).fetchone()['name']})
        return {'success':True,'transfer_id':mid,'message':f"Dispatched {request_data.quantity} {item['part_number']}; awaiting receipt"}


def require_no_pending_transfer(conn, kind, identifier):
    predicates={'part':'m.part_id=?','store':'(m.from_store_id=? OR m.to_store_id=?)',
                'user':'(m.created_by=? OR s1.assigned_user_id=? OR s2.assigned_user_id=?)'}
    values=(identifier,)*(1 if kind=='part' else 2 if kind=='store' else 3)
    row=conn.execute("SELECT 1 FROM stock_transfers t JOIN movements m ON m.id=t.movement_id JOIN stores s1 ON s1.id=m.from_store_id JOIN stores s2 ON s2.id=m.to_store_id WHERE t.status='in_transit' AND "+predicates[kind]+" LIMIT 1",values).fetchone()
    if row:
        raise HTTPException(status_code=400,detail='Cannot delete a record used by an in-transit transfer. Complete the receipt or physical return first')


def transfer_permissions(actor, row, user_id):
    admin=actor and actor['role'] in ('admin','superadmin')
    receive=bool(admin or row['dest_owner']==user_id or (row['dest_owner'] is None and row['dest_type']=='central'))
    returned=bool(admin or row['created_by']==user_id or row['source_owner']==user_id)
    return receive,returned


@app.get('/api/inventory/transfers')
async def pending_transfers(user_id: int = Depends(get_current_user)):
    conn=get_db_connection()
    try:
        actor=conn.execute('SELECT role FROM users WHERE id=?',(user_id,)).fetchone()
        rows=conn.execute("""SELECT m.id,m.quantity,m.created_at,m.created_by,m.from_store_id,m.to_store_id,
            p.part_number,p.description,s1.name AS from_store_name,s2.name AS to_store_name,
            s1.assigned_user_id AS source_owner,s2.assigned_user_id AS dest_owner,s2.type AS dest_type,
            u.name AS created_by_name,wo.work_order_number AS work_order,t.status
            FROM stock_transfers t JOIN movements m ON m.id=t.movement_id
            JOIN parts p ON p.id=m.part_id JOIN stores s1 ON s1.id=m.from_store_id
            JOIN stores s2 ON s2.id=m.to_store_id JOIN users u ON u.id=m.created_by
            LEFT JOIN work_orders wo ON wo.id=m.work_order_id
            WHERE t.status='in_transit' ORDER BY m.created_at,m.id""").fetchall()
        result=[]
        for row in rows:
            item=dict(row)
            item['can_receive'],item['can_return']=transfer_permissions(actor,row,user_id)
            result.append(item)
        return result
    finally:
        conn.close()


def complete_transfer(transfer_id, data, user_id, action, request=None, *, session_token):
    if not data.confirmed:
        raise HTTPException(status_code=400,detail='Physical receipt or return must be confirmed')
    with authenticated_write_transaction(user_id, session_token, busy_detail="Stock is busy; no changes saved. Try again") as conn:
        row=conn.execute("""SELECT m.*,t.status,t.source_min_threshold,s1.assigned_user_id AS source_owner,
            s2.assigned_user_id AS dest_owner,s2.type AS dest_type
            FROM stock_transfers t JOIN movements m ON m.id=t.movement_id
            JOIN stores s1 ON s1.id=m.from_store_id JOIN stores s2 ON s2.id=m.to_store_id
            WHERE t.movement_id=?""",(transfer_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404,detail='Pending transfer not found')
        actor=conn.execute('SELECT role FROM users WHERE id=?',(user_id,)).fetchone()
        receive,returned=transfer_permissions(actor,row,user_id)
        if not (receive if action=='received' else returned):
            raise HTTPException(status_code=403,detail='Permission denied for this confirmation')
        if row['status']!='in_transit':
            raise HTTPException(status_code=409,detail='Transfer is already completed; stock was not changed')
        store_id=row['to_store_id'] if action=='received' else row['from_store_id']
        before=balance_snapshot(conn,store_id,row['part_id'],row['work_order_id'])
        inventory_id=add_inventory_quantity(conn,store_id,row['part_id'],row['quantity'],row['work_order_id'])
        if action=='returned':
            # Ordinary restocking may have recreated the row with its default 0.
            # Retain any nonzero threshold configured since dispatch.
            conn.execute('UPDATE inventory SET min_threshold=? WHERE id=? AND min_threshold=0',
                         (row['source_min_threshold'],inventory_id))
        conn.execute('UPDATE stock_transfers SET status=?,completed_by=?,completed_at=CURRENT_TIMESTAMP,completion_note=? WHERE movement_id=?',
                     (action,user_id,data.notes,transfer_id))
        if action=='returned':
            conn.execute("INSERT INTO movements(to_store_id,part_id,quantity,movement_type,work_order_id,created_by,notes) VALUES(?,?,?,'return',?,?,?)",
                         (store_id,row['part_id'],row['quantity'],row['work_order_id'],user_id,f'Physical return confirmed for transfer #{transfer_id}'))
        movement_ids=[transfer_id]
        if action=='returned': movement_ids.append(conn.execute('SELECT last_insert_rowid()').fetchone()[0])
        record_stock_audit(conn,user_id,'receive_transfer' if action=='received' else 'return_transfer',[change_after(conn,before)],movement_ids,resource_id=inventory_id,request=request,extra={'transfer_id':transfer_id,'before_status':'in_transit','after_status':action,'notes':data.notes})
        return {'success':True,'message':'Receipt confirmed; destination stock is available' if action=='received' else 'Physical return confirmed; source stock restored'}


@app.post('/api/inventory/transfers/{transfer_id}/receive')
@log_endpoint(action='receive_transfer',resource_type='inventory', transactional=True)
async def receive_transfer(transfer_id: int,data: TransferConfirmationRequest,
    user_id: int = Depends(get_current_user),csrf_valid: bool = Depends(verify_csrf),request: Request = None):
    return complete_transfer(transfer_id,data,user_id,'received',request,session_token=request.cookies.get('session_token'))


@app.post('/api/inventory/transfers/{transfer_id}/return')
@log_endpoint(action='return_transfer',resource_type='inventory', transactional=True)
async def return_transfer(transfer_id: int,data: TransferConfirmationRequest,
    user_id: int = Depends(get_current_user),csrf_valid: bool = Depends(verify_csrf),request: Request = None):
    return complete_transfer(transfer_id,data,user_id,'returned',request,session_token=request.cookies.get('session_token'))


from backend.routes.work_orders import create_work_order_router

app.include_router(create_work_order_router(
    get_connection=get_db_connection, current_user=get_current_user,
))








# User Management (Admin only)
from backend.routes.users import create_users_router

app.include_router(create_users_router(
    get_connection=lambda: get_db_connection(),
    authenticated_writer=lambda *args, **kwargs: authenticated_write_transaction(*args, **kwargs),
    current_user=get_current_user,
    csrf_dependency=verify_csrf,
    user_management_guard=lambda *args, **kwargs: require_user_management(*args, **kwargs),
    archive_admin_guard=lambda *args, **kwargs: require_archive_admin(*args, **kwargs),
    archive_service=lambda *args, **kwargs: archive_record(*args, **kwargs),
    password_hash=lambda password: hash_password(password),
    endpoint_log=lambda *args, **kwargs: log_endpoint(*args, **kwargs),
    mutation_activity=lambda *args, **kwargs: _record_mutation_activity(*args, **kwargs),
))



# -------------Logging Test Endpoint-------------
@app.get("/api/logs/test")
async def test_logging(
    user_id: int = Depends(get_current_user), request: Request = None
):
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
            log_count = cursor.fetchone()["count"]
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
            "can_view_logs": user["role"] == "admin" if user else False,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}




# Store Management



    # Bulk import stores from CSV (admin only)






# ============ STORE TYPE MANAGEMENT ============















# Parts Management



# bulk part import from CSV (admin only)








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
    request: Request = None,
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
            m.created_at,
            CASE WHEN m.movement_type='transfer' THEN COALESCE(t.status,'completed') END AS transfer_status,
            u2.name AS completed_by_name,t.completed_at
        FROM movements m
        LEFT JOIN stock_transfers t ON t.movement_id=m.id
        LEFT JOIN users u2 ON u2.id=t.completed_by
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
    request: Request = None,
):
    """Get activity logs (admin only for all logs, users can see their own)"""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM activity_logs WHERE 1=1"
    params = []

    # Non-admins can only see their own logs
    if not check_admin(user_id):
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
            log_dict.setdefault("details", None)
            log_dict.setdefault("ip_address", None)
            log_dict.setdefault("user_agent", None)
            log_dict.setdefault("error_message", None)
            result.append(log_dict)

        return result
    except Exception as e:
        error_logger.error(f"Failed to get activity logs: {e}")
        conn.close()
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve logs: {str(e)}"
        )


@app.get("/api/logs/activity/stats")
async def get_activity_stats(
    user_id: int = Depends(get_current_user),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    request: Request = None,
):
    """Get activity statistics (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if user is admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if user["role"] != "admin":
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
    cursor.execute(
        f"SELECT COUNT(*) as total FROM activity_logs WHERE 1=1 {date_filter}", params
    )
    total_activities = cursor.fetchone()["total"]

    # Activities by action
    cursor.execute(
        f"""
        SELECT action, COUNT(*) as count 
        FROM activity_logs 
        WHERE 1=1 {date_filter}
        GROUP BY action 
        ORDER BY count DESC 
        LIMIT 10
    """,
        params,
    )
    by_action = [dict(row) for row in cursor.fetchall()]

    # Activities by user (top 10)
    cursor.execute(
        f"""
        SELECT username, COUNT(*) as count 
        FROM activity_logs 
        WHERE 1=1 {date_filter}
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 10
    """,
        params,
    )
    by_user = [dict(row) for row in cursor.fetchall()]

    # Error rate
    cursor.execute(
        f"""
        SELECT 
            COUNT(CASE WHEN status = 'error' THEN 1 END) as errors,
            COUNT(CASE WHEN status = 'success' THEN 1 END) as successes
        FROM activity_logs
        WHERE 1=1 {date_filter}
    """,
        params,
    )
    error_stats = dict(cursor.fetchone())

    # Recent logins
    cursor.execute(
        f"""
        SELECT username, created_at, ip_address
        FROM activity_logs
        WHERE action = 'login' {date_filter}
        ORDER BY created_at DESC
        LIMIT 10
    """,
        params,
    )
    recent_logins = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "total_activities": total_activities,
        "by_action": by_action,
        "by_user": by_user,
        "error_rate": error_stats,
        "recent_logins": recent_logins,
    }


@app.delete("/api/logs/activity/cleanup")
async def cleanup_old_logs(
    days: int = 90,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Delete activity logs older than specified days (admin only)"""
    with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
        cursor = conn.cursor()

        # Check if user is admin
        cursor.execute("SELECT role,name FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if not user or user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")

        # Delete old logs
        cursor.execute(
            f"""
            DELETE FROM activity_logs
            WHERE action NOT IN {PROTECTED_AUDIT_SQL} AND created_at < datetime('now', '-' || ? || ' days')
        """,
            (days,),
        )

        deleted_count = cursor.rowcount


        log_activity(
            user_id=user_id,
            username=user["name"],
            action="cleanup_logs",
            details={"days": days, "deleted_count": deleted_count}, conn=conn)

        return {"success": True, "deleted_count": deleted_count, "days": days}



# equipment management routes
@app.get("/api/equipment/statistics", response_model=EquipmentStatsResponse)
@log_endpoint(action="view_equipment_stats", resource_type="equipment")
async def get_equipment_stats(
    user_id: int = Depends(get_current_user), request: Request = None
):
    """Get equipment statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get user role
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    # Total equipment
    cursor.execute("SELECT COUNT(*) as count FROM equipment WHERE status = 'active'")
    total_equipment = cursor.fetchone()["count"]

    # My equipment
    cursor.execute(
        """
        SELECT COUNT(*) as count FROM equipment 
        WHERE status = 'active' AND assigned_user_id = ?
    """,
        (user_id,),
    )
    my_equipment = cursor.fetchone()["count"]

    # Get calibration reminder days
    cursor.execute("""
        SELECT setting_value FROM system_settings 
        WHERE setting_key = 'calibration_reminder_days'
    """)
    reminder_setting = cursor.fetchone()
    reminder_days = int(reminder_setting["setting_value"]) if reminder_setting else 30

    # Equipment due soon
    from datetime import datetime, timedelta

    check_date = (datetime.now() + timedelta(days=reminder_days)).strftime("%Y-%m-%d")

    if user["role"] == "admin":
        cursor.execute(
            """
            SELECT COUNT(*) as count FROM equipment 
            WHERE status = 'active'
            AND next_calibration_date IS NOT NULL
            AND next_calibration_date <= ?
            AND next_calibration_date >= date('now')
        """,
            (check_date,),
        )
    else:
        cursor.execute(
            """
            SELECT COUNT(*) as count FROM equipment 
            WHERE status = 'active'
            AND assigned_user_id = ?
            AND next_calibration_date IS NOT NULL
            AND next_calibration_date <= ?
            AND next_calibration_date >= date('now')
        """,
            (user_id, check_date),
        )

    due_soon = cursor.fetchone()["count"]

    # Overdue equipment
    if user["role"] == "admin":
        cursor.execute("""
            SELECT COUNT(*) as count FROM equipment 
            WHERE status = 'active'
            AND next_calibration_date IS NOT NULL
            AND next_calibration_date < date('now')
        """)
    else:
        cursor.execute(
            """
            SELECT COUNT(*) as count FROM equipment 
            WHERE status = 'active'
            AND assigned_user_id = ?
            AND next_calibration_date IS NOT NULL
            AND next_calibration_date < date('now')
        """,
            (user_id,),
        )

    overdue = cursor.fetchone()["count"]

    conn.close()

    return {
        "total_equipment": total_equipment,
        "my_equipment": my_equipment,
        "due_soon": due_soon,
        "overdue": overdue,
    }


@app.get("/api/equipment", response_model=List[EquipmentResponse])
@log_endpoint(action="view_equipment", resource_type="equipment")
async def get_equipment(
    user_id: int = Depends(get_current_user),
    show_all: bool = False,
    request: Request = None,
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

    if not show_all and user["role"] != "admin":
        query += " AND e.assigned_user_id = ?"
        cursor.execute(query + " ORDER BY e.next_calibration_date", (user_id,))
    else:
        cursor.execute(query + " ORDER BY e.next_calibration_date")

    equipment = cursor.fetchall()
    conn.close()

    return [dict(eq) for eq in equipment]


@app.post("/api/equipment")
@log_endpoint(action="create_equipment", resource_type="equipment", transactional=True)
async def create_equipment(
    request_data: CreateEquipmentRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Create new equipment (admin only)"""
    with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
        cursor = conn.cursor()

        if request_data.assigned_user_id is not None:
            require_active_record(conn,"users",request_data.assigned_user_id)

        # Check if user is admin
        if not check_admin(user_id, conn):
            raise HTTPException(status_code=403, detail="Admin access required")

        # Check if serial number already exists
        cursor.execute(
            "SELECT id FROM equipment WHERE serial_number = ?",
            (request_data.serial_number,),
        )
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Serial number already exists")

        cursor.execute(
            """
            INSERT INTO equipment (
                equipment_name, make, model, serial_number, assigned_user_id,
                calibration_cert_number, calibration_authority, calibration_date,
                next_calibration_date, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                request_data.equipment_name,
                request_data.make,
                request_data.model,
                request_data.serial_number,
                request_data.assigned_user_id,
                request_data.calibration_cert_number,
                request_data.calibration_authority,
                request_data.calibration_date,
                request_data.next_calibration_date,
                request_data.notes,
            ),
        )

        equipment_id = cursor.lastrowid

        # Log history
        cursor.execute(
            """
            INSERT INTO equipment_history (equipment_id, action, to_user_id, created_by)
            VALUES (?, 'created', ?, ?)
        """,
            (equipment_id, request_data.assigned_user_id, user_id),
        )


        _result = {
            "success": True,
            "id": equipment_id,
            "message": "Equipment created successfully",
        }

        _record_mutation_activity(conn, user_id, 'create_equipment', 'equipment', _result, request)
        return _result


@app.put("/api/equipment/{equipment_id}")
@log_endpoint(action="update_equipment", resource_type="equipment", transactional=True)
async def update_equipment(
    equipment_id: int,
    request_data: UpdateEquipmentRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Update equipment (admin only)"""
    with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
        cursor = conn.cursor()

        if not check_admin(user_id, conn):
            raise HTTPException(status_code=403, detail="Admin access required")

        if request_data.assigned_user_id is not None:
            require_active_record(conn,"users",request_data.assigned_user_id)

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

        cursor.execute(f"UPDATE equipment SET {', '.join(updates)} WHERE id = ?", values)

        # Log history if assignment changed
        if (
            request_data.assigned_user_id is not None
            and request_data.assigned_user_id != equipment["assigned_user_id"]
        ):
            cursor.execute(
                """
                INSERT INTO equipment_history (equipment_id, action, from_user_id, to_user_id, created_by)
                VALUES (?, 'transferred', ?, ?, ?)
            """,
                (
                    equipment_id,
                    equipment["assigned_user_id"],
                    request_data.assigned_user_id,
                    user_id,
                ),
            )


        _result = {"success": True, "message": "Equipment updated successfully"}

        _record_mutation_activity(conn, user_id, 'update_equipment', 'equipment', _result, request)
        return _result


@app.post("/api/equipment/{equipment_id}/transfer")
@log_endpoint(action="transfer_equipment", resource_type="equipment", transactional=True)
async def transfer_equipment(
    equipment_id: int,
    request_data: TransferEquipmentRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Transfer equipment to another user"""
    with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
        cursor = conn.cursor()

        require_active_record(conn,"users",request_data.to_user_id)

        # Get equipment
        cursor.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
        equipment = cursor.fetchone()
        if not equipment:
            raise HTTPException(status_code=404, detail="Equipment not found")

        # Check permissions
        if not check_admin(user_id, conn) and equipment["assigned_user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Permission denied")

        # Update equipment
        cursor.execute(
            """
            UPDATE equipment
            SET assigned_user_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """,
            (request_data.to_user_id, equipment_id),
        )

        # Log history
        cursor.execute(
            """
            INSERT INTO equipment_history (equipment_id, action, from_user_id, to_user_id, notes, created_by)
            VALUES (?, 'transferred', ?, ?, ?, ?)
        """,
            (
                equipment_id,
                equipment["assigned_user_id"],
                request_data.to_user_id,
                request_data.notes,
                user_id,
            ),
        )


        _result = {"success": True, "message": "Equipment transferred successfully"}

        _record_mutation_activity(conn, user_id, 'transfer_equipment', 'equipment', _result, request)
        return _result


@app.post("/api/equipment/{equipment_id}/calibrate")
@log_endpoint(action="calibrate_equipment", resource_type="equipment", transactional=True)
async def update_calibration(
    equipment_id: int,
    request_data: UpdateCalibrationRequest,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Update equipment calibration"""
    with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
        cursor = conn.cursor()

        # Get equipment
        cursor.execute("SELECT * FROM equipment WHERE id = ?", (equipment_id,))
        equipment = cursor.fetchone()
        if not equipment:
            raise HTTPException(status_code=404, detail="Equipment not found")

        # Check permissions - admin or assigned user
        if not check_admin(user_id, conn) and equipment["assigned_user_id"] != user_id:
            raise HTTPException(status_code=403, detail="Permission denied")

        # Update calibration
        cursor.execute(
            """
            UPDATE equipment
            SET calibration_cert_number = ?,
                calibration_authority = ?,
                calibration_date = ?,
                next_calibration_date = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """,
            (
                request_data.calibration_cert_number,
                request_data.calibration_authority,
                request_data.calibration_date,
                request_data.next_calibration_date,
                equipment_id,
            ),
        )

        # Log history
        cursor.execute(
            """
            INSERT INTO equipment_history (
                equipment_id, action, calibration_date, notes, created_by
            ) VALUES (?, 'calibrated', ?, ?, ?)
        """,
            (equipment_id, request_data.calibration_date, request_data.notes, user_id),
        )


        _result = {"success": True, "message": "Calibration updated successfully"}

        _record_mutation_activity(conn, user_id, 'calibrate_equipment', 'equipment', _result, request)
        return _result



@app.delete("/api/equipment/{equipment_id}")
@log_endpoint(action="delete_equipment", resource_type="equipment", transactional=True)
async def delete_equipment(
    equipment_id: int,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Delete/deactivate equipment (admin only)"""
    with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
        cursor = conn.cursor()

        if not check_admin(user_id, conn):
            raise HTTPException(status_code=403, detail="Admin access required")

        # Get equipment
        cursor.execute("SELECT equipment_name FROM equipment WHERE id = ?", (equipment_id,))
        equipment = cursor.fetchone()
        if not equipment:
            raise HTTPException(status_code=404, detail="Equipment not found")

        # Soft delete
        cursor.execute(
            """
            UPDATE equipment
            SET status = 'deleted', updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """,
            (equipment_id,),
        )

        # Log history
        cursor.execute(
            """
            INSERT INTO equipment_history (equipment_id, action, created_by)
            VALUES (?, 'deleted', ?)
        """,
            (equipment_id, user_id),
        )


        _result = {
            "success": True,
            "message": f"Equipment {equipment['equipment_name']} deleted successfully",
        }

        _record_mutation_activity(conn, user_id, 'delete_equipment', 'equipment', _result, request)
        return _result



@app.get("/api/equipment/{equipment_id}/history")
@log_endpoint(action="view_equipment_history", resource_type="equipment")
async def get_equipment_history(
    equipment_id: int, user_id: int = Depends(get_current_user), request: Request = None
):
    """Get equipment history"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
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
    """,
        (equipment_id,),
    )

    history = cursor.fetchall()
    conn.close()

    return [dict(h) for h in history]


# System Settings endpoint
@app.get("/api/settings/calibration-reminder-days")
@log_endpoint(action="view_calibration_settings", resource_type="settings")
async def get_calibration_reminder_days(
    user_id: int = Depends(get_current_user), request: Request = None
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

    return {"days": int(result["setting_value"]) if result else 30}


@app.put("/api/settings/calibration-reminder-days")
@log_endpoint(action="update_calibration_settings", resource_type="settings", transactional=True)
async def update_calibration_reminder_days(
    days: int,
    user_id: int = Depends(get_current_user),
    csrf_valid: bool = Depends(verify_csrf),
    request: Request = None,
):
    """Update calibration reminder days setting (admin only)"""
    with authenticated_write_transaction(user_id, request.cookies.get('session_token')) as conn:
        if days < 1 or days > 365:
            raise HTTPException(status_code=400, detail="Days must be between 1 and 365")

        cursor = conn.cursor()

        if not check_admin(user_id, conn):
            raise HTTPException(status_code=403, detail="Admin access required")

        cursor.execute(
            """
            UPDATE system_settings
            SET setting_value = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
            WHERE setting_key = 'calibration_reminder_days'
        """,
            (str(days), user_id),
        )


        _result = {"success": True, "message": f"Calibration reminder set to {days} days"}

        _record_mutation_activity(conn, user_id, 'update_calibration_settings', 'settings', _result, request)
        return _result



@app.get("/")
async def root():
    """Serve the main application"""
    return {
        "message": "Inventory Management API",
        "docs": "/docs",
        "frontend": "/static/index.html",
    }

#-----------------------------------------------------------------------------------
# super admin routes

# ── Re-usable guard ──────────────────────────────────────────────────────────

def require_superadmin(user_id: int, conn=None):
    """Raise 403 unless the caller has role == 'superadmin'."""
    close = conn is None
    if close:
        conn = get_db_connection()
    cur = conn.cursor()
    cur.row_factory = sqlite3.Row
    try:
        row = cur.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
    finally:
        cur.close()
        if close:
            conn.close()
    if not row or row["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required")


# ── Pydantic models ──────────────────────────────────────────────────────────

from backend.schemas.superadmin import (
    SystemSettingUpdate, AccountUnlockRequest, BulkUnlockRequest, SecurityConfigUpdate,
    DatabaseQueryRequest, UserRoleUpdate, ForceLogoutRequest, SystemAnnouncementRequest,
    SuperadminPasswordReset,
)

from backend.routes.superadmin import create_superadmin_router

app.include_router(create_superadmin_router(
    get_connection=lambda: get_db_connection(),
    database_path=lambda: DATABASE,
    authenticated_writer=lambda user_id, session_token: authenticated_write_transaction(user_id, session_token),
    current_user=get_current_user,
    csrf_dependency=verify_csrf,
    superadmin_guard=lambda user_id, conn=None: require_superadmin(user_id, conn),
    password_hash=lambda password: hash_password(password),
    activity_log=lambda *args, **kwargs: log_activity(*args, **kwargs),
    authenticated_activity=lambda user_id, token, **kwargs: log_authenticated_activity(user_id, token, **kwargs),
    database_defaults=lambda: database_defaults(),
    session_validator=lambda *args, **kwargs: require_session(*args, **kwargs),
))

from replenishment import register_replenishment_routes, require_planned_dispatch

register_replenishment_routes(
    app, get_connection=get_db_connection, write_transaction=lambda uid, token: authenticated_write_transaction(uid, token, busy_detail="Stock is busy; no changes saved. Try again"),
    require_active=require_active_record, require_access=require_stock_access,
    current_user=get_current_user, verify_csrf=verify_csrf,
)

from stock_reports import register_stock_report_routes

register_stock_report_routes(
    app, get_connection=get_db_connection, current_user=get_current_user, require_active=require_active_record,
)

from stock_counts import register_stock_count_routes

register_stock_count_routes(
    app, get_connection=get_db_connection, write_transaction=lambda uid, token: authenticated_write_transaction(uid, token, busy_detail="Stock is busy; no changes saved. Try again"),
    require_active=require_active_record, require_access=require_stock_access,
    current_user=get_current_user, verify_csrf=verify_csrf, secret=SECRET_KEY,
)

if __name__ == "__main__":
    import uvicorn

    print("🎯 Starting Inventory Management API...")
    print("📊 Frontend: http://localhost:8000/static/index.html")
    print("📚 API Docs: http://localhost:8000/docs")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
