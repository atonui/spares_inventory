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
from pydantic import BaseModel, EmailStr, Field, validator
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


from backend.config import Settings


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

from backend.schemas.inventory_writes import (
    AddStockRequest, ImportBalanceRow, ImportBalancesRequest,
    UpdateStockRequest, TransferConfirmationRequest, TransferStockRequest,
    ConsumeStockRequest,
)


from backend.schemas.inventory_reads import InventoryResponse, StatsResponse
















from backend.schemas.history import MovementResponse, ActivityLogResponse










from backend.schemas.users import UserRole, CreateUserRequest, UpdateUserRequest

from backend.schemas.work_orders import WorkOrderResponse





# calibration models
from backend.schemas.equipment import (
    EquipmentResponse, CreateEquipmentRequest, UpdateEquipmentRequest,
    TransferEquipmentRequest, UpdateCalibrationRequest, EquipmentStatsResponse,
)














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


from backend.routes.inventory_reads import create_inventory_read_router

app.include_router(create_inventory_read_router(
    get_connection=lambda: get_db_connection(),
    current_user=get_current_user,
    transfer_permission=lambda *args, **kwargs: transfer_permissions(*args, **kwargs),
))


from backend.routes.inventory_writes import create_inventory_write_router

inventory_write_router = create_inventory_write_router(
    current_user=get_current_user,
    csrf_dependency=verify_csrf,
    endpoint_log=log_endpoint,
    authenticated_writer=lambda *args, **kwargs: authenticated_write_transaction(*args, **kwargs),
    stock_access_guard=lambda *args, **kwargs: require_stock_access(*args, **kwargs),
    active_record_guard=lambda *args, **kwargs: require_active_record(*args, **kwargs),
    balance_reader=lambda *args, **kwargs: balance_snapshot(*args, **kwargs),
    inventory_adder=lambda *args, **kwargs: add_inventory_quantity(*args, **kwargs),
    stock_audit=lambda *args, **kwargs: record_stock_audit(*args, **kwargs),
    stock_change_reader=lambda *args, **kwargs: change_after(*args, **kwargs),
    planned_dispatch_guard=lambda *args, **kwargs: require_planned_dispatch(*args, **kwargs),
    transfer_completion=lambda *args, **kwargs: complete_transfer(*args, **kwargs),
)
app.include_router(inventory_write_router)
consume_stock = inventory_write_router.consume_stock
import_stock_balances = inventory_write_router.import_stock_balances
add_stock = inventory_write_router.add_stock
update_stock = inventory_write_router.update_stock
transfer_stock = inventory_write_router.transfer_stock
receive_transfer = inventory_write_router.receive_transfer
return_transfer = inventory_write_router.return_transfer


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
from backend.routes.history import create_history_router

app.include_router(create_history_router(
    get_connection=lambda: get_db_connection(),
    authenticated_writer=lambda *args, **kwargs: authenticated_write_transaction(*args, **kwargs),
    current_user=get_current_user,
    csrf_dependency=verify_csrf,
    admin_guard=lambda *args, **kwargs: check_admin(*args, **kwargs),
    activity_log=lambda *args, **kwargs: log_activity(*args, **kwargs),
    error_log=lambda *args, **kwargs: error_logger.error(*args, **kwargs),
))




# Store Management



    # Bulk import stores from CSV (admin only)






# ============ STORE TYPE MANAGEMENT ============















# Parts Management



# bulk part import from CSV (admin only)








# Movement History


# ============ LOGGING ENDPOINTS ============









# equipment management routes
from backend.routes.equipment import create_equipment_router

app.include_router(create_equipment_router(
    get_connection=lambda: get_db_connection(),
    authenticated_writer=lambda *args, **kwargs: authenticated_write_transaction(*args, **kwargs),
    current_user=get_current_user,
    csrf_dependency=verify_csrf,
    admin_guard=lambda *args, **kwargs: check_admin(*args, **kwargs),
    active_record_guard=lambda *args, **kwargs: require_active_record(*args, **kwargs),
    endpoint_log=lambda *args, **kwargs: log_endpoint(*args, **kwargs),
    mutation_activity=lambda *args, **kwargs: _record_mutation_activity(*args, **kwargs),
))


















# System Settings endpoint





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

from backend.routes.reports import create_stock_report_router

app.include_router(create_stock_report_router(
    get_connection=lambda: get_db_connection(),
    current_user=get_current_user,
    require_active=lambda *args, **kwargs: require_active_record(*args, **kwargs),
))

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
