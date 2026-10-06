from fastapi import HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Cookie
from fastapi import Header
from fastapi.responses import FileResponse

from contextlib import asynccontextmanager, contextmanager, closing
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Literal
import sqlite3
import hashlib
from datetime import datetime
import os
import csv
import io

from jose import JWTError, jwt


import shutil
from stock_audit import balance_snapshot, change_after, record_stock_audit, STOCK_AUDIT_ACTIONS, PROTECTED_AUDIT_SQL

from backend.config import Settings
from backend.app_bootstrap import create_inventory_app, database_integrity_error
from backend.logging_config import setup_logging
from backend.security import (
    create_access_token as _create_access_token,
    create_csrf_helpers,
    CsrfHelpers,
    require_csrf_token,
    hash_password as _hash_password,
    verify_password as _verify_password,
)
from backend.app_activity import (
    create_endpoint_logger,
    log_activity as _log_activity,
    log_authenticated_activity as _log_authenticated_activity,
    log_system_event as _log_system_event,
    record_mutation_activity as _record_mutation_activity_service,
)
from backend.email_service import send_password_reset_email


configured_loggers = setup_logging()
logger = configured_loggers.logger
audit_logger = configured_loggers.audit_logger
error_logger = configured_loggers.error_logger

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
csrf_helpers = create_csrf_helpers(CSRF_SECRET)
csrf_serializer = csrf_helpers.serializer


# Database setup
from backend.app_database import (
    initialize_application_database,
    make_database_defaults,
    open_application_database,
)


def database_defaults():
    return make_database_defaults(
        max_login_attempts=MAX_LOGIN_ATTEMPTS,
        lockout_duration_minutes=LOCKOUT_DURATION_MINUTES,
        session_duration_hours=SESSION_DURATION_HOURS,
        remember_me_duration_days=REMEMBER_ME_DURATION_DAYS,
    )


def init_db():
    """Apply explicit migrations and preserve configured bootstrap defaults."""
    initialize_application_database(DATABASE, defaults=database_defaults())


# ============ CSRF UTILITIES ============
def generate_csrf_token() -> str:
    """Generate CSRF token"""
    return CsrfHelpers(csrf_serializer).generate_csrf_token()


def verify_csrf_token(token: str, max_age: int = 3600) -> bool:
    """Verify CSRF token (valid for 1 hour by default)"""
    return CsrfHelpers(csrf_serializer).verify_csrf_token(token, max_age=max_age)


# ============ AUTHENTICATION UTILITIES ============
def hash_password(password: str) -> str:
    """Hash password for storage"""
    return _hash_password(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash"""
    return _verify_password(plain_password, hashed_password)


def create_access_token(data: dict):
    """Create JWT token"""
    return _create_access_token(data, SECRET_KEY)


def get_db_connection():
    """Open a configured connection using the application database path."""
    return open_application_database(DATABASE)


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
from backend.services.session_authentication import authenticate_session
from backend.services.security_settings import load_security_settings
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
    return load_security_settings(get_db_connection, defaults={
        "max_login_attempts": MAX_LOGIN_ATTEMPTS,
        "lockout_duration_minutes": LOCKOUT_DURATION_MINUTES,
        "session_duration_hours": SESSION_DURATION_HOURS,
        "remember_me_duration_days": REMEMBER_ME_DURATION_DAYS,
    })


def send_reset_email(email: str, token: str):
    """Send password reset email"""
    return send_password_reset_email(
        email=email,
        token=token,
        frontend_url=FRONTEND_URL,
        smtp_server=SMTP_SERVER,
        smtp_port=SMTP_PORT,
        smtp_username=SMTP_USERNAME,
        smtp_password=SMTP_PASSWORD,
        logger=logger,
    )


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
    return _log_activity(
        get_db_connection,
        audit_logger,
        error_logger,
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        status=status,
        error_message=error_message,
        ip_address=ip_address,
        user_agent=user_agent,
        conn=conn,
    )


def log_system_event(level: str, component: str, message: str, details: dict = None):
    """Log system events to database"""
    return _log_system_event(get_db_connection, logger, error_logger, level, component, message, details)


def log_authenticated_activity(user_id: int, session_token: str | None, **activity):
    """Best-effort read/maintenance evidence; never write with a stale session."""
    return _log_authenticated_activity(authenticated_write_transaction, error_logger,
        user_id, session_token, **activity)


def _record_mutation_activity(conn, user_id, action, resource_type, result, request):
    return _record_mutation_activity_service(conn, user_id, action, resource_type, result, request)


# ============ LOGGING DECORATOR ============


def log_endpoint(action: str, resource_type: str = None, *, transactional: bool = False):
    return create_endpoint_logger(
        get_connection_provider=lambda: get_db_connection,
        authenticated_activity_provider=lambda: log_authenticated_activity,
        logger_provider=lambda: logger,
        error_logger_provider=lambda: error_logger,
        stock_audit_actions_provider=lambda: STOCK_AUDIT_ACTIONS,
    )(action, resource_type, transactional=transactional)


# Lifespan event handler
@asynccontextmanager
async def lifespan(app):
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


# Initialize FastAPI app with shared bootstrap wiring
app, limiter = create_inventory_app(
    lifespan=lifespan,
    cors_allowed_origins=settings.CORS_ALLOWED_ORIGINS,
)

# Security
security = HTTPBearer()

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
    return authenticate_session(
        session_token, get_db_connection,
        session_validator=require_session,
        transaction_factory=write_stock_transaction,
        busy_detail=GENERIC_BUSY_DETAIL,
    )


# csrf middleware
async def verify_csrf(x_csrf_token: str = Header(None)):
    """Verify CSRF token for state-changing operations"""
    return require_csrf_token(x_csrf_token, verify_csrf_token)


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
