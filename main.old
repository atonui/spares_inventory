# main.py
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
import os

# Database setup
DATABASE = "inventory.db"

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
            work_order_id INTEGER,
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
    
    # Insert sample data
    insert_sample_data(cursor)
    
    conn.commit()
    conn.close()

def insert_sample_data(cursor):
    """Insert sample data for testing"""
    
    # Sample users
    users_data = [
        ('john@company.com', 'John Engineer', hash_password('password123'), 'engineer', 'North Region'),
        ('admin@company.com', 'System Admin', hash_password('admin123'), 'admin', 'All Regions'),
        ('mike@company.com', 'Mike Engineer', hash_password('password123'), 'engineer', 'South Region'),
        ('manager@company.com', 'Regional Manager', hash_password('manager123'), 'manager', 'North Region')
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO users (email, name, password_hash, role, territory)
        VALUES (?, ?, ?, ?, ?)
    ''', users_data)
    
    # Sample stores
    stores_data = [
        ('Central Warehouse', 'central', 'Main Office', None),
        ('Site Alpha', 'customer_site', 'Customer Location A', 1),
        ('Site Beta', 'customer_site', 'Customer Location B', 3),
        ('John\'s Personal', 'engineer', 'John\'s Inventory', 1),
        ('Mike\'s Personal', 'engineer', 'Mike\'s Inventory', 3),
        ('FE Consignment', 'fe_consignment', 'Customer Owned Stock', None)
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO stores (name, type, location, assigned_user_id)
        VALUES (?, ?, ?, ?)
    ''', stores_data)
    
    # Sample parts
    parts_data = [
        ('BRG-001', 'Main Bearing Assembly', 'Mechanical', 150.00),
        ('SEAL-045', 'Oil Seal 45mm', 'Seals', 25.00),
        ('MTR-500', 'Drive Motor 500W', 'Electrical', 450.00),
        ('BELT-V100', 'V-Belt 100cm', 'Mechanical', 35.00),
        ('FILT-AIR', 'Air Filter Element', 'Filters', 15.00)
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO parts (part_number, description, category, unit_cost)
        VALUES (?, ?, ?, ?)
    ''', parts_data)
    
    # Sample work orders
    wo_data = [
        ('WO-2024-001', 'Customer A', 'Bearing replacement', 'open', 1),
        ('WO-2024-002', 'Customer B', 'Seal maintenance', 'open', 1),
        ('WO-2024-003', 'Customer C', 'Motor repair', 'closed', 3)
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO work_orders (work_order_number, customer_name, description, status, assigned_engineer_id)
        VALUES (?, ?, ?, ?, ?)
    ''', wo_data)
    
    # Sample inventory
    inventory_data = [
        (1, 1, 15, 5, None),  # Central warehouse original stock
        (1, 2, 25, 5, None),  # Central warehouse original stock
        (1, 3, 8, 3, None),   # Central warehouse original stock
        (2, 1, 2, 2, 1),      # Site Alpha - WO stock
        (4, 2, 3, 1, 2),      # John's personal - WO stock
        (5, 2, 1, 1, 3),      # Mike's personal - WO stock
        (3, 2, 1, 2, None),   # Site Beta - original stock
        (6, 1, 5, 2, 1)       # FE Consignment
    ]
    
    cursor.executemany('''
        INSERT OR IGNORE INTO inventory (store_id, part_id, quantity, min_threshold, work_order_id)
        VALUES (?, ?, ?, ?, ?)
    ''', inventory_data)

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

# Lifespan event handler (modern FastAPI way)
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Starting up...")
    init_db()
    print("✅ Database initialized")
    yield
    # Shutdown (if needed)
    print("⏹️ Shutting down...")

# Initialize FastAPI app with lifespan
app = FastAPI(
    title="Inventory Management API", 
    version="1.0.0",
    lifespan=lifespan
)

# Security
security = HTTPBearer()
SECRET_KEY = "your-secret-key-change-in-production"

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

class TransferStockRequest(BaseModel):
    inventory_id: int
    to_store_id: int
    quantity: int

class StatsResponse(BaseModel):
    total_parts: int
    total_stores: int
    low_stock: int
    my_parts: int

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Routes
@app.get("/")
async def root():
    """Serve the main application"""
    return {"message": "Inventory Management API", "docs": "/docs", "frontend": "/static/index.html"}

@app.post("/api/auth/login")
async def login(user_login: UserLogin):
    """User login"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, email, name, role, territory, password_hash FROM users WHERE email = ?",
        (user_login.email,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if not user or user['password_hash'] != hash_password(user_login.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token({"user_id": user['id']})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user['id'],
            "email": user['email'],
            "name": user['name'],
            "role": user['role'],
            "territory": user['territory']
        }
    }

@app.get("/api/me", response_model=UserResponse)
async def get_current_user_info(user_id: int = Depends(get_current_user)):
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
async def get_stores(user_id: int = Depends(get_current_user)):
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
async def get_parts(user_id: int = Depends(get_current_user)):
    """Get all parts"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, part_number, description, category, unit_cost FROM parts")
    parts = cursor.fetchall()
    conn.close()
    
    return [dict(part) for part in parts]

@app.get("/api/inventory", response_model=List[InventoryResponse])
async def get_inventory(user_id: int = Depends(get_current_user)):
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
async def get_stats(user_id: int = Depends(get_current_user)):
    """Get dashboard statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total unique parts
    cursor.execute("SELECT COUNT(DISTINCT part_id) FROM inventory")
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
async def add_stock(request: AddStockRequest, user_id: int = Depends(get_current_user)):
    """Add stock to inventory"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user can edit this store
    cursor.execute("""
        SELECT type, assigned_user_id FROM stores WHERE id = ?
    """, (request.store_id,))
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
    if request.work_order_number:
        cursor.execute(
            "SELECT id FROM work_orders WHERE work_order_number = ?",
            (request.work_order_number,)
        )
        wo = cursor.fetchone()
        if wo:
            work_order_id = wo['id']
        else:
            # Create new work order
            cursor.execute("""
                INSERT INTO work_orders (work_order_number, assigned_engineer_id)
                VALUES (?, ?)
            """, (request.work_order_number, user_id))
            work_order_id = cursor.lastrowid
    
    # Add or update inventory
    cursor.execute("""
        INSERT INTO inventory (store_id, part_id, quantity, work_order_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(store_id, part_id, work_order_id) 
        DO UPDATE SET quantity = quantity + ?
    """, (request.store_id, request.part_id, request.quantity, work_order_id, request.quantity))
    
    # Log movement
    cursor.execute("""
        INSERT INTO movements (to_store_id, part_id, quantity, movement_type, work_order_id, created_by)
        VALUES (?, ?, ?, 'add', ?, ?)
    """, (request.store_id, request.part_id, request.quantity, work_order_id, user_id))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Stock added successfully"}

if __name__ == "__main__":
    import uvicorn
    print("🎯 Starting Inventory Management API...")
    print("📊 Frontend: http://localhost:8000/static/index.html")
    print("📚 API Docs: http://localhost:8000/docs")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)