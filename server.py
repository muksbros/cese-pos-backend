from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import uuid
import bcrypt
import jwt
import httpx
import base64
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal
from datetime import datetime, timezone, timedelta

# ----------------------------------------------------------------------------
# Configurations (Pulled from Render Environment Variables)
# ----------------------------------------------------------------------------
MONGO_URL = os.environ.get("MONGO_URL")
DB_NAME = os.environ.get("DB_NAME", "cese_pos")
JWT_SECRET = os.environ.get("JWT_SECRET", "cese_senior_tier_secret_2025")
XENDIT_KEY = os.environ.get("XENDIT_SECRET_KEY") 
ADMIN_KEY = os.environ.get("ADMIN_SECRET_KEY", "admin123")
JWT_ALGO = "HS256"
JWT_TTL_DAYS = 14
FREE_TIER_PRODUCT_LIMIT = 20

# Database Initialization
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="CESE POS API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

# ----------------------------------------------------------------------------
# ADMIN PORTAL (Web UI for you to approve merchants)
# ----------------------------------------------------------------------------
@app.get("/admin/portal", response_class=HTMLResponse)
async def admin_portal(key: str = ""):
    if key != ADMIN_KEY: return "<h1>Access Denied: Invalid Admin Key</h1>"
    
    users = await db.users.find().to_list(100)
    subs = await db.premium_submissions.find({"status": "PENDING"}).to_list(100)
    
    html = f"""
    <html><head><title>CESE Admin</title><style>
    body {{ font-family: sans-serif; padding: 40px; background: #f0f2f5; }}
    table {{ width: 100%; border-collapse: collapse; background: white; margin-bottom: 40px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
    th, td {{ padding: 15px; border: 1px solid #ddd; text-align: left; }}
    th {{ background: #003366; color: white; text-transform: uppercase; font-size: 12px; }}
    .btn {{ background: #E6AC40; padding: 10px 15px; border: none; cursor: pointer; font-weight: bold; border-radius: 4px; }}
    .badge {{ padding: 5px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
    .premium {{ background: #D1FAE5; color: #047857; }}
    .free {{ background: #F3F4F6; color: #4B5563; }}
    </style></head><body>
    <h1 style="color: #003366;">CESE POS - System Administration</h1>
    
    <h3>Pending Premium Requests (Manual Maya Validation)</h3>
    <table><tr><th>Merchant Store</th><th>Email Address</th><th>Maya Ref ID</th><th>Command</th></tr>
    """
    if not subs: html += "<tr><td colspan='4' style='text-align:center;'>No pending requests</td></tr>"
    for s in subs:
        html += f"<tr><td>{s['store_name']}</td><td>{s['email']}</td><td><code>{s['reference_id']}</code></td>"
        html += f"<td><form method='POST' action='/admin/approve?key={ADMIN_KEY}&user_id={s['user_id']}'><button class='btn'>ACTIVATE PREMIUM</button></form></td></tr>"
    
    html += "</table><h3>Registered Merchants</h3><table><tr><th>Store Name</th><th>Login Email</th><th>Subscription</th></tr>"
    for u in users:
        p_class = "premium" if u.get("is_premium") else "free"
        p_text = "PREMIUM TIER" if u.get("is_premium") else "FREE TIER"
        html += f"<tr><td><b>{u['store_name']}</b></td><td>{u['email']}</td><td><span class='badge {p_class}'>{p_text}</span></td></tr>"
    
    html += "</table></body></html>"
    return html

@app.post("/admin/approve")
async def admin_approve(user_id: str, key: str = ""):
    if key != ADMIN_KEY: raise HTTPException(status_code=401)
    await db.users.update_one({"id": user_id}, {"$set": {"is_premium": True}})
    await db.premium_submissions.update_many({"user_id": user_id}, {"$set": {"status": "APPROVED"}})
    return HTMLResponse(f"<h1>Activation Successful</h1><p>Merchant {user_id} upgraded.</p><a href='/admin/portal?key={ADMIN_KEY}'>Return to Portal</a>")

# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    store_name: str = Field(min_length=1)

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class ProductIn(BaseModel):
    name: str
    sku: Optional[str] = ""
    retail_price: float = Field(ge=0)
    wholesale_cost: float = Field(ge=0, default=0)
    stock: int = Field(ge=0, default=0)
    low_stock_threshold: int = Field(ge=0, default=5)
    image_base64: Optional[str] = ""

class Product(ProductIn):
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime

class CartItem(BaseModel):
    product_id: str
    name: str
    unit_price: float
    quantity: int = Field(ge=1)

class TransactionIn(BaseModel):
    items: List[CartItem]
    total: float
    payment_method: Literal["cash", "qrph"]
    amount_tendered: Optional[float] = None
    change: Optional[float] = 0

class Transaction(TransactionIn):
    id: str
    tenant_id: str
    created_at: datetime

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try: return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except: return False

def create_token(user_id: str, tenant_id: str, email: str) -> str:
    payload = {"sub": user_id, "tenant_id": tenant_id, "email": email, "iat": datetime.now(timezone.utc), "exp": datetime.now(timezone.utc) + timedelta(days=JWT_TTL_DAYS)}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

async def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not creds: raise HTTPException(status_code=401, detail="Missing auth token")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGO])
    except:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user: raise HTTPException(status_code=401, detail="User not found")
    return user

def user_to_public(user_doc: dict) -> dict:
    return {"id": user_doc["id"], "email": user_doc["email"], "store_name": user_doc["store_name"], "tenant_id": user_doc["tenant_id"], "is_premium": user_doc.get("is_premium", False), "created_at": user_doc["created_at"]}

# ----------------------------------------------------------------------------
# API Endpoints
# ----------------------------------------------------------------------------
@api_router.post("/auth/register", response_model=TokenOut)
async def register(payload: RegisterIn):
    existing = await db.users.find_one({"email": payload.email.lower()})
    if existing: raise HTTPException(status_code=400, detail="Email already registered")
    u_id, t_id = str(uuid.uuid4()), str(uuid.uuid4())
    user_doc = {"id": u_id, "tenant_id": t_id, "email": payload.email.lower(), "store_name": payload.store_name, "password_hash": hash_password(payload.password), "is_premium": False, "created_at": datetime.now(timezone.utc)}
    await db.users.insert_one(user_doc)
    return {"access_token": create_token(u_id, t_id, payload.email.lower()), "token_type": "bearer", "user": user_to_public(user_doc)}

@api_router.post("/auth/login", response_model=TokenOut)
async def login(payload: LoginIn):
    user = await db.users.find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_token(user["id"], user["tenant_id"], user["email"]), "token_type": "bearer", "user": user_to_public(user)}

@api_router.get("/auth/me")
async def me(current_user: dict = Depends(get_current_user)):
    return user_to_public(current_user)

@api_router.get("/products", response_model=List[Product])
async def list_products(current_user: dict = Depends(get_current_user)):
    return await db.products.find({"tenant_id": current_user["tenant_id"]}, {"_id": 0}).to_list(1000)

@api_router.post("/products", response_model=Product)
async def create_product(payload: ProductIn, current_user: dict = Depends(get_current_user)):
    if not current_user.get("is_premium", False):
        count = await db.products.count_documents({"tenant_id": current_user["tenant_id"]})
        if count >= FREE_TIER_PRODUCT_LIMIT:
            raise HTTPException(status_code=403, detail="PREMIUM_REQUIRED")
    doc = {**payload.model_dump(), "id": str(uuid.uuid4()), "tenant_id": current_user["tenant_id"], "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)}
    await db.products.insert_one(doc)
    doc.pop("_id", None)
    return doc

@api_router.put("/products/{product_id}", response_model=Product)
async def update_product(product_id: str, payload: ProductIn, current_user: dict = Depends(get_current_user)):
    updates = {**payload.model_dump(), "updated_at": datetime.now(timezone.utc)}
    res = await db.products.find_one_and_update({"id": product_id, "tenant_id": current_user["tenant_id"]}, {"$set": updates}, return_document=True, projection={"_id": 0})
    if not res: raise HTTPException(status_code=404, detail="Product not found")
    return res

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, current_user: dict = Depends(get_current_user)):
    res = await db.products.delete_one({"id": product_id, "tenant_id": current_user["tenant_id"]})
    if res.deleted_count == 0: raise HTTPException(status_code=404, detail="Product not found")
    return {"ok": True}

@api_router.post("/transactions", response_model=Transaction)
async def create_transaction(payload: TransactionIn, current_user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    doc = {**payload.model_dump(), "id": str(uuid.uuid4()), "tenant_id": current_user["tenant_id"], "created_at": now}
    await db.transactions.insert_one(doc)
    for item in payload.items:
        await db.products.update_one({"id": item.product_id, "tenant_id": current_user["tenant_id"]}, {"$inc": {"stock": -item.quantity}, "$set": {"updated_at": now}})
    doc.pop("_id", None)
    return doc

@api_router.get("/transactions", response_model=List[Transaction])
async def list_transactions(current_user: dict = Depends(get_current_user)):
    return await db.transactions.find({"tenant_id": current_user["tenant_id"]}, {"_id": 0}).sort("created_at", -1).to_list(500)

@api_router.get("/stats/summary")
async def stats_summary(current_user: dict = Depends(get_current_user)):
    t_id = current_user["tenant_id"]
    p_count = await db.products.count_documents({"tenant_id": t_id})
    low = await db.products.find({"tenant_id": t_id, "$expr": {"$lte": ["$stock", "$low_stock_threshold"]}}, {"_id": 0, "id": 1, "name": 1, "stock": 1, "low_stock_threshold": 1}).to_list(50)
    now = datetime.now(timezone.utc)
    today_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    pipeline = [{"$match": {"tenant_id": t_id, "created_at": {"$gte": today_start}}}, {"$group": {"_id": None, "total": {"$sum": "$total"}, "count": {"$sum": 1}}}]
    rows = await db.transactions.aggregate(pipeline).to_list(1)
    t_total, t_count = (rows[0]["total"], rows[0]["count"]) if rows else (0.0, 0)
    return {"today_total": t_total, "today_count": t_count, "product_count": p_count, "free_tier_limit": FREE_TIER_PRODUCT_LIMIT, "low_stock_items": low}

# --- Payments ---
@api_router.post("/xendit/qr")
async def xendit_create_qr(payload: dict, current_user: dict = Depends(get_current_user)):
    auth_str = base64.b64encode(f"{XENDIT_KEY}:".encode()).decode()
    headers = {"Authorization": f"Basic {auth_str}", "Content-Type": "application/json"}
    x_payload = {"reference_id": payload["order_id"], "type": "DYNAMIC", "currency": "PHP", "amount": payload["amount"]}
    async with httpx.AsyncClient() as client:
        res = await client.post("https://api.xendit.co/qr_codes", json=x_payload, headers=headers)
        if res.status_code >= 400: raise HTTPException(status_code=res.status_code, detail=res.text)
        data = res.json()
        await db.xendit_qrs.insert_one({"order_id": payload["order_id"], "status": "PENDING", "created_at": datetime.now(timezone.utc)})
        return {"order_id": payload["order_id"], "qr_string": data["qr_string"], "status": "PENDING"}

@api_router.get("/xendit/qr/{order_id}")
async def xendit_qr_status(order_id: str):
    res = await db.xendit_qrs.find_one({"order_id": order_id}, {"_id": 0})
    return res or {"status": "NOT_FOUND"}

@api_router.post("/xendit/qr/{order_id}/mock-pay")
async def xendit_mock_pay(order_id: str):
    await db.xendit_qrs.update_one({"order_id": order_id}, {"$set": {"status": "PAID"}})
    return {"status": "PAID"}

# --- Premium Submissions ---
@api_router.post("/premium/submit-reference")
async def submit_premium(payload: dict, current_user: dict = Depends(get_current_user)):
    sub = {"user_id": current_user["id"], "store_name": current_user["store_name"], "email": current_user["email"], "reference_id": payload.get("maya_reference_id"), "status": "PENDING", "created_at": datetime.now(timezone.utc)}
    await db.premium_submissions.insert_one(sub)
    return {"ok": True}

@api_router.post("/premium/activate")
async def activate_premium(current_user: dict = Depends(get_current_user)):
    # FOR DEMO: Instant upgrade
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"is_premium": True}})
    return {"ok": True}

@app.get("/")
async def root(): return {"service": "CESE CLOUD API", "status": "active"}

app.include_router(api_router)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
