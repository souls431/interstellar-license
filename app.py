"""
Interstellar License Server - FastAPI
Products: spoofer | roblox | cs2 | viewbot
Each key is bound to ONE product + ONE HWID on redeem/activate.
"""

import os
import secrets
import string
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./interstellar_licenses.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "/Lix2252..admincheck")

PRODUCTS = {
    "spoofer": {"name": "Lix Temp Spoofer", "prefix": "LIX"},
    "roblox":  {"name": "Roblox External",  "prefix": "RBX"},
    "cs2":     {"name": "CS2 Cheat",        "prefix": "CS2"},
    "viewbot": {"name": "Viewbot",          "prefix": "VBOT"},
}

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(64), unique=True, index=True, nullable=False)
    product = Column(String(32), default="spoofer", index=True)
    hwid = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    activated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    is_revoked = Column(Boolean, default=False)
    note = Column(Text, nullable=True)
    max_resets = Column(Integer, default=3)
    reset_count = Column(Integer, default=0)


Base.metadata.create_all(bind=engine)

# Schema upgrade for existing DBs
try:
    with engine.begin() as conn:
        if "sqlite" in DATABASE_URL:
            cols = [row[1] for row in conn.exec_driver_sql("PRAGMA table_info(licenses)").fetchall()]
            if "product" not in cols:
                conn.exec_driver_sql(
                    "ALTER TABLE licenses ADD COLUMN product VARCHAR(32) DEFAULT 'spoofer'"
                )
        elif "postgresql" in DATABASE_URL:
            conn.exec_driver_sql(
                "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS product VARCHAR(32) DEFAULT 'spoofer'"
            )
except Exception:
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_admin(x_admin_secret: Optional[str] = Header(None, alias="X-Admin-Secret")):
    if not x_admin_secret or x_admin_secret != ADMIN_SECRET:
        raise HTTPException(401, "Invalid admin secret")
    return True


def normalize_key(key: str) -> str:
    return (key or "").strip().upper().replace(" ", "")


def generate_key(prefix: str) -> str:
    alphabet = string.ascii_uppercase + string.digits
    chunks = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
    return f"{prefix.upper()}-{'-'.join(chunks)}"


def product_payload(lic: License) -> dict:
    meta = PRODUCTS.get(lic.product or "spoofer", {"name": lic.product or "spoofer"})
    return {
        "id": lic.product or "spoofer",
        "name": meta.get("name", lic.product),
    }


class ActivateRequest(BaseModel):
    key: str
    hwid: str
    product: Optional[str] = None  # optional client hint; key's product always wins


class ValidateRequest(BaseModel):
    key: str
    hwid: str
    product: Optional[str] = None


class GenerateRequest(BaseModel):
    count: int = Field(1, ge=1, le=100)
    product: str = Field("spoofer", description="spoofer|roblox|cs2|viewbot")
    prefix: Optional[str] = None  # override; default from PRODUCTS
    note: Optional[str] = None
    days: Optional[int] = None  # null/0 = lifetime


class AdminAction(BaseModel):
    key: str
    note: Optional[str] = None


app = FastAPI(title="Interstellar License", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"ok": True, "service": "interstellar-license", "products": list(PRODUCTS.keys())}


@app.get("/products")
def list_products():
    return {
        "ok": True,
        "products": [
            {"id": k, "name": v["name"], "prefix": v["prefix"]}
            for k, v in PRODUCTS.items()
        ],
    }


@app.post("/activate")
def activate(req: ActivateRequest, db=Depends(get_db)):
    key = normalize_key(req.key)
    hwid = (req.hwid or "").strip()
    if not hwid or len(hwid) < 8:
        raise HTTPException(400, "Invalid HWID")

    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        raise HTTPException(404, "Key not found")
    if lic.is_revoked or not lic.is_active:
        raise HTTPException(403, "Key revoked or inactive")

    if lic.expires_at:
        exp = lic.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            raise HTTPException(403, "Key expired")

    # Optional: client asked for a product that doesn't match this key
    if req.product:
        want = req.product.strip().lower()
        if want in PRODUCTS and (lic.product or "spoofer") != want:
            raise HTTPException(
                403,
                f"Key is for product '{lic.product}', not '{want}'",
            )

    if lic.hwid and lic.hwid != hwid:
        raise HTTPException(
            403,
            "HWID mismatch — key already bound to another machine. Request reset.",
        )

    if not lic.hwid:
        lic.hwid = hwid
        lic.activated_at = datetime.now(timezone.utc)
        db.commit()

    return {
        "ok": True,
        "message": "Activated",
        "key": lic.key,
        "hwid": lic.hwid,
        "product": product_payload(lic),
        "product_id": lic.product or "spoofer",
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "lifetime": lic.expires_at is None,
    }


@app.post("/validate")
def validate(req: ValidateRequest, db=Depends(get_db)):
    key = normalize_key(req.key)
    hwid = (req.hwid or "").strip()

    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        return {"ok": False, "reason": "not_found"}
    if lic.is_revoked or not lic.is_active:
        return {"ok": False, "reason": "revoked"}
    if lic.expires_at:
        exp = lic.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            return {"ok": False, "reason": "expired"}
    if not lic.hwid:
        return {"ok": False, "reason": "not_activated", "product_id": lic.product or "spoofer"}
    if lic.hwid != hwid:
        return {"ok": False, "reason": "hwid_mismatch"}

    if req.product:
        want = req.product.strip().lower()
        if want in PRODUCTS and (lic.product or "spoofer") != want:
            return {
                "ok": False,
                "reason": "product_mismatch",
                "product_id": lic.product or "spoofer",
            }

    return {
        "ok": True,
        "key": lic.key,
        "hwid": lic.hwid,
        "product": product_payload(lic),
        "product_id": lic.product or "spoofer",
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "lifetime": lic.expires_at is None,
    }


@app.post("/admin/generate")
def admin_generate(req: GenerateRequest, _=Depends(require_admin), db=Depends(get_db)):
    product = (req.product or "spoofer").strip().lower()
    if product not in PRODUCTS:
        raise HTTPException(400, f"Unknown product. Use: {', '.join(PRODUCTS)}")

    prefix = (req.prefix or PRODUCTS[product]["prefix"]).strip().upper() or PRODUCTS[product]["prefix"]
    expires = None
    if req.days and int(req.days) > 0:
        expires = datetime.now(timezone.utc) + timedelta(days=int(req.days))

    keys = []
    for _ in range(int(req.count)):
        for _try in range(20):
            k = generate_key(prefix)
            if not db.query(License).filter(License.key == k).first():
                break
        else:
            raise HTTPException(500, "Failed to generate unique key")
        lic = License(
            key=k,
            product=product,
            expires_at=expires,
            note=req.note,
            is_active=True,
            is_revoked=False,
        )
        db.add(lic)
        keys.append(k)
    db.commit()
    return {
        "ok": True,
        "keys": keys,
        "count": len(keys),
        "product": product,
        "product_name": PRODUCTS[product]["name"],
        "prefix": prefix,
        "expires_at": expires.isoformat() if expires else None,
        "lifetime": expires is None,
    }


@app.post("/admin/reset_hwid")
def admin_reset_hwid(req: AdminAction, _=Depends(require_admin), db=Depends(get_db)):
    key = normalize_key(req.key)
    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        raise HTTPException(404, "Key not found")
    if lic.reset_count >= lic.max_resets:
        raise HTTPException(403, f"Max resets ({lic.max_resets}) reached")
    lic.hwid = None
    lic.activated_at = None
    lic.reset_count += 1
    if req.note:
        lic.note = (lic.note or "") + f" | reset: {req.note}"
    db.commit()
    return {"ok": True, "message": "HWID reset", "reset_count": lic.reset_count, "product": lic.product}


@app.post("/admin/revoke")
def admin_revoke(req: AdminAction, _=Depends(require_admin), db=Depends(get_db)):
    key = normalize_key(req.key)
    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        raise HTTPException(404, "Key not found")
    lic.is_revoked = True
    lic.is_active = False
    if req.note:
        lic.note = (lic.note or "") + f" | revoked: {req.note}"
    db.commit()
    return {"ok": True, "message": "Key revoked"}


@app.post("/admin/remove")
def admin_remove(req: AdminAction, _=Depends(require_admin), db=Depends(get_db)):
    key = normalize_key(req.key)
    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        raise HTTPException(404, "Key not found")
    db.delete(lic)
    db.commit()
    return {"ok": True, "message": "Key permanently removed"}


@app.get("/admin/list")
def admin_list(product: Optional[str] = None, _=Depends(require_admin), db=Depends(get_db)):
    q = db.query(License)
    if product:
        q = q.filter(License.product == product.strip().lower())
    rows = q.order_by(License.created_at.desc()).limit(500).all()
    return {
        "ok": True,
        "licenses": [
            {
                "key": r.key,
                "product": r.product or "spoofer",
                "product_name": PRODUCTS.get(r.product or "spoofer", {}).get("name", r.product),
                "hwid": r.hwid,
                "is_active": r.is_active,
                "is_revoked": r.is_revoked,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "activated_at": r.activated_at.isoformat() if r.activated_at else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "lifetime": r.expires_at is None,
                "reset_count": r.reset_count,
                "note": r.note,
            }
            for r in rows
        ],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
