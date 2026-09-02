"""
Interstellar License Server - FastAPI backend for Render.com
Endpoints:
  POST /activate   - activate key + bind HWID
  POST /validate   - check key + HWID
  POST /reset_hwid - reset HWID binding (admin)
  POST /revoke     - revoke key
  POST /remove     - permanently delete key
  GET  /health
Admin endpoints protected by ADMIN_SECRET.
"""

import os
import hashlib
import secrets
import string
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import IntegrityError

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./interstellar_licenses.db")
# Render Postgres uses postgres:// — SQLAlchemy wants postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "change-me-interstellar-admin-secret-2026")
APP_NAME = "Interstellar"

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(64), unique=True, index=True, nullable=False)
    hwid = Column(String(128), nullable=True)          # bound hardware id
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    activated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)       # null = lifetime
    is_active = Column(Boolean, default=True)
    is_revoked = Column(Boolean, default=False)
    note = Column(Text, nullable=True)
    max_resets = Column(Integer, default=3)
    reset_count = Column(Integer, default=0)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class ActivateRequest(BaseModel):
    key: str
    hwid: str


class ValidateRequest(BaseModel):
    key: str
    hwid: str


class KeyOnly(BaseModel):
    key: str


class GenerateRequest(BaseModel):
    count: int = Field(1, ge=1, le=100)
    prefix: str = "INTL"
    note: Optional[str] = None
    days: Optional[int] = None  # null = lifetime


class AdminAction(BaseModel):
    key: str
    note: Optional[str] = None


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Interstellar License API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_admin(x_admin_secret: str = Header(None)):
    if not x_admin_secret or x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin secret")
    return True


def normalize_key(k: str) -> str:
    return k.strip().upper().replace(" ", "")


def generate_key(prefix: str = "INTL") -> str:
    parts = [
        prefix,
        "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4)),
        "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4)),
        "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4)),
        "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4)),
    ]
    return "-".join(parts)


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "app": APP_NAME, "time": datetime.now(timezone.utc).isoformat()}


@app.post("/activate")
def activate(req: ActivateRequest, db=Depends(get_db)):
    key = normalize_key(req.key)
    hwid = req.hwid.strip()
    if not hwid or len(hwid) < 8:
        raise HTTPException(400, "Invalid HWID")

    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        raise HTTPException(404, "Key not found")
    if lic.is_revoked or not lic.is_active:
        raise HTTPException(403, "Key revoked or inactive")

    if lic.expires_at and lic.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(403, "Key expired")

    if lic.hwid and lic.hwid != hwid:
        raise HTTPException(
            403,
            "HWID mismatch — key is locked to another device. Admin must RESET HWID before this key can be used here."
        )

    # Bind
    if not lic.hwid:
        lic.hwid = hwid
        lic.activated_at = datetime.now(timezone.utc)
        db.commit()

    return {
        "ok": True,
        "message": "Activated",
        "key": lic.key,
        "hwid": lic.hwid,
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "lifetime": lic.expires_at is None,
    }


@app.post("/validate")
def validate(req: ValidateRequest, db=Depends(get_db)):
    key = normalize_key(req.key)
    hwid = req.hwid.strip()

    lic = db.query(License).filter(License.key == key).first()
    if not lic:
        return {"ok": False, "reason": "not_found"}
    if lic.is_revoked or not lic.is_active:
        return {"ok": False, "reason": "revoked"}
    if lic.expires_at and lic.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return {"ok": False, "reason": "expired"}
    if not lic.hwid:
        return {"ok": False, "reason": "not_activated"}
    if lic.hwid != hwid:
        return {"ok": False, "reason": "hwid_mismatch"}

    return {
        "ok": True,
        "key": lic.key,
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "lifetime": lic.expires_at is None,
    }


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------
@app.post("/admin/generate")
def admin_generate(req: GenerateRequest, _=Depends(require_admin), db=Depends(get_db)):
    keys = []
    expires = None
    if req.days:
        from datetime import timedelta
        expires = datetime.now(timezone.utc) + timedelta(days=req.days)

    for _ in range(req.count):
        for attempt in range(20):
            k = generate_key(req.prefix)
            if not db.query(License).filter(License.key == k).first():
                lic = License(key=k, note=req.note, expires_at=expires)
                db.add(lic)
                keys.append(k)
                break
        else:
            raise HTTPException(500, "Failed to generate unique key")
    db.commit()
    return {"ok": True, "keys": keys, "count": len(keys)}


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
    return {"ok": True, "message": "HWID reset", "reset_count": lic.reset_count}


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
def admin_list(_=Depends(require_admin), db=Depends(get_db)):
    rows = db.query(License).order_by(License.created_at.desc()).limit(500).all()
    return {
        "ok": True,
        "licenses": [
            {
                "key": r.key,
                "hwid": r.hwid,
                "is_active": r.is_active,
                "is_revoked": r.is_revoked,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "activated_at": r.activated_at.isoformat() if r.activated_at else None,
                "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                "reset_count": r.reset_count,
                "note": r.note,
            }
            for r in rows
        ],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
