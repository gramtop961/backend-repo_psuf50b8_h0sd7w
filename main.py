import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
from database import db, create_document
from schemas import Account
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"

            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


# ----------------------
# Auth Endpoints (Simple)
# ----------------------
class SignupPayload(BaseModel):
    name: str
    email: EmailStr
    password: str
    avatar_url: Optional[str] = None


class LoginPayload(BaseModel):
    name: str
    password: str


@app.post("/auth/signup")
def signup(payload: SignupPayload):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    name = payload.name.strip()
    email = payload.email.lower().strip()

    # Uniqueness: name OR email must not already exist
    existing = db["account"].find_one({"$or": [{"email": email}, {"name": name}]})
    if existing:
        raise HTTPException(status_code=400, detail="Account with this email or name already exists")

    password_hash = pwd_context.hash(payload.password)
    account = Account(
        name=name,
        email=email,
        password_hash=password_hash,
        avatar_url=payload.avatar_url,
        onboarded=False,
    )
    inserted_id = create_document("account", account)

    return {
        "id": inserted_id,
        "name": account.name,
        "email": account.email,
        "avatar_url": account.avatar_url,
        "onboarded": account.onboarded,
    }


@app.post("/auth/login")
def login(payload: LoginPayload):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")

    # Login with name + password (as requested)
    doc = db["account"].find_one({"name": payload.name.strip()})
    if not doc:
        raise HTTPException(status_code=401, detail="Invalid name or password")

    if not pwd_context.verify(payload.password, doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid name or password")

    return {
        "id": str(doc.get("_id")),
        "name": doc.get("name"),
        "email": doc.get("email"),
        "avatar_url": doc.get("avatar_url"),
        "onboarded": doc.get("onboarded", False),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
