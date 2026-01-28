import os
import sys

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field

# Make "src" importable (so we can import web_security_tool.*)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from web_security_tool.password_generator import ProcessGenerator
from web_security_tool.password_assessor import PasswordAssessor
from web_security_tool.input_validator import InputValidator

app = FastAPI(
    title="Web Security Tool",
    description="Security Script Programming Academic Project",
    version="1.0.0",
)

# ---------- Models ----------
class GenerateRequest(BaseModel):
    length: int = Field(default=16, ge=4, le=128)

class AssessRequest(BaseModel):
    password: str

class ValidateRequest(BaseModel):
    type: str = Field(..., description="email | url | phone | alphanumeric | text | sql")
    value: str


# ---------- Routes ----------
@app.api_route("/", methods=["GET", "HEAD"])
def root():
    return {"status": "ok", "message": "Web Security Tool API running"}

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)

@app.post("/generate")
def generate_password(req: GenerateRequest):
    pwd, sha, bcr, ts = ProcessGenerator.generate(req.length)
    return {
        "password": pwd,
        "sha256": sha,
        "bcrypt": bcr,
        "timestamp": ts,
    }

@app.post("/assess")
def assess_password(req: AssessRequest):
    result = PasswordAssessor.evaluate_password(req.password)
    return {"result": result}

@app.post("/validate")
def validate_input(req: ValidateRequest):
    v = InputValidator()
    t = req.type.lower().strip()

    handlers = {
        "email": v.validate_email,
        "url": v.validate_url,
        "phone": v.validate_phone,
        "alphanumeric": v.validate_alphanumeric,
        "text": v.validate_text,
        "sql": v.validate_sql,
    }

    fn = handlers.get(t)
    if not fn:
        raise HTTPException(status_code=400, detail="Unknown validation type")

    return fn(req.value)
