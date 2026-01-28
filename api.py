from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.web_security_tool.password_generator import ProcessGenerator
from src.web_security_tool.password_assessor import PasswordAssessor
from src.web_security_tool.input_validator import InputValidator

app = FastAPI(
    title="Web Security Tool",
    description="Security Script Programming Academic Project",
    version="1.0.0"
)

# ---------- Models ----------
class GenerateRequest(BaseModel):
    length: int = Field(default=16, ge=4, le=128)

class AssessRequest(BaseModel):
    password: str

class ValidateRequest(BaseModel):
    type: str = Field(
        ...,
        description="email | url | phone | alphanumeric | text | sql"
    )
    value: str


# ---------- Routes ----------
@app.get("/")
def root():
    return {"status": "ok", "message": "Web Security Tool API running"}


@app.post("/generate")
def generate_password(req: GenerateRequest):
    pwd, sha, bcr, ts = ProcessGenerator.generate(req.length)
    return {
        "password": pwd,
        "sha256": sha,
        "bcrypt": bcr,
        "timestamp": ts
    }


@app.post("/assess")
def assess_password(req: AssessRequest):
    result = PasswordAssessor.evaluate_password(req.password)
    return {"result": result}


@app.post("/validate")
def validate_input(req: ValidateRequest):
    v = InputValidator()
    t = req.type.lower().strip()

    if t == "email":
        return v.validate_email(req.value)
    if t == "url":
        return v.validate_url(req.value)
    if t == "phone":
        return v.validate_phone(req.value)
    if t == "alphanumeric":
        return v.validate_alphanumeric(req.value)
    if t == "text":
        return v.validate_text(req.value)
    if t == "sql":
        return v.validate_sql(req.value)

    raise HTTPException(status_code=400, detail="Unknown validation type")
