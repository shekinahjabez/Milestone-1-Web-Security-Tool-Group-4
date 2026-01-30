import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# -------------------------------------------------
# Make "src" importable (so we can import web_security_tool.*)
# -------------------------------------------------
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

# -------------------------------------------------
# Vite build (React) served by FastAPI
# -------------------------------------------------
FRONTEND_DIST = os.path.join(BASE_DIR, "frontend", "dist")
FRONTEND_ASSETS = os.path.join(FRONTEND_DIST, "assets")

# Serve hashed assets (JS/CSS) from /assets
if os.path.isdir(FRONTEND_ASSETS):
    app.mount("/assets", StaticFiles(directory=FRONTEND_ASSETS), name="assets")


# -------------------------------------------------
# Models
# -------------------------------------------------
class GenerateRequest(BaseModel):
    length: int = Field(default=16, ge=4, le=128)


class AssessRequest(BaseModel):
    password: str


class ValidateRequest(BaseModel):
    field_type: str = Field(..., description="name | email | username | message")
    value: str


# -------------------------------------------------
# API
# -------------------------------------------------
@app.api_route("/api", methods=["GET", "HEAD"], include_in_schema=False)
def api_root():
    return {"status": "ok", "message": "Web Security Tool API running"}


@app.post("/api/generate")
def generate_password(req: GenerateRequest):
    pwd, sha, bcr, ts = ProcessGenerator.generate(req.length)
    return {"password": pwd, "sha256": sha, "bcrypt": bcr, "timestamp": ts}


@app.post("/api/assess")
def assess_password(req: AssessRequest):
    result = PasswordAssessor.evaluate_password(req.password)
    return {"result": result}


@app.post("/api/validate")
def validate_input(req: ValidateRequest):
    ft = (req.field_type or "").lower().strip()
    sanitized, was_sanitized, notes = InputValidator.sanitize_input(req.value, ft)

    # SQL detected note is produced by InputValidator.sanitize_input()
    sql_detected = any("SQL keyword/pattern detected" in n for n in notes)

    # Validate using ORIGINAL when SQL is detected (so keyword errors still show)
    validation_text = req.value if sql_detected else sanitized

    if ft in ("name", "full_name", "fullname"):
        is_valid, errors = InputValidator.validate_full_name(validation_text)
        ft_out = "name"
    elif ft == "email":
        is_valid, errors = InputValidator.validate_email_simple(validation_text)
        ft_out = "email"
    elif ft == "username":
        is_valid, errors = InputValidator.validate_username(validation_text)
        ft_out = "username"
    elif ft == "message":
        is_valid, errors = InputValidator.validate_message(validation_text)
        ft_out = "message"
    else:
        raise HTTPException(status_code=400, detail="Unknown field_type. Use: name, email, username, message")

    # ✅ BLOCK display of sanitized output for ANY field if SQL detected
    sanitized_out = sanitized
    if sql_detected:
        sanitized_out = "[BLOCKED: SQL detected]"

    return {
        "field_type": ft_out,
        "original": req.value,
        "sanitized": sanitized_out,
        "was_sanitized": was_sanitized,
        "notes": notes,
        "is_valid": is_valid,
        "errors": errors,
    }



# -------------------------------------------------
# React SPA catch-all (must be last)
# -------------------------------------------------
@app.get("/{full_path:path}", include_in_schema=False)
def serve_react_app(full_path: str):
    index_path = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return {"error": "React build not found. Run `npm run build` inside /frontend."}
