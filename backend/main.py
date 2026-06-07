from __future__ import annotations

import json
import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "droidshield_reports.db"

app = FastAPI(
    title="MySecure Government Audit Backend",
    version="1.0.0",
    description="Stores Malaysian government Android APK static compliance and forensic audit reports.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Finding(BaseModel):
    category: str = "Unknown"
    severity: str = "low"
    title: str
    advice: str


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2)
    email: str
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    name: str
    email: str
    role: str
    createdAt: str


class AuthToken(BaseModel):
    accessToken: str
    tokenType: str = "bearer"
    user: UserOut


class ForensicEvidence(BaseModel):
    evidenceSource: str | None = None
    apkSha256: str | None = None
    apkSizeBytes: int | None = None
    sourcePath: str | None = None
    installerPackage: str | None = None
    firstInstallTime: str | None = None
    lastUpdateTime: str | None = None
    splitApkCount: int | None = None
    dexCount: int | None = None
    nativeLibCount: int | None = None
    nativeLibraries: list[str] = Field(default_factory=list)
    httpUrls: list[str] = Field(default_factory=list)
    secretSignals: list[str] = Field(default_factory=list)
    trackerSignals: list[str] = Field(default_factory=list)
    networkConfigFiles: list[str] = Field(default_factory=list)
    backupRuleFiles: list[str] = Field(default_factory=list)
    signingFiles: list[str] = Field(default_factory=list)
    piiSignals: list[str] = Field(default_factory=list)
    cryptoSignals: list[str] = Field(default_factory=list)
    readableIdentifierSignals: list[str] = Field(default_factory=list)


class ReportCreate(BaseModel):
    appName: str
    packageName: str
    version: str | None = None
    targetSdk: int | None = None
    riskScore: int = Field(ge=0, le=100)
    riskLevel: str
    forensicEvidence: ForensicEvidence | None = None
    findings: list[Finding] = Field(default_factory=list)
    generatedAt: str | None = None
    examinerName: str | None = None
    caseReference: str | None = None
    notes: str | None = None


class ReportUpdate(BaseModel):
    caseReference: str | None = None
    notes: str | None = None
    examinerName: str | None = None


class ReportSummary(BaseModel):
    id: int
    appName: str
    packageName: str
    version: str | None
    riskScore: int
    riskLevel: str
    apkSha256: str | None
    findingCount: int
    examinerName: str | None
    createdAt: str


class ReportDetail(ReportSummary):
    targetSdk: int | None
    forensicEvidence: dict[str, Any] | None
    findings: list[dict[str, Any]]
    generatedAt: str | None
    caseReference: str | None
    notes: str | None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with connect() as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'examiner')),
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                app_name TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT,
                target_sdk INTEGER,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                apk_sha256 TEXT,
                forensic_evidence_json TEXT,
                findings_json TEXT NOT NULL,
                generated_at TEXT,
                examiner_name TEXT,
                case_reference TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        _ensure_column(db, "reports", "user_id", "INTEGER")
        _ensure_column(db, "reports", "apk_sha256", "TEXT")
        _ensure_column(db, "reports", "forensic_evidence_json", "TEXT")
        _ensure_column(db, "reports", "generated_at", "TEXT")
        _ensure_column(db, "reports", "examiner_name", "TEXT")
        _ensure_column(db, "reports", "case_reference", "TEXT")
        _ensure_column(db, "reports", "notes", "TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_package ON reports(package_name)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_sha256 ON reports(apk_sha256)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at)")


def get_current_user(authorization: str | None = Header(default=None)) -> sqlite3.Row:
    token = _extract_bearer_token(authorization)
    with connect() as db:
        user = db.execute(
            """
            SELECT users.*
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
            """,
            (_hash_token(token),),
        ).fetchone()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "database": str(DB_PATH)}


@app.post("/auth/register", response_model=AuthToken, status_code=201)
def register(payload: RegisterRequest) -> AuthToken:
    init_db()
    email = payload.email.strip().lower()

    with connect() as db:
        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Email is already registered")

        user_count = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        role = "admin" if user_count == 0 else "examiner"
        cursor = db.execute(
            """
            INSERT INTO users (name, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (payload.name.strip(), email, _hash_password(payload.password), role, now_iso()),
        )
        user_id = cursor.lastrowid

    return _issue_token(user_id)


@app.post("/auth/login", response_model=AuthToken)
def login(payload: LoginRequest) -> AuthToken:
    init_db()
    email = payload.email.strip().lower()

    with connect() as db:
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user is None or not _verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return _issue_token(user["id"])


@app.get("/auth/me", response_model=UserOut)
def me(current_user: sqlite3.Row = Depends(get_current_user)) -> UserOut:
    return _user_out(current_user)


@app.post("/auth/logout")
def logout(
    authorization: str | None = Header(default=None),
    current_user: sqlite3.Row = Depends(get_current_user),
) -> dict[str, str]:
    token = _extract_bearer_token(authorization)
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))
    return {"status": "logged_out"}


@app.post("/reports", response_model=ReportDetail, status_code=201)
def create_report(
    report: ReportCreate,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> ReportDetail:
    init_db()
    evidence = report.forensicEvidence.model_dump() if report.forensicEvidence else None
    findings = [finding.model_dump() for finding in report.findings]
    apk_sha256 = evidence.get("apkSha256") if evidence else None

    try:
        with connect() as db:
            cursor = db.execute(
                """
                INSERT INTO reports (
                    app_name, package_name, version, target_sdk, risk_score, risk_level,
                    apk_sha256, forensic_evidence_json, findings_json, generated_at,
                    examiner_name, case_reference, notes, created_at, user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.appName,
                    report.packageName,
                    report.version,
                    report.targetSdk,
                    report.riskScore,
                    report.riskLevel,
                    apk_sha256,
                    json.dumps(evidence) if evidence else None,
                    json.dumps(findings),
                    report.generatedAt,
                    report.examinerName or current_user["name"],
                    report.caseReference,
                    report.notes,
                    now_iso(),
                    current_user["id"],
                ),
            )
            report_id = cursor.lastrowid
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=500,
            detail=f"Could not save report to database: {error}",
        ) from error

    try:
        return get_report(report_id, current_user)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Report was saved, but could not be loaded back: {error}",
        ) from error


@app.get("/reports", response_model=list[ReportSummary])
def list_reports(
    package_name: str | None = Query(default=None),
    risk_level: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: sqlite3.Row = Depends(get_current_user),
) -> list[ReportSummary]:
    init_db()
    query = "SELECT * FROM reports WHERE 1=1"
    params: list[Any] = []

    if current_user["role"] != "admin":
        query += " AND user_id = ?"
        params.append(current_user["id"])

    if package_name:
        query += " AND package_name LIKE ?"
        params.append(f"%{package_name}%")
    if risk_level:
        query += " AND lower(risk_level) = lower(?)"
        params.append(risk_level)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with connect() as db:
        rows = db.execute(query, params).fetchall()
    return [_summary(row) for row in rows]


@app.get("/reports/{report_id}", response_model=ReportDetail)
def get_report(
    report_id: int,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> ReportDetail:
    init_db()
    with connect() as db:
        row = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Report not found")
    _require_report_access(row, current_user)

    return _detail(row)


@app.patch("/reports/{report_id}", response_model=ReportDetail)
def update_report(
    report_id: int,
    payload: ReportUpdate,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> ReportDetail:
    init_db()
    with connect() as db:
        row = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Report not found")
        _require_report_access(row, current_user)
        db.execute(
            """
            UPDATE reports
            SET case_reference = ?, notes = ?, examiner_name = ?
            WHERE id = ?
            """,
            (
                payload.caseReference,
                payload.notes,
                payload.examinerName or row["examiner_name"],
                report_id,
            ),
        )

    return get_report(report_id, current_user)


@app.delete("/reports/{report_id}")
def delete_report(
    report_id: int,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> dict[str, str]:
    init_db()
    with connect() as db:
        row = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Report not found")
        _require_report_access(row, current_user)
        cursor = db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "deleted"}


@app.get("/stats")
def stats(current_user: sqlite3.Row = Depends(get_current_user)) -> dict[str, Any]:
    init_db()
    with connect() as db:
        if current_user["role"] == "admin":
            where = ""
            params: tuple[Any, ...] = ()
        else:
            where = "WHERE user_id = ?"
            params = (current_user["id"],)

        total = db.execute(f"SELECT COUNT(*) AS count FROM reports {where}", params).fetchone()["count"]
        by_level = db.execute(
            f"SELECT risk_level, COUNT(*) AS count FROM reports {where} GROUP BY risk_level ORDER BY count DESC",
            params,
        ).fetchall()
        latest = db.execute(
            f"SELECT MAX(created_at) AS created_at FROM reports {where}",
            params,
        ).fetchone()["created_at"]

    return {
        "totalReports": total,
        "latestReportAt": latest,
        "byRiskLevel": {row["risk_level"]: row["count"] for row in by_level},
    }


def _summary(row: sqlite3.Row) -> ReportSummary:
    findings = _json_list(row["findings_json"])
    return ReportSummary(
        id=row["id"],
        appName=row["app_name"],
        packageName=row["package_name"],
        version=row["version"],
        riskScore=row["risk_score"],
        riskLevel=row["risk_level"],
        apkSha256=row["apk_sha256"],
        findingCount=len(findings),
        examinerName=row["examiner_name"],
        createdAt=row["created_at"],
    )


def _detail(row: sqlite3.Row) -> ReportDetail:
    summary = _summary(row).model_dump()
    return ReportDetail(
        **summary,
        targetSdk=row["target_sdk"],
        forensicEvidence=_json_object(row["forensic_evidence_json"]),
        findings=_json_list(row["findings_json"]),
        generatedAt=row["generated_at"],
        caseReference=row["case_reference"],
        notes=row["notes"],
    )


def _ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _json_list(value: str | None) -> list[dict[str, Any]]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _json_object(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, salt, expected = password_hash.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return hmac.compare_digest(digest.hex(), expected)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _issue_token(user_id: int) -> AuthToken:
    token = secrets.token_urlsafe(32)
    with connect() as db:
        db.execute(
            "INSERT INTO sessions (user_id, token_hash, created_at) VALUES (?, ?, ?)",
            (user_id, _hash_token(token), now_iso()),
        )
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        raise HTTPException(status_code=500, detail="User was not found after login")
    return AuthToken(accessToken=token, user=_user_out(user))


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return token


def _user_out(row: sqlite3.Row) -> UserOut:
    return UserOut(
        id=row["id"],
        name=row["name"],
        email=row["email"],
        role=row["role"],
        createdAt=row["created_at"],
    )


def _require_report_access(report: sqlite3.Row, user: sqlite3.Row) -> None:
    if user["role"] == "admin":
        return
    if report["user_id"] == user["id"]:
        return
    raise HTTPException(status_code=403, detail="You do not have access to this report")
