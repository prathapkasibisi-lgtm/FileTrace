from __future__ import annotations

import hashlib
import io
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import qrcode
from docx import Document
from docx.shared import Inches
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

ROOT = Path(__file__).resolve().parent.parent

# Vercel's deployed application directory is read-only.
# /tmp is writable but temporary; use external persistent storage for production.
RUNTIME_DIR = Path(os.getenv("RUNTIME_DIR", "/tmp/filetrace"))
DB_PATH = Path(os.getenv("DATABASE_PATH", RUNTIME_DIR / "filetrace.db"))
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", RUNTIME_DIR / "storage"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "25"))
APP_NAME = os.getenv("APP_NAME", "FileTrace")
# Set this to a public HTTPS URL before sharing files with other people.
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "app" / "templates")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with connect() as con:
        con.executescript("""
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS tracked_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_id TEXT NOT NULL UNIQUE,
            scan_token TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            qr_name TEXT NOT NULL,
            content_type TEXT,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS access_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL REFERENCES tracked_files(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            ip_hash TEXT,
            user_agent TEXT,
            visitor_name TEXT
        );
        CREATE TABLE IF NOT EXISTS device_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_event_id INTEGER NOT NULL UNIQUE REFERENCES access_events(id) ON DELETE CASCADE,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy_meters REAL NOT NULL,
            captured_at TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'DEVICE_REPORTED_LOCATION'
        );
        CREATE INDEX IF NOT EXISTS idx_access_file_time ON access_events(file_id, occurred_at);
        """)
        # Migrate the earlier starter database without deleting existing rows.
        cols = {r["name"] for r in con.execute("PRAGMA table_info(tracked_files)").fetchall()}
        if "scan_token" not in cols:
            con.execute("ALTER TABLE tracked_files ADD COLUMN scan_token TEXT")
        if "qr_name" not in cols:
            con.execute("ALTER TABLE tracked_files ADD COLUMN qr_name TEXT")
        event_cols = {r["name"] for r in con.execute("PRAGMA table_info(access_events)").fetchall()}
        if "visitor_name" not in event_cols:
            con.execute("ALTER TABLE access_events ADD COLUMN visitor_name TEXT")
        rows = con.execute("SELECT id FROM tracked_files WHERE scan_token IS NULL OR qr_name IS NULL").fetchall()
        for row in rows:
            con.execute("UPDATE tracked_files SET scan_token=?, qr_name=? WHERE id=?",
                        (secrets.token_urlsafe(24), f"legacy-{row['id']}.png", row["id"]))


init_db()


def ip_fingerprint(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()


def log_event(file_id: int, event_type: str, request: Request, visitor_name: str = "") -> int:
    with connect() as con:
        cur = con.execute("""
            INSERT INTO access_events (file_id, event_type, occurred_at, ip_hash, user_agent, visitor_name)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (file_id, event_type, now_iso(), ip_fingerprint(request),
              request.headers.get("user-agent", "")[:500], visitor_name[:120]))
        return int(cur.lastrowid)


class LocationPayload(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    accuracy_meters: float = Field(gt=0, le=100000)
    captured_at: str = Field(min_length=10, max_length=80)


class VisitorNamePayload(BaseModel):
    name: str = Field(min_length=1, max_length=120)


def make_qr(url: str) -> bytes:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def make_pdf_with_qr(source: bytes, qr_bytes: bytes, tracking_id: str) -> bytes:
    # Add a clearly labeled final page so the source pages remain intact.
    overlay = io.BytesIO()
    c = canvas.Canvas(overlay, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 16)
    c.drawString(48, height - 70, "FileTrace document identification")
    c.setFont("Helvetica", 10)
    c.drawString(48, height - 92, f"Tracking ID: {tracking_id}")
    c.drawString(48, height - 110, "Scan the QR code to report receipt and optionally share device location.")
    c.drawImage(ImageReader(Image.open(io.BytesIO(qr_bytes))), width/2 - 65, height/2 - 65,
                width=130, height=130)
    c.setFont("Helvetica", 8)
    c.drawCentredString(width/2, height/2 - 85, "Location is requested only with browser permission.")
    c.save()
    overlay.seek(0)
    writer = PdfWriter()
    reader = PdfReader(io.BytesIO(source))
    for page in reader.pages:
        writer.add_page(page)
    extra = PdfReader(overlay)
    writer.add_page(extra.pages[0])
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def make_docx_with_qr(source: bytes, qr_bytes: bytes, tracking_id: str) -> bytes:
    doc = Document(io.BytesIO(source))
    section = doc.sections[0]
    footer = section.footer
    para = footer.add_paragraph()
    para.add_run(f"FileTrace ID: {tracking_id}  |  Scan QR to report receipt: ")
    para.add_run().add_picture(io.BytesIO(qr_bytes), width=Inches(0.8))
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


def make_image_with_qr(source: bytes, qr_bytes: bytes) -> bytes:
    image = Image.open(io.BytesIO(source)).convert("RGBA")
    qr = Image.open(io.BytesIO(qr_bytes)).convert("RGBA")
    # Add a white QR panel in the lower-right corner, sized to remain scannable.
    side = max(150, min(260, image.width // 4, image.height // 4))
    qr.thumbnail((side, side))
    pad = max(10, side // 12)
    panel = Image.new("RGBA", (qr.width + pad * 2, qr.height + pad * 2), "white")
    panel.alpha_composite(qr, (pad, pad))
    x = max(0, image.width - panel.width - pad)
    y = max(0, image.height - panel.height - pad)
    image.alpha_composite(panel, (x, y))
    out = io.BytesIO()
    suffix = Path("image.png").suffix.lower()
    image.convert("RGB").save(out, format="PNG")
    return out.getvalue()


def embed_qr(filename: str, content_type: str, data: bytes, qr_bytes: bytes, tracking_id: str) -> tuple[bytes, str]:
    suffix = Path(filename).suffix.lower()
    if suffix == ".pdf" or content_type == "application/pdf":
        return make_pdf_with_qr(data, qr_bytes, tracking_id), "PDF with QR identification page"
    if suffix == ".docx":
        return make_docx_with_qr(data, qr_bytes, tracking_id), "DOCX with QR in footer"
    if suffix in {".png", ".jpg", ".jpeg", ".webp"} or content_type.startswith("image/"):
        try:
            return make_image_with_qr(data, qr_bytes), "Image with embedded QR panel"
        except Exception:
            return data, "Original file retained; QR available separately"
    return data, "Original format retained; QR available as separate PNG"


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    with connect() as con:
        rows = con.execute("""
            SELECT f.*,
              (SELECT COUNT(*) FROM access_events e WHERE e.file_id=f.id) AS event_count,
              (SELECT COUNT(*) FROM device_locations l JOIN access_events e ON e.id=l.access_event_id
               WHERE e.file_id=f.id) AS location_count
            FROM tracked_files f ORDER BY f.created_at DESC
        """).fetchall()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "files": rows,
            "app_name": APP_NAME,
            "public_base_url": PUBLIC_BASE_URL
        }
    )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(400, "Choose a file.")
    safe_name = Path(file.filename).name
    data = await file.read((MAX_UPLOAD_MB * 1024 * 1024) + 1)
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {MAX_UPLOAD_MB} MB.")
    if not data:
        raise HTTPException(400, "The selected file is empty.")

    digest = hashlib.sha256(data).hexdigest()
    tracking_id = "FT-" + secrets.token_hex(8).upper()
    scan_token = secrets.token_urlsafe(24)
    scan_url = f"{PUBLIC_BASE_URL}/scan/{scan_token}"
    qr_bytes = make_qr(scan_url)
    processed, processing_note = embed_qr(safe_name, file.content_type or "", data, qr_bytes, tracking_id)
    download_name = safe_name
    if Path(safe_name).suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"} or (file.content_type or "").startswith("image/"):
        download_name = f"{Path(safe_name).stem}_FileTrace.png"

    stored_name = secrets.token_hex(16)
    qr_name = f"{tracking_id}-QR.png"
    (STORAGE_DIR / stored_name).write_bytes(processed)
    (STORAGE_DIR / qr_name).write_bytes(qr_bytes)

    with connect() as con:
        con.execute("""
            INSERT INTO tracked_files
            (tracking_id, scan_token, original_name, stored_name, qr_name, content_type, size_bytes, sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (tracking_id, scan_token, safe_name, stored_name, qr_name,
              file.content_type or "application/octet-stream", len(processed), digest, now_iso()))
    return RedirectResponse("/", status_code=303)


@app.get("/download/{tracking_id}")
def download_processed_file(tracking_id: str):
    with connect() as con:
        row = con.execute("SELECT * FROM tracked_files WHERE tracking_id=?", (tracking_id,)).fetchone()
    if not row:
        raise HTTPException(404, "File not found.")
    path = STORAGE_DIR / row["stored_name"]
    return FileResponse(path, filename=f"FileTrace_{row['original_name']}",
                        media_type=row["content_type"] or "application/octet-stream")


@app.get("/qr/{tracking_id}")
def download_qr(tracking_id: str):
    with connect() as con:
        row = con.execute("SELECT * FROM tracked_files WHERE tracking_id=?", (tracking_id,)).fetchone()
    if not row:
        raise HTTPException(404, "File not found.")
    return FileResponse(STORAGE_DIR / row["qr_name"], filename=row["qr_name"], media_type="image/png")


@app.get("/scan/{token}", response_class=HTMLResponse)
def scan_qr(token: str, request: Request):
    with connect() as con:
        row = con.execute("SELECT * FROM tracked_files WHERE scan_token=?", (token,)).fetchone()
    if not row:
        raise HTTPException(404, "This tracking QR is invalid or expired.")
    event_id = log_event(row["id"], "QR_SCANNED", request)
    return templates.TemplateResponse(
        request=request,
        name="scan.html",
        context={
            "request": request,
            "file": row,
            "token": token,
            "event_id": event_id,
            "app_name": APP_NAME
        }
    )


@app.post("/api/scan/{token}/name")
def save_visitor_name(token: str, payload: VisitorNamePayload, request: Request):
    with connect() as con:
        row = con.execute("SELECT id FROM tracked_files WHERE scan_token=?", (token,)).fetchone()
        if not row:
            raise HTTPException(404, "Tracking QR not found.")
        cur = con.execute("""
            INSERT INTO access_events (file_id, event_type, occurred_at, ip_hash, user_agent, visitor_name)
            VALUES (?, 'VISITOR_NAME_SUBMITTED', ?, ?, ?, ?)
        """, (row["id"], now_iso(), ip_fingerprint(request),
              request.headers.get("user-agent", "")[:500], payload.name.strip()))
        event_id = cur.lastrowid
    return {"saved": True, "event_id": event_id}


@app.post("/api/scan/{token}/location")
def save_device_location(token: str, payload: LocationPayload, request: Request):
    with connect() as con:
        row = con.execute("SELECT id FROM tracked_files WHERE scan_token=?", (token,)).fetchone()
        if not row:
            raise HTTPException(404, "Tracking QR not found.")
        # Attach the location to the latest QR scan from this browser fingerprint.
        event = con.execute("""
            SELECT id FROM access_events WHERE file_id=? AND event_type='QR_SCANNED' AND ip_hash=?
            ORDER BY occurred_at DESC LIMIT 1
        """, (row["id"], ip_fingerprint(request))).fetchone()
        if not event:
            raise HTTPException(404, "No matching QR scan event found.")
        con.execute("""
            INSERT OR REPLACE INTO device_locations
            (access_event_id, latitude, longitude, accuracy_meters, captured_at, source)
            VALUES (?, ?, ?, ?, ?, 'DEVICE_REPORTED_LOCATION')
        """, (event["id"], payload.latitude, payload.longitude,
              payload.accuracy_meters, payload.captured_at))
    return {"saved": True}


@app.get("/files/{tracking_id}/events", response_class=HTMLResponse)
def file_events(tracking_id: str, request: Request):
    with connect() as con:
        file_row = con.execute("SELECT * FROM tracked_files WHERE tracking_id=?", (tracking_id,)).fetchone()
        if not file_row:
            raise HTTPException(404, "File not found.")
        events = con.execute("""
            SELECT e.*, l.latitude, l.longitude, l.accuracy_meters, l.captured_at, l.source
            FROM access_events e LEFT JOIN device_locations l ON l.access_event_id=e.id
            WHERE e.file_id=? ORDER BY e.occurred_at DESC
        """, (file_row["id"],)).fetchall()
    return templates.TemplateResponse(
        request=request,
        name="events.html",
        context={
            "request": request,
            "file": file_row,
            "events": events,
            "app_name": APP_NAME
        }
    )


@app.get("/health")
def health():
    return {"status": "ok", "app": APP_NAME}
