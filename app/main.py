from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import models  # noqa: F401  (registers the tables)
from .database import Base, SessionLocal, engine
from .routers import audit, auth, cases, evidence, users
from .seed import ensure_admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        ensure_admin(db)
    yield


app = FastAPI(title="Cloud-Based Digital Forensics System", version="1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://localhost:3000"],
                   allow_methods=["*"], allow_headers=["*"])
for module in (auth, users, cases, evidence, audit):
    app.include_router(module.router)

UI_DIR = Path(__file__).resolve().parent.parent / "ui"
app.mount("/ui", StaticFiles(directory=UI_DIR), name="ui")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(UI_DIR / "index.html")


@app.get("/api/health", tags=["system"])
def health():
    return {"status": "ok"}
