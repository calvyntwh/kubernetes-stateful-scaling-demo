from fastapi import FastAPI, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from sqlmodel import Field, Session, SQLModel, create_engine, select
from contextlib import asynccontextmanager
from typing import Optional, List
from sqlalchemy.exc import OperationalError
from pydantic import BaseModel, Field as PydanticField, validator
import html
import logging
import os
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MessageCreate(BaseModel):
    message: str = PydanticField(..., min_length=1, max_length=500)
    
    @validator('message')
    def sanitize_message(cls, v):
        if not v or not v.strip():
            raise ValueError('Message cannot be empty')
        
        # Remove script tags and other dangerous elements
        v = re.sub(r'<script[^>]*>.*?</script>', '', v, flags=re.IGNORECASE | re.DOTALL)
        v = re.sub(r'<[^>]*>', '', v)  # Remove all HTML tags
        v = html.escape(v.strip())
        if not v:
            raise ValueError('Message cannot be empty after sanitization')
        return v
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
        return response
DATABASE_FILE = os.getenv("DATABASE_FILE", "/data/database.db")
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"

engine = create_engine(
    DATABASE_URL, 
    echo=False,
    connect_args={"check_same_thread": False}
)

class GuestbookEntry(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    message: str

class Config(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str

def create_db_and_tables():
    try:
        os.makedirs(os.path.dirname(DATABASE_FILE), exist_ok=True)
        SQLModel.metadata.create_all(engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Application starting up...")
    create_db_and_tables()

    try:
        with Session(engine) as session:
            secret = session.exec(select(Config).where(Config.key == "secret_message")).first()
            if not secret:
                logger.info("Seeding secret message into the database...")
                new_secret = Config(key="secret_message", value="This secret now comes from the SQLite database!")
                session.add(new_secret)
                session.commit()
    except Exception as e:
        logger.error(f"Failed to initialize database data: {e}")
        raise
    
    yield
    logger.info("Application shutting down...")

app = FastAPI(lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
templates = Jinja2Templates(directory="templates")

def get_session():
    with Session(engine) as session:
        yield session

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, session: Session = Depends(get_session), error: Optional[str] = None):
    """Display the main page with guestbook entries."""
    try:
        entries = session.exec(select(GuestbookEntry)).all()
        secret_from_db = session.exec(select(Config).where(Config.key == "secret_message")).first()
        secret_message = secret_from_db.value if secret_from_db else "No secret found in DB."

        return templates.TemplateResponse("index.html", {
            "request": request,
            "secret": secret_message,
            "entries": entries,
            "error": error
        })
    except Exception as e:
        logger.error(f"Error loading main page: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes probes."""
    return {"status": "healthy", "service": "stateful-guestbook"}

@app.post("/add", response_class=RedirectResponse)
async def add_entry(message: str = Form(...), session: Session = Depends(get_session)):
    """Handle the submission of a new guestbook entry."""
    try:
        if not message or not message.strip():
            logger.warning("Empty message submission attempted")
            error_message = "Invalid input: Message cannot be empty"
            return RedirectResponse(url=f"/?error={error_message}", status_code=303)
        
        message_data = MessageCreate(message=message)
        new_entry = GuestbookEntry(message=message_data.message)
        session.add(new_entry)
        session.commit()
        
        logger.info(f"New guestbook entry added: {message_data.message[:50]}...")
        return RedirectResponse(url="/", status_code=303)
        
    except ValueError as e:
        logger.warning(f"Invalid input received: {e}")
        error_message = "Invalid input: Message cannot be empty or too long"
        return RedirectResponse(url=f"/?error={error_message}", status_code=303)
        
    except OperationalError as e:
        # This demonstrates the database locking issue when scaling
        if "database is locked" in str(e).lower():
            logger.error("DEMO ERROR: Database is locked! This is expected when scaled > 1 replica.")
            error_message = "DATABASE IS LOCKED! This is the error you get when multiple application instances try to write to the same SQLite file at once."
            return RedirectResponse(url=f"/?error={error_message}", status_code=303)
        else:
            logger.error(f"Database operational error: {e}")
            error_message = "Database error occurred. Please try again."
            return RedirectResponse(url=f"/?error={error_message}", status_code=303)
            
    except Exception as e:
        logger.error(f"Unexpected error adding entry: {e}")
        error_message = "An unexpected error occurred. Please try again."
        return RedirectResponse(url=f"/?error={error_message}", status_code=303)
