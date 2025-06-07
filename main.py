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
from sqlalchemy import event
from pydantic import BaseModel, Field as PydanticField, validator
import html
import logging
import os
import re
import time
import random
import uuid

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

# STATEFUL APPLICATION DESIGN: Demonstrates multiple 12-factor violations
# This configuration works fine with single instance but fails with multiple instances

# In-memory state that violates stateless principle (Factor #6)
APPLICATION_STATE = {
    "instance_id": os.urandom(8).hex(),
    "startup_time": None,
    "request_counter": 0,
    "active_sessions": {},
    "cached_data": {},
    "temp_files": [],
    "processing_queue": []
}

# Configure SQLite with moderate settings - works for single pod, contentious for multiple
engine = create_engine(
    DATABASE_URL, 
    echo=False,
    connect_args={
        "check_same_thread": False,
        "timeout": 5.0,  # Reasonable timeout for single pod
    },
    pool_size=3,  # Small pool that becomes bottleneck with multiple pods
    max_overflow=2
)

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Configure SQLite for single-instance usage"""
    cursor = dbapi_connection.cursor()
    try:
        # Use WAL mode for better single-instance performance
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=2000")  # 2 second timeout
    finally:
        cursor.close()

class GuestbookEntry(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    message: str
    instance_id: str  # Track which instance created this entry
    session_id: Optional[str] = None  # Demonstrates session affinity issues

class Config(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str

class UserSession(SQLModel, table=True):
    """Demonstrates stateful session storage violation"""
    session_id: str = Field(primary_key=True)
    instance_id: str
    user_data: str
    created_at: str

def create_db_and_tables():
    try:
        os.makedirs(os.path.dirname(DATABASE_FILE), exist_ok=True)
        
        # For demo purposes, always recreate tables to ensure schema is up to date
        # In production, you'd use proper migrations
        SQLModel.metadata.drop_all(engine)
        SQLModel.metadata.create_all(engine)
        
        # Initialize application state
        APPLICATION_STATE["startup_time"] = str(int(time.time()))
        
        logger.info(f"Database tables created successfully by instance {APPLICATION_STATE['instance_id']}")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Application starting up... Instance ID: {APPLICATION_STATE['instance_id']}")
    create_db_and_tables()

    try:
        with Session(engine) as session:
            # Seed initial data with instance awareness
            secret = session.exec(select(Config).where(Config.key == "secret_message")).first()
            if not secret:
                logger.info("Seeding secret message into the database...")
                new_secret = Config(key="secret_message", value=f"Secret from instance {APPLICATION_STATE['instance_id']}")
                session.add(new_secret)
                session.commit()
                
            # Track instance startup in database
            instance_key = f"instance_{APPLICATION_STATE['instance_id']}"
            instance_config = session.exec(select(Config).where(Config.key == instance_key)).first()
            if instance_config:
                instance_config.value = APPLICATION_STATE['startup_time']
            else:
                instance_config = Config(key=instance_key, value=APPLICATION_STATE['startup_time'])
                session.add(instance_config)
            session.commit()
                
    except Exception as e:
        logger.error(f"Failed to initialize database data: {e}")
        raise
    
    yield
    logger.info(f"Application shutting down... Instance ID: {APPLICATION_STATE['instance_id']}")

app = FastAPI(lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
templates = Jinja2Templates(directory="templates")

def get_session():
    with Session(engine) as session:
        yield session

def get_or_create_user_session(request: Request, db_session: Session):
    """Demonstrates stateful session handling - violates stateless principle"""
    session_id = request.cookies.get("session_id")
    
    if not session_id:
        # Create new session
        session_id = str(uuid.uuid4())
        user_session = UserSession(
            session_id=session_id,
            instance_id=APPLICATION_STATE['instance_id'],
            user_data="{}",
            created_at=str(int(time.time()))
        )
        db_session.add(user_session)
        db_session.commit()
        APPLICATION_STATE["active_sessions"][session_id] = {
            "created_at": time.time(),
            "requests": 0,
            "instance_id": APPLICATION_STATE['instance_id']
        }
    else:
        # Check if session exists in current instance (stateful problem!)
        if session_id not in APPLICATION_STATE["active_sessions"]:
            # Session exists in DB but not in this instance's memory - scaling problem!
            user_session = db_session.exec(select(UserSession).where(UserSession.session_id == session_id)).first()
            if user_session and user_session.instance_id != APPLICATION_STATE['instance_id']:
                logger.warning(f"Session {session_id} was created by different instance {user_session.instance_id}")
                # This creates inconsistent behavior across instances
                APPLICATION_STATE["active_sessions"][session_id] = {
                    "created_at": time.time(),
                    "requests": 0,
                    "instance_id": user_session.instance_id,
                    "foreign_session": True
                }
    
    return session_id

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, session: Session = Depends(get_session), error: Optional[str] = None):
    """Display the main page with guestbook entries and instance information."""
    try:
        # Update request counter (in-memory state)
        APPLICATION_STATE["request_counter"] += 1
        
        # Get user session (demonstrates session affinity issues)
        session_id = get_or_create_user_session(request, session)
        
        # Get entries with instance information
        entries = session.exec(select(GuestbookEntry)).all()
        
        # Get secret from DB
        secret_from_db = session.exec(select(Config).where(Config.key == "secret_message")).first()
        secret_message = secret_from_db.value if secret_from_db else "No secret found in DB."

        # Get instance information to show scaling issues
        instance_info = {
            "current_instance": APPLICATION_STATE['instance_id'],
            "request_count": APPLICATION_STATE["request_counter"],
            "startup_time": APPLICATION_STATE["startup_time"],
            "active_sessions": len(APPLICATION_STATE["active_sessions"]),
            "session_id": session_id
        }
        
        # Check for other instances in database
        all_instances = session.exec(select(Config).where(Config.key.like("instance_%"))).all()
        other_instances = [config for config in all_instances 
                          if config.key != f"instance_{APPLICATION_STATE['instance_id']}"]

        response = templates.TemplateResponse("index.html", {
            "request": request,
            "secret": secret_message,
            "entries": entries,
            "error": error,
            "instance_info": instance_info,
            "other_instances": other_instances
        })
        
        # Set session cookie
        response.set_cookie("session_id", session_id, httponly=True)
        return response
        
    except Exception as e:
        logger.error(f"Error loading main page: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes probes."""
    return {"status": "healthy", "service": "stateful-guestbook"}

@app.post("/add", response_class=RedirectResponse)
async def add_entry(message: str = Form(...), request: Request = None, session: Session = Depends(get_session)):
    """Handle the submission of a new guestbook entry with stateful processing."""
    try:
        if not message or not message.strip():
            logger.warning("Empty message submission attempted")
            error_message = "Invalid input: Message cannot be empty"
            return RedirectResponse(url=f"/?error={error_message}", status_code=303)
        
        message_data = MessageCreate(message=message)
        
        # Get current session for stateful processing
        session_id = request.cookies.get("session_id") if request else None
        
        # Simulate stateful processing that works fine with single instance
        # but causes issues with multiple instances
        
        # 1. In-memory cache processing (violates stateless principle)
        cache_key = f"processing_{session_id}_{int(time.time())}"
        APPLICATION_STATE["cached_data"][cache_key] = {
            "message": message_data.message,
            "started_at": time.time(),
            "instance_id": APPLICATION_STATE['instance_id']
        }
        
        # 2. Add to processing queue (in-memory state)
        APPLICATION_STATE["processing_queue"].append({
            "id": cache_key,
            "message": message_data.message,
            "session_id": session_id
        })
        
        # 3. Moderate processing delay (realistic for single instance)
        time.sleep(random.uniform(0.1, 0.3))  # Small delay, acceptable for single pod
        
        # 4. Database operations with session affinity
        try:
            # Check if this session has entries from other instances
            existing_entries = session.exec(
                select(GuestbookEntry).where(GuestbookEntry.session_id == session_id)
            ).all()
            
            # Create new entry with instance tracking
            new_entry = GuestbookEntry(
                message=message_data.message,
                instance_id=APPLICATION_STATE['instance_id'],
                session_id=session_id
            )
            session.add(new_entry)
            
            # Update instance stats in database
            stats_key = f"stats_{APPLICATION_STATE['instance_id']}"
            stats_entry = session.exec(select(Config).where(Config.key == stats_key)).first()
            if stats_entry:
                current_count = int(stats_entry.value) + 1
                stats_entry.value = str(current_count)
            else:
                stats_entry = Config(key=stats_key, value="1")
                session.add(stats_entry)
            
            # Commit changes
            session.commit()
            
            # Clean up processing state
            if cache_key in APPLICATION_STATE["cached_data"]:
                del APPLICATION_STATE["cached_data"][cache_key]
            APPLICATION_STATE["processing_queue"] = [
                item for item in APPLICATION_STATE["processing_queue"] 
                if item["id"] != cache_key
            ]
            
            logger.info(f"Entry added by instance {APPLICATION_STATE['instance_id']}: {message_data.message[:50]}...")
            
            # Show session affinity warning if user has entries from multiple instances
            if existing_entries:
                different_instances = set(entry.instance_id for entry in existing_entries 
                                        if entry.instance_id != APPLICATION_STATE['instance_id'])
                if different_instances:
                    warning = f"WARNING: Your session has entries from multiple instances: {', '.join(different_instances)}. This shows session affinity issues!"
                    return RedirectResponse(url=f"/?error={warning}", status_code=303)
            
            return RedirectResponse(url="/", status_code=303)
            
        except Exception as db_error:
            # Clean up state on error
            if cache_key in APPLICATION_STATE["cached_data"]:
                del APPLICATION_STATE["cached_data"][cache_key]
            APPLICATION_STATE["processing_queue"] = [
                item for item in APPLICATION_STATE["processing_queue"] 
                if item["id"] != cache_key
            ]
            raise db_error
        
    except ValueError as e:
        logger.warning(f"Invalid input received: {e}")
        error_message = "Invalid input: Message cannot be empty or too long"
        return RedirectResponse(url=f"/?error={error_message}", status_code=303)
        
    except Exception as e:
        logger.error(f"Error adding entry: {e}")
        error_message = f"Error occurred on instance {APPLICATION_STATE['instance_id']}: {str(e)}"
        return RedirectResponse(url=f"/?error={error_message}", status_code=303)

@app.get("/status")
async def get_status(session: Session = Depends(get_session)):
    """Show detailed instance status - demonstrates stateful information"""
    try:
        # Get database stats
        all_entries = session.exec(select(GuestbookEntry)).all()
        entries_by_instance = {}
        for entry in all_entries:
            instance = entry.instance_id
            entries_by_instance[instance] = entries_by_instance.get(instance, 0) + 1
        
        # Get all active instances from database
        all_instances = session.exec(select(Config).where(Config.key.like("instance_%"))).all()
        
        return {
            "current_instance": {
                "id": APPLICATION_STATE['instance_id'],
                "startup_time": APPLICATION_STATE['startup_time'],
                "request_count": APPLICATION_STATE["request_counter"],
                "active_sessions": len(APPLICATION_STATE["active_sessions"]),
                "cache_size": len(APPLICATION_STATE["cached_data"]),
                "queue_size": len(APPLICATION_STATE["processing_queue"])
            },
            "database_stats": {
                "total_entries": len(all_entries),
                "entries_by_instance": entries_by_instance
            },
            "all_instances": [{"id": config.key.replace("instance_", ""), "startup_time": config.value} 
                            for config in all_instances],
            "scaling_issues": {
                "session_affinity": "Sessions tied to specific instances",
                "in_memory_state": "Cache and queue data lost when pods restart",
                "database_contention": "Multiple pods competing for database access",
                "inconsistent_state": "Different instances have different in-memory state"
            }
        }
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
