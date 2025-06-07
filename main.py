import asyncio
import html
import logging
import os
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, validator
from pydantic import Field as PydanticField
from sqlalchemy import event
from sqlmodel import Field, Session, SQLModel, create_engine, select
from starlette.middleware.base import BaseHTTPMiddleware

# Constants
REDIRECT_STATUS_CODE = 303
SERVER_ERROR_STATUS_CODE = 500
LINE_LENGTH_LIMIT = 88

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class MessageCreate(BaseModel):
    message: str = PydanticField(..., min_length=1, max_length=500)
    
    @validator("message")
    def sanitize_message(self, v):
        if not v or not v.strip():
            msg = "Message cannot be empty"
            raise ValueError(msg)
        
        # Remove script tags and other dangerous elements
        v = re.sub(r"<script[^>]*>.*?</script>", "", v, flags=re.IGNORECASE | re.DOTALL)
        v = re.sub(r"<[^>]*>", "", v)  # Remove all HTML tags
        v = html.escape(v.strip())
        if not v:
            msg = "Message cannot be empty after sanitization"
            raise ValueError(msg)
        return v
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline';"
        )
        response.headers["Content-Security-Policy"] = csp_policy
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

# Configure SQLite with moderate settings - works for single pod,
# contentious for multiple
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
def set_sqlite_pragma(dbapi_connection, _connection_record):
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
    id: int | None = Field(default=None, primary_key=True)
    message: str
    instance_id: str  # Track which instance created this entry
    session_id: str | None = None  # Demonstrates session affinity issues

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
        Path(DATABASE_FILE).parent.mkdir(parents=True, exist_ok=True)
        
        # For demo purposes, always recreate tables to ensure schema is up to date
        # In production, you'd use proper migrations
        SQLModel.metadata.drop_all(engine)
        SQLModel.metadata.create_all(engine)
        
        # Initialize application state
        APPLICATION_STATE["startup_time"] = str(int(time.time()))
        
        logger.info(
            "Database tables created successfully by instance %s",
            APPLICATION_STATE["instance_id"]
        )
    except Exception:
        logger.exception("Failed to create database tables")
        raise

@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info(
        "Application starting up... Instance ID: %s",
        APPLICATION_STATE["instance_id"]
    )
    create_db_and_tables()

    try:
        with Session(engine) as session:
            # Seed initial data with instance awareness
            secret_query = select(Config).where(Config.key == "secret_message")
            secret = session.exec(secret_query).first()
            if not secret:
                logger.info("Seeding secret message into the database...")
                instance_id = APPLICATION_STATE["instance_id"]
                secret_value = f"Secret from instance {instance_id}"
                new_secret = Config(key="secret_message", value=secret_value)
                session.add(new_secret)
                session.commit()
                
            # Track instance startup in database
            instance_key = f"instance_{APPLICATION_STATE['instance_id']}"
            instance_query = select(Config).where(Config.key == instance_key)
            instance_config = session.exec(instance_query).first()
            if instance_config:
                instance_config.value = APPLICATION_STATE["startup_time"]
            else:
                startup_time = APPLICATION_STATE["startup_time"]
                instance_config = Config(key=instance_key, value=startup_time)
                session.add(instance_config)
            session.commit()
                
    except Exception:
        logger.exception("Failed to initialize database data")
        raise
    
    yield
    logger.info(
        "Application shutting down... Instance ID: %s",
        APPLICATION_STATE["instance_id"]
    )

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
            instance_id=APPLICATION_STATE["instance_id"],
            user_data="{}",
            created_at=str(int(time.time()))
        )
        db_session.add(user_session)
        db_session.commit()
        APPLICATION_STATE["active_sessions"][session_id] = {
            "created_at": time.time(),
            "requests": 0,
            "instance_id": APPLICATION_STATE["instance_id"]
        }
    # Check if session exists in current instance (stateful problem!)
    elif session_id not in APPLICATION_STATE["active_sessions"]:
        # Session exists in DB but not in this instance's memory - scaling problem!
        session_query = select(UserSession).where(
            UserSession.session_id == session_id
        )
        user_session = db_session.exec(session_query).first()
        current_instance = APPLICATION_STATE["instance_id"]
        if user_session and user_session.instance_id != current_instance:
            logger.warning(
                "Session %s was created by different instance %s",
                session_id,
                user_session.instance_id
            )
            # This creates inconsistent behavior across instances
            APPLICATION_STATE["active_sessions"][session_id] = {
                "created_at": time.time(),
                "requests": 0,
                "instance_id": user_session.instance_id,
                "foreign_session": True
            }
    
    return session_id

@app.get("/", response_class=HTMLResponse)
async def read_root(
    request: Request,
    session: Session = Depends(get_session),  # noqa: B008
    error: str | None = None,
):
    """Display the main page with guestbook entries and instance information."""
    try:
        # Update request counter (in-memory state)
        APPLICATION_STATE["request_counter"] += 1
        
        # Get user session (demonstrates session affinity issues)
        session_id = get_or_create_user_session(request, session)
        
        # Get entries with instance information
        entries = session.exec(select(GuestbookEntry)).all()
        
        # Get secret from DB
        secret_query = select(Config).where(Config.key == "secret_message")
        secret_from_db = session.exec(secret_query).first()
        default_message = "No secret found in DB."
        secret_message = secret_from_db.value if secret_from_db else default_message

        # Get instance information to show scaling issues
        instance_info = {
            "current_instance": APPLICATION_STATE["instance_id"],
            "request_count": APPLICATION_STATE["request_counter"],
            "startup_time": APPLICATION_STATE["startup_time"],
            "active_sessions": len(APPLICATION_STATE["active_sessions"]),
            "session_id": session_id
        }
        
        # Check for other instances in database
        instance_query = select(Config).where(Config.key.like("instance_%"))
        all_instances = session.exec(instance_query).all()
        current_instance_key = f"instance_{APPLICATION_STATE['instance_id']}"
        other_instances = [
            config for config in all_instances
            if config.key != current_instance_key
        ]

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
    except Exception:
        logger.exception("Error loading main page")
        raise HTTPException(
            status_code=SERVER_ERROR_STATUS_CODE,
            detail="Internal server error"
        ) from None
    else:
        return response

@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes probes."""
    return {"status": "healthy", "service": "stateful-guestbook"}

@app.post("/add", response_class=RedirectResponse)
async def add_entry(
    message: str = Form(...),
    request: Request = None,
    session: Session = Depends(get_session),  # noqa: B008
):
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
            "instance_id": APPLICATION_STATE["instance_id"]
        }
        
        # 2. Add to processing queue (in-memory state)
        APPLICATION_STATE["processing_queue"].append({
            "id": cache_key,
            "message": message_data.message,
            "session_id": session_id
        })
        
        # 3. Moderate processing delay (realistic for single instance)
        # Use cryptographically secure random for security compliance
        # Random between 0.1-0.3 seconds
        delay = 0.1 + (secrets.randbits(8) / 255.0) * 0.2
        await asyncio.sleep(delay)  # Use async sleep instead of time.sleep
        
        # 4. Database operations with session affinity
        try:
            # Check if this session has entries from other instances
            existing_entries = session.exec(
                select(GuestbookEntry).where(GuestbookEntry.session_id == session_id)
            ).all()
            
            # Create new entry with instance tracking
            new_entry = GuestbookEntry(
                message=message_data.message,
                instance_id=APPLICATION_STATE["instance_id"],
                session_id=session_id
            )
            session.add(new_entry)
            
            # Update instance stats in database
            stats_key = f"stats_{APPLICATION_STATE['instance_id']}"
            stats_query = select(Config).where(Config.key == stats_key)
            stats_entry = session.exec(stats_query).first()
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
            
            logger.info(
                "Entry added by instance %s: %s...",
                APPLICATION_STATE["instance_id"],
                message_data.message[:50]
            )
            
            # Show session affinity warning if user has entries from multiple instances
            if existing_entries:
                current_instance = APPLICATION_STATE["instance_id"]
                different_instances = {
                    entry.instance_id for entry in existing_entries
                    if entry.instance_id != current_instance
                }
                if different_instances:
                    instances_list = ", ".join(different_instances)
                    warning = (
                        f"WARNING: Your session has entries from multiple "
                        f"instances: {instances_list}. This shows session "
                        f"affinity issues!"
                    )
                    return RedirectResponse(
                        url=f"/?error={warning}",
                        status_code=REDIRECT_STATUS_CODE
                    )
            
            return RedirectResponse(url="/", status_code=REDIRECT_STATUS_CODE)
            
        except Exception:
            # Clean up state on error
            if cache_key in APPLICATION_STATE["cached_data"]:
                del APPLICATION_STATE["cached_data"][cache_key]
            APPLICATION_STATE["processing_queue"] = [
                item for item in APPLICATION_STATE["processing_queue"] 
                if item["id"] != cache_key
            ]
            raise
        
    except ValueError:
        logger.warning("Invalid input received")
        error_message = "Invalid input: Message cannot be empty or too long"
        return RedirectResponse(
            url=f"/?error={error_message}",
            status_code=REDIRECT_STATUS_CODE
        )
        
    except Exception:
        logger.exception("Error adding entry")
        instance_id = APPLICATION_STATE["instance_id"]
        error_message = f"Error occurred on instance {instance_id}"
        return RedirectResponse(
            url=f"/?error={error_message}",
            status_code=REDIRECT_STATUS_CODE
        )

@app.get("/status")
async def get_status(session: Session = Depends(get_session)):  # noqa: B008
    """Show detailed instance status - demonstrates stateful information"""
    try:
        # Get database stats
        all_entries = session.exec(select(GuestbookEntry)).all()
        entries_by_instance = {}
        for entry in all_entries:
            instance = entry.instance_id
            entries_by_instance[instance] = entries_by_instance.get(instance, 0) + 1
        
        # Get all active instances from database
        all_instances_query = select(Config).where(Config.key.like("instance_%"))
        all_instances = session.exec(all_instances_query).all()
        
        return {
            "current_instance": {
                "id": APPLICATION_STATE["instance_id"],
                "startup_time": APPLICATION_STATE["startup_time"],
                "request_count": APPLICATION_STATE["request_counter"],
                "active_sessions": len(APPLICATION_STATE["active_sessions"]),
                "cache_size": len(APPLICATION_STATE["cached_data"]),
                "queue_size": len(APPLICATION_STATE["processing_queue"])
            },
            "database_stats": {
                "total_entries": len(all_entries),
                "entries_by_instance": entries_by_instance
            },
            "all_instances": [
                {
                    "id": config.key.replace("instance_", ""),
                    "startup_time": config.value
                }
                for config in all_instances
            ],
            "scaling_issues": {
                "session_affinity": "Sessions tied to specific instances",
                "in_memory_state": "Cache and queue data lost when pods restart",
                "database_contention": "Multiple pods competing for database access",
                "inconsistent_state": (
                    "Different instances have different in-memory state"
                )
            }
        }
    except Exception:
        logger.exception("Error getting status")
        raise HTTPException(
            status_code=SERVER_ERROR_STATUS_CODE,
            detail="Internal server error"
        ) from None
