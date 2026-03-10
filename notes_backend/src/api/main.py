import hashlib
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from psycopg2.extras import RealDictCursor


openapi_tags = [
    {
        "name": "Health",
        "description": "Service health and readiness operations.",
    },
    {
        "name": "Authentication",
        "description": "Email/password registration and login flows.",
    },
    {
        "name": "Notes",
        "description": "CRUD, autosave, pin/favorite, and search operations for notes.",
    },
    {
        "name": "Tags",
        "description": "Tag management and tag-note association operations.",
    },
    {
        "name": "Settings",
        "description": "User settings such as theme preferences.",
    },
    {
        "name": "Sync",
        "description": "Simple synchronization endpoint for client device sync.",
    },
]


app = FastAPI(
    title="NoteMaster API",
    description=(
        "Retro-themed notes backend with authentication, notes, tags, autosave, "
        "favorites/pinned state, theme settings, and sync APIs."
    ),
    version="1.0.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "*")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


security = HTTPBearer(auto_error=False)


def _db_conn_kwargs() -> dict[str, Any]:
    """Build database connection kwargs from environment variables."""
    db_url = os.getenv("POSTGRES_URL")
    if db_url:
        return {"dsn": db_url}

    return {
        "host": os.getenv("POSTGRES_HOST", "localhost"),
        "port": os.getenv("POSTGRES_PORT", "5432"),
        "user": os.getenv("POSTGRES_USER"),
        "password": os.getenv("POSTGRES_PASSWORD"),
        "dbname": os.getenv("POSTGRES_DB"),
    }


# PUBLIC_INTERFACE
def get_db_connection():
    """Create and return a PostgreSQL database connection."""
    kwargs = _db_conn_kwargs()
    try:
        return psycopg2.connect(**kwargs)  # type: ignore[arg-type]
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connection failed: {exc}",
        ) from exc


def _hash_password(password: str, salt: str) -> str:
    """Generate SHA-256 password hash with a user-specific salt."""
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()


def _utc_now() -> datetime:
    """Return timezone-aware UTC now timestamp."""
    return datetime.now(timezone.utc)


def _ensure_schema() -> None:
    """Ensure all required tables/indexes exist."""
    ddl_statements = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS auth_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS notes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL DEFAULT '',
            content TEXT NOT NULL DEFAULT '',
            pinned BOOLEAN NOT NULL DEFAULT FALSE,
            favorite BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS tags (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(user_id, name)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS note_tags (
            note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
            tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            PRIMARY KEY (note_id, tag_id)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            theme TEXT NOT NULL DEFAULT 'light',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """,
        "CREATE INDEX IF NOT EXISTS idx_notes_user_updated ON notes(user_id, updated_at DESC);",
        "CREATE INDEX IF NOT EXISTS idx_notes_user_flags ON notes(user_id, pinned, favorite);",
        "CREATE INDEX IF NOT EXISTS idx_tags_user_name ON tags(user_id, name);",
    ]

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            for statement in ddl_statements:
                cur.execute(statement)
        conn.commit()


@app.on_event("startup")
def startup_initialize_schema() -> None:
    """Initialize required database schema during API startup."""
    _ensure_schema()


class HealthResponse(BaseModel):
    message: str = Field(..., description="Health status message.")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address.")
    password: str = Field(..., min_length=8, description="User password (minimum 8 characters).")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address.")
    password: str = Field(..., min_length=8, description="User password.")


class AuthResponse(BaseModel):
    token: str = Field(..., description="Bearer auth token.")
    user_id: int = Field(..., description="Authenticated user identifier.")
    email: EmailStr = Field(..., description="Authenticated user email.")


class ThemeUpdateRequest(BaseModel):
    theme: str = Field(..., description="Theme value. Supported: light, dark.")


class ThemeResponse(BaseModel):
    theme: str = Field(..., description="Current user theme setting.")


class TagCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=50, description="Tag display name.")


class TagResponse(BaseModel):
    id: int = Field(..., description="Tag ID.")
    name: str = Field(..., description="Tag name.")


class NoteCreateRequest(BaseModel):
    title: str = Field("", max_length=200, description="Note title.")
    content: str = Field("", description="Note content.")
    pinned: bool = Field(False, description="Whether note is pinned.")
    favorite: bool = Field(False, description="Whether note is favorited.")
    tag_ids: list[int] = Field(default_factory=list, description="Associated tag IDs.")


class NoteUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=200, description="Updated note title.")
    content: Optional[str] = Field(None, description="Updated note content.")
    pinned: Optional[bool] = Field(None, description="Updated pinned state.")
    favorite: Optional[bool] = Field(None, description="Updated favorite state.")
    tag_ids: Optional[list[int]] = Field(None, description="Replacement list of associated tag IDs.")


class NoteResponse(BaseModel):
    id: int = Field(..., description="Note ID.")
    title: str = Field(..., description="Note title.")
    content: str = Field(..., description="Note content.")
    pinned: bool = Field(..., description="Pinned state.")
    favorite: bool = Field(..., description="Favorite state.")
    tags: list[TagResponse] = Field(..., description="Tags associated with the note.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Last update timestamp.")


class SyncResponse(BaseModel):
    notes: list[NoteResponse] = Field(..., description="Notes updated since the provided checkpoint.")
    server_time: datetime = Field(..., description="Server UTC timestamp for checkpointing.")


def _serialize_note(cur, note_row: dict[str, Any]) -> dict[str, Any]:
    """Serialize note row and embed tag list."""
    cur.execute(
        """
        SELECT t.id, t.name
        FROM tags t
        INNER JOIN note_tags nt ON nt.tag_id = t.id
        WHERE nt.note_id = %s
        ORDER BY t.name ASC
        """,
        (note_row["id"],),
    )
    tags = [{"id": row["id"], "name": row["name"]} for row in cur.fetchall()]
    return {
        "id": note_row["id"],
        "title": note_row["title"],
        "content": note_row["content"],
        "pinned": note_row["pinned"],
        "favorite": note_row["favorite"],
        "tags": tags,
        "created_at": note_row["created_at"],
        "updated_at": note_row["updated_at"],
    }


# PUBLIC_INTERFACE
def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Resolve authenticated user from bearer token in Authorization header."""
    token = None
    if credentials:
        token = credentials.credentials
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT u.id, u.email
                FROM auth_tokens a
                INNER JOIN users u ON u.id = a.user_id
                WHERE a.token = %s
                """,
                (token,),
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")
            return user


# PUBLIC_INTERFACE
@app.get(
    "/",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health check",
    description="Simple API health endpoint used by runtime/container checks.",
    operation_id="healthCheck",
)
def health_check() -> HealthResponse:
    """Return service health status."""
    return HealthResponse(message="Healthy")


# PUBLIC_INTERFACE
@app.post(
    "/auth/register",
    response_model=AuthResponse,
    tags=["Authentication"],
    summary="Register new user",
    description="Create a user account with email/password and return an auth token.",
    operation_id="registerUser",
)
def register_user(payload: RegisterRequest) -> AuthResponse:
    """Register a new user and return access token."""
    salt = secrets.token_hex(16)
    password_hash = _hash_password(payload.password, salt)
    token = secrets.token_urlsafe(32)

    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (payload.email,))
            existing = cur.fetchone()
            if existing:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered.")

            cur.execute(
                """
                INSERT INTO users (email, password_salt, password_hash)
                VALUES (%s, %s, %s)
                RETURNING id, email
                """,
                (payload.email, salt, password_hash),
            )
            user = cur.fetchone()

            cur.execute(
                """
                INSERT INTO auth_tokens (token, user_id, created_at)
                VALUES (%s, %s, %s)
                """,
                (token, user["id"], _utc_now()),
            )

            cur.execute(
                """
                INSERT INTO user_settings (user_id, theme, updated_at)
                VALUES (%s, 'light', %s)
                ON CONFLICT (user_id) DO NOTHING
                """,
                (user["id"], _utc_now()),
            )
        conn.commit()

    return AuthResponse(token=token, user_id=user["id"], email=user["email"])


# PUBLIC_INTERFACE
@app.post(
    "/auth/login",
    response_model=AuthResponse,
    tags=["Authentication"],
    summary="Login user",
    description="Authenticate user by email/password and return a fresh auth token.",
    operation_id="loginUser",
)
def login_user(payload: LoginRequest) -> AuthResponse:
    """Login existing user and return access token."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, email, password_salt, password_hash FROM users WHERE email = %s",
                (payload.email,),
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

            attempted_hash = _hash_password(payload.password, user["password_salt"])
            if attempted_hash != user["password_hash"]:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

            token = secrets.token_urlsafe(32)
            cur.execute(
                "INSERT INTO auth_tokens (token, user_id, created_at) VALUES (%s, %s, %s)",
                (token, user["id"], _utc_now()),
            )
        conn.commit()

    return AuthResponse(token=token, user_id=user["id"], email=user["email"])


# PUBLIC_INTERFACE
@app.get(
    "/auth/me",
    tags=["Authentication"],
    summary="Current user profile",
    description="Get currently authenticated user profile.",
    operation_id="getCurrentUser",
)
def me(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Return current authenticated user profile."""
    return {"id": current_user["id"], "email": current_user["email"]}


# PUBLIC_INTERFACE
@app.get(
    "/tags",
    response_model=list[TagResponse],
    tags=["Tags"],
    summary="List tags",
    description="List all tags for current user.",
    operation_id="listTags",
)
def list_tags(current_user: dict[str, Any] = Depends(get_current_user)) -> list[TagResponse]:
    """Return all tags for the authenticated user."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, name FROM tags WHERE user_id = %s ORDER BY name ASC",
                (current_user["id"],),
            )
            rows = cur.fetchall()
    return [TagResponse(id=row["id"], name=row["name"]) for row in rows]


# PUBLIC_INTERFACE
@app.post(
    "/tags",
    response_model=TagResponse,
    tags=["Tags"],
    summary="Create tag",
    description="Create a new tag for the authenticated user.",
    operation_id="createTag",
)
def create_tag(
    payload: TagCreateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> TagResponse:
    """Create and return tag."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO tags (user_id, name)
                VALUES (%s, %s)
                ON CONFLICT (user_id, name)
                DO UPDATE SET name = EXCLUDED.name
                RETURNING id, name
                """,
                (current_user["id"], payload.name.strip()),
            )
            row = cur.fetchone()
        conn.commit()
    return TagResponse(id=row["id"], name=row["name"])


# PUBLIC_INTERFACE
@app.delete(
    "/tags/{tag_id}",
    tags=["Tags"],
    summary="Delete tag",
    description="Delete a user tag and remove associations from notes.",
    operation_id="deleteTag",
)
def delete_tag(tag_id: int, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, bool]:
    """Delete a tag owned by the authenticated user."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM tags WHERE id = %s AND user_id = %s", (tag_id, current_user["id"]))
            deleted = cur.rowcount
        conn.commit()

    if deleted == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag not found.")
    return {"deleted": True}


# PUBLIC_INTERFACE
@app.post(
    "/notes",
    response_model=NoteResponse,
    tags=["Notes"],
    summary="Create note",
    description="Create a note with optional tags, pin/favorite flags.",
    operation_id="createNote",
)
def create_note(
    payload: NoteCreateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> NoteResponse:
    """Create a note and return full note payload."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO notes (user_id, title, content, pinned, favorite, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, title, content, pinned, favorite, created_at, updated_at
                """,
                (
                    current_user["id"],
                    payload.title,
                    payload.content,
                    payload.pinned,
                    payload.favorite,
                    _utc_now(),
                    _utc_now(),
                ),
            )
            note = cur.fetchone()

            if payload.tag_ids:
                for tag_id in payload.tag_ids:
                    cur.execute(
                        """
                        INSERT INTO note_tags (note_id, tag_id)
                        SELECT %s, t.id FROM tags t
                        WHERE t.id = %s AND t.user_id = %s
                        ON CONFLICT DO NOTHING
                        """,
                        (note["id"], tag_id, current_user["id"]),
                    )

            response = _serialize_note(cur, note)
        conn.commit()

    return NoteResponse(**response)


# PUBLIC_INTERFACE
@app.get(
    "/notes",
    response_model=list[NoteResponse],
    tags=["Notes"],
    summary="List notes",
    description=(
        "List notes with optional text search, tag filter, and pinned/favorite filters."
    ),
    operation_id="listNotes",
)
def list_notes(
    q: Optional[str] = Query(default=None, description="Full-text-like search on title/content."),
    tag: Optional[str] = Query(default=None, description="Tag name filter."),
    pinned: Optional[bool] = Query(default=None, description="Pinned filter."),
    favorite: Optional[bool] = Query(default=None, description="Favorite filter."),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[NoteResponse]:
    """List notes for authenticated user with filters."""
    query = """
        SELECT DISTINCT n.id, n.title, n.content, n.pinned, n.favorite, n.created_at, n.updated_at
        FROM notes n
        LEFT JOIN note_tags nt ON nt.note_id = n.id
        LEFT JOIN tags t ON t.id = nt.tag_id
        WHERE n.user_id = %s
    """
    params: list[Any] = [current_user["id"]]

    if q:
        query += " AND (n.title ILIKE %s OR n.content ILIKE %s)"
        params.extend([f"%{q}%", f"%{q}%"])
    if tag:
        query += " AND t.name = %s"
        params.append(tag)
    if pinned is not None:
        query += " AND n.pinned = %s"
        params.append(pinned)
    if favorite is not None:
        query += " AND n.favorite = %s"
        params.append(favorite)

    query += " ORDER BY n.pinned DESC, n.updated_at DESC"

    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, tuple(params))
            notes = cur.fetchall()
            response_rows = [_serialize_note(cur, row) for row in notes]

    return [NoteResponse(**row) for row in response_rows]


# PUBLIC_INTERFACE
@app.get(
    "/notes/{note_id}",
    response_model=NoteResponse,
    tags=["Notes"],
    summary="Get note",
    description="Get single note with tag details.",
    operation_id="getNote",
)
def get_note(note_id: int, current_user: dict[str, Any] = Depends(get_current_user)) -> NoteResponse:
    """Fetch single note by ID."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, title, content, pinned, favorite, created_at, updated_at
                FROM notes
                WHERE id = %s AND user_id = %s
                """,
                (note_id, current_user["id"]),
            )
            note = cur.fetchone()
            if not note:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")
            response = _serialize_note(cur, note)
    return NoteResponse(**response)


# PUBLIC_INTERFACE
@app.put(
    "/notes/{note_id}",
    response_model=NoteResponse,
    tags=["Notes"],
    summary="Update note",
    description="Update note fields and optionally replace note tags.",
    operation_id="updateNote",
)
def update_note(
    note_id: int,
    payload: NoteUpdateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> NoteResponse:
    """Update existing note and return updated payload."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id FROM notes WHERE id = %s AND user_id = %s",
                (note_id, current_user["id"]),
            )
            exists = cur.fetchone()
            if not exists:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")

            fields: list[str] = []
            values: list[Any] = []

            if payload.title is not None:
                fields.append("title = %s")
                values.append(payload.title)
            if payload.content is not None:
                fields.append("content = %s")
                values.append(payload.content)
            if payload.pinned is not None:
                fields.append("pinned = %s")
                values.append(payload.pinned)
            if payload.favorite is not None:
                fields.append("favorite = %s")
                values.append(payload.favorite)

            fields.append("updated_at = %s")
            values.append(_utc_now())

            cur.execute(
                f"""
                UPDATE notes
                SET {", ".join(fields)}
                WHERE id = %s AND user_id = %s
                RETURNING id, title, content, pinned, favorite, created_at, updated_at
                """,
                (*values, note_id, current_user["id"]),
            )
            updated = cur.fetchone()

            if payload.tag_ids is not None:
                cur.execute("DELETE FROM note_tags WHERE note_id = %s", (note_id,))
                for tag_id in payload.tag_ids:
                    cur.execute(
                        """
                        INSERT INTO note_tags (note_id, tag_id)
                        SELECT %s, t.id FROM tags t
                        WHERE t.id = %s AND t.user_id = %s
                        ON CONFLICT DO NOTHING
                        """,
                        (note_id, tag_id, current_user["id"]),
                    )

            response = _serialize_note(cur, updated)
        conn.commit()

    return NoteResponse(**response)


# PUBLIC_INTERFACE
@app.post(
    "/notes/{note_id}/autosave",
    response_model=NoteResponse,
    tags=["Notes"],
    summary="Autosave note",
    description="Convenience endpoint that updates note content/title during autosave.",
    operation_id="autosaveNote",
)
def autosave_note(
    note_id: int,
    payload: NoteUpdateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> NoteResponse:
    """Autosave note by delegating to update endpoint logic."""
    return update_note(note_id=note_id, payload=payload, current_user=current_user)


# PUBLIC_INTERFACE
@app.delete(
    "/notes/{note_id}",
    tags=["Notes"],
    summary="Delete note",
    description="Delete a note owned by the authenticated user.",
    operation_id="deleteNote",
)
def delete_note(note_id: int, current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, bool]:
    """Delete note by ID."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, current_user["id"]))
            deleted = cur.rowcount
        conn.commit()

    if deleted == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")
    return {"deleted": True}


# PUBLIC_INTERFACE
@app.get(
    "/settings/theme",
    response_model=ThemeResponse,
    tags=["Settings"],
    summary="Get theme setting",
    description="Get current user's selected theme.",
    operation_id="getThemeSetting",
)
def get_theme(current_user: dict[str, Any] = Depends(get_current_user)) -> ThemeResponse:
    """Return user theme setting."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT theme FROM user_settings WHERE user_id = %s", (current_user["id"],))
            row = cur.fetchone()
            if not row:
                return ThemeResponse(theme="light")
    return ThemeResponse(theme=row["theme"])


# PUBLIC_INTERFACE
@app.put(
    "/settings/theme",
    response_model=ThemeResponse,
    tags=["Settings"],
    summary="Update theme setting",
    description="Update current user's theme setting (light/dark).",
    operation_id="updateThemeSetting",
)
def update_theme(
    payload: ThemeUpdateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ThemeResponse:
    """Update and return user theme setting."""
    normalized = payload.theme.strip().lower()
    if normalized not in {"light", "dark"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Theme must be 'light' or 'dark'.")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO user_settings (user_id, theme, updated_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id)
                DO UPDATE SET theme = EXCLUDED.theme, updated_at = EXCLUDED.updated_at
                """,
                (current_user["id"], normalized, _utc_now()),
            )
        conn.commit()

    return ThemeResponse(theme=normalized)


# PUBLIC_INTERFACE
@app.get(
    "/sync",
    response_model=SyncResponse,
    tags=["Sync"],
    summary="Sync notes",
    description="Return notes updated since the provided ISO timestamp for device synchronization.",
    operation_id="syncNotes",
)
def sync_notes(
    since: Optional[datetime] = Query(
        default=None,
        description="Only return notes updated after this ISO8601 timestamp.",
    ),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> SyncResponse:
    """Return changed notes for synchronization."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if since is None:
                cur.execute(
                    """
                    SELECT id, title, content, pinned, favorite, created_at, updated_at
                    FROM notes
                    WHERE user_id = %s
                    ORDER BY updated_at DESC
                    """,
                    (current_user["id"],),
                )
            else:
                cur.execute(
                    """
                    SELECT id, title, content, pinned, favorite, created_at, updated_at
                    FROM notes
                    WHERE user_id = %s AND updated_at > %s
                    ORDER BY updated_at DESC
                    """,
                    (current_user["id"], since),
                )
            notes = cur.fetchall()
            payload = [_serialize_note(cur, row) for row in notes]

    return SyncResponse(
        notes=[NoteResponse(**row) for row in payload],
        server_time=_utc_now(),
    )
