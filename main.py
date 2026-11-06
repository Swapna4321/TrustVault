
import os
import uuid
import psycopg

from pathlib import Path
from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    UploadFile,
    File,
    Form
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from pwdlib import PasswordHash
from jose import jwt, JWTError
from datetime import date, datetime, timedelta, timezone


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

load_dotenv()

app = FastAPI(title="TrustVault API")
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_hash = PasswordHash.recommended()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ==========================================
# DOCUMENT STORAGE CONFIGURATION
# ==========================================

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf", ".doc", ".docx",
    ".txt", ".png", ".jpg", ".jpeg"
}


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_connection():
    settings = {
        "host": os.getenv("DB_HOST"),
        "dbname": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
        "port": os.getenv("DB_PORT")
    }
    missing = [key for key, value in settings.items() if not value]
    if missing:
        raise RuntimeError(
            f"Missing database configuration: {', '.join(missing)}"
        )

    settings["port"] = int(settings["port"])
    return psycopg.connect(
        **settings
    )


def get_signing_key():
    if not SECRET_KEY or len(SECRET_KEY) < 32:
        raise RuntimeError("SECRET_KEY must contain at least 32 characters")
    return SECRET_KEY


# ==========================================
# REQUEST MODEL
# ==========================================

class RegisterRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str


# ==========================================
# PASSWORD SECURITY
# ==========================================

def hash_password(password):
    return password_hash.hash(password)


def verify_password(password, hashed_password):
    return password_hash.verify(password, hashed_password)


# ==========================================
# JWT TOKEN CREATION
# ==========================================

def create_access_token(user_id, role):
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire
    }

    return jwt.encode(
        payload,
        get_signing_key(),
        algorithm=ALGORITHM
    )


# ==========================================
# CURRENT USER AUTHENTICATION
# ==========================================

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(
            token,
            get_signing_key(),
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("sub")
        role = payload.get("role")

        if user_id is None or role is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, full_name, email, role, is_active
                    FROM users
                    WHERE id = %s
                    """,
                    (int(user_id),)
                )

                user = cur.fetchone()

        if not user or not user[4] or user[3] != role:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

        return {
            "id": user[0],
            "full_name": user[1],
            "email": user[2],
            "role": user[3],
            "is_active": user[4]
        }

    except (JWTError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )


# ==========================================
# ROLE-BASED ACCESS CONTROL
# ==========================================

def require_roles(*allowed_roles):
    def role_checker(
        current_user: dict = Depends(get_current_user)
    ):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to access this resource"
            )

        return current_user

    return role_checker


# ==========================================
# AUDIT LOGGING
# ==========================================

def insert_audit_log(cur, user_id, document_id, action, details, success):
    cur.execute(
        """
        INSERT INTO audit_logs
        (user_id, document_id, action, details, success)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (user_id, document_id, action, details, success)
    )


def add_audit_log(
    user_id,
    document_id,
    action,
    details,
    success
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            insert_audit_log(
                cur, user_id, document_id, action, details, success
            )


# ==========================================
# HOME AND HEALTH
# ==========================================

@app.get("/")
def home():
    return {
        "message": "Welcome to TrustVault"
    }


@app.get("/health")
def health():
    return {
        "status": "TrustVault is running"
    }


@app.get("/app", include_in_schema=False)
def app_home():
    return FileResponse(STATIC_DIR / "index.html")


# ==========================================
# USER REGISTRATION
# ==========================================

@app.post("/register")
def register(data: RegisterRequest):

    if len(data.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 8 characters"
        )

    hashed_password = hash_password(data.password)

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users
                    (full_name, email, password_hash, role)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, full_name, email, role
                    """,
                    (
                        data.full_name,
                        data.email,
                        hashed_password,
                        "viewer"
                    )
                )

                user = cur.fetchone()
                insert_audit_log(
                    cur, user[0], None, "REGISTER",
                    "Viewer account registered", True
                )

        return {
            "message": "Registration successful",
            "user": {
                "id": user[0],
                "full_name": user[1],
                "email": user[2],
                "role": user[3]
            }
        }

    except psycopg.errors.UniqueViolation:
        add_audit_log(None, None, "REGISTER", "Duplicate email rejected", False)
        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )


# ==========================================
# USER LOGIN
# ==========================================

@app.post("/login")
def login(data: OAuth2PasswordRequestForm = Depends()):

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, full_name, email, password_hash, role, is_active
                FROM users
                WHERE email = %s
                """,
                (data.username,)
            )

            user = cur.fetchone()

    if not user or not user[5] or not verify_password(data.password, user[3]):
        add_audit_log(
            user[0] if user else None,
            None,
            "LOGIN",
            "Sign-in rejected",
            False
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    add_audit_log(user[0], None, "LOGIN", "Sign-in successful", True)
    token = create_access_token(user[0], user[4])

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# ==========================================
# CURRENT USER PROFILE
# ==========================================

@app.get("/users/me")
def read_current_user(
    current_user: dict = Depends(get_current_user)
):
    return {
        "message": "Authenticated successfully",
        "user": current_user
    }


class UserStatusUpdate(BaseModel):
    is_active: bool


@app.patch("/admin/users/{user_id}/status")
def update_user_status(
    user_id: int,
    request: UserStatusUpdate,
    current_user: dict = Depends(require_roles("admin"))
):
    if user_id == current_user["id"] and not request.is_active:
        raise HTTPException(
            status_code=400,
            detail="An administrator cannot deactivate their own account"
        )

    action = "USER_ACTIVATED" if request.is_active else "USER_DEACTIVATED"
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, is_active FROM users WHERE id = %s",
                (user_id,)
            )
            user = cur.fetchone()

            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            cur.execute(
                "UPDATE users SET is_active = %s WHERE id = %s",
                (request.is_active, user_id)
            )
            insert_audit_log(
                cur, current_user["id"], None, action,
                f"User ID {user_id} account status changed", True
            )
    return {"user_id": user_id, "is_active": request.is_active}


# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.get("/admin/dashboard")
def admin_dashboard(
    current_user: dict = Depends(require_roles("admin"))
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) AS total_users,
                    COUNT(*) FILTER (WHERE is_active) AS active_users,
                    COUNT(*) FILTER (WHERE NOT is_active) AS inactive_users,
                    COUNT(*) FILTER (WHERE role = 'owner') AS owners,
                    COUNT(*) FILTER (WHERE role = 'viewer') AS viewers,
                    COUNT(*) FILTER (WHERE role = 'admin') AS admins
                FROM users
                """
            )
            stats = cur.fetchone()

            cur.execute(
                """
                SELECT
                    u.full_name,
                    u.email,
                    a.document_id,
                    a.action,
                    a.details,
                    a.success,
                    a.created_at
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.created_at DESC
                LIMIT 8
                """
            )
            recent_activity = cur.fetchall()

    return {
        "message": "Welcome to Admin Dashboard",
        "user": current_user,
        "stats": {
            "total_users": stats[0],
            "active_users": stats[1],
            "inactive_users": stats[2],
            "owners": stats[3],
            "viewers": stats[4],
            "admins": stats[5]
        },
        "recent_activity": [
            {
                "user_name": activity[0],
                "user_email": activity[1],
                "document_id": activity[2],
                "action": activity[3],
                "details": activity[4],
                "success": activity[5],
                "created_at": activity[6]
            }
            for activity in recent_activity
        ]
    }


# ==========================================
# OWNER DASHBOARD
# ==========================================

@app.get("/owner/dashboard")
def owner_dashboard(
    current_user: dict = Depends(require_roles("owner"))
):
    return {
        "message": "Welcome to Owner Dashboard",
        "user": current_user
    }


# ==========================================
# VIEWER DASHBOARD
# ==========================================

@app.get("/viewer/dashboard")
def viewer_dashboard(
    current_user: dict = Depends(require_roles("viewer"))
):
    return {
        "message": "Welcome to Viewer Dashboard",
        "user": current_user
    }


# ==========================================
# COMMON DASHBOARD
# ==========================================

@app.get("/dashboard")
def common_dashboard(
    current_user: dict = Depends(
        require_roles("admin", "owner", "viewer")
    )
):
    return {
        "message": "Access granted to TrustVault Dashboard",
        "user": current_user
    }


# ==========================================
# SECURE DOCUMENT UPLOAD
# ==========================================

@app.post("/documents/upload")
def upload_document(
    category: str = Form(...),
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles("owner"))
):

    original_name = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    extension = Path(original_name).suffix.lower()

    if not original_name or extension not in ALLOWED_EXTENSIONS:
        add_audit_log(
            current_user["id"], None, "UPLOAD",
            "Upload rejected: unsupported file type", False
        )
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type"
        )

    if not category.strip():
        add_audit_log(
            current_user["id"], None, "UPLOAD",
            "Upload rejected: empty category", False
        )
        raise HTTPException(
            status_code=400,
            detail="Category cannot be empty"
        )

    content = file.file.read(MAX_FILE_SIZE + 1)

    if not content:
        add_audit_log(
            current_user["id"], None, "UPLOAD",
            f"Upload rejected: empty file {original_name}", False
        )
        raise HTTPException(
            status_code=400,
            detail="Empty file is not allowed"
        )

    if len(content) > MAX_FILE_SIZE:
        add_audit_log(
            current_user["id"], None, "UPLOAD",
            f"Upload rejected: file too large ({original_name})", False
        )
        raise HTTPException(
            status_code=413,
            detail="File exceeds 5 MB limit"
        )

    stored_name = f"{uuid.uuid4().hex}{extension}"
    file_path = UPLOAD_DIR / stored_name

    try:
        with file_path.open("xb") as destination:
            destination.write(content)

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO documents
                    (name, category, owner_id, storage_path)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, name, category, owner_id, created_at
                    """,
                    (
                        original_name,
                        category.strip(),
                        current_user["id"],
                        str(file_path)
                    )
                )

                document = cur.fetchone()

                cur.execute(
                    """
                    INSERT INTO audit_logs
                    (user_id, document_id, action, details, success)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        current_user["id"],
                        document[0],
                        "UPLOAD",
                        f"Uploaded document: {original_name}",
                        True
                    )
                )

        return {
            "message": "Document uploaded successfully",
            "document": {
                "id": document[0],
                "name": document[1],
                "category": document[2],
                "owner_id": document[3],
                "created_at": document[4]
            }
        }

    except Exception:
        if file_path.exists():
            file_path.unlink()
        raise

    finally:
        file.file.close()


# ==========================================
# VIEW ACCESSIBLE DOCUMENTS
# ==========================================

@app.get("/documents")
def list_documents(
    current_user: dict = Depends(
        require_roles("admin", "owner", "viewer")
    )
):

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                  SELECT d.id, d.name, d.category, d.owner_id,
                      d.created_at, u.full_name,
                      CASE WHEN d.owner_id = %s THEN 'OWNER'
                        ELSE mine.access_type END
                FROM documents d
                  JOIN users u ON u.id = d.owner_id
                  LEFT JOIN permissions mine
                      ON mine.document_id = d.id AND mine.user_id = %s
                WHERE d.owner_id = %s
                OR EXISTS (
                    SELECT 1
                    FROM permissions p
                    WHERE p.document_id = d.id
                    AND p.user_id = %s
                    AND p.access_type IN ('READ', 'EDIT')
                )
                ORDER BY d.created_at DESC
                """,
                (
                    current_user["id"],
                    current_user["id"],
                    current_user["id"],
                    current_user["id"]
                )
            )

            documents = cur.fetchall()

    return {
        "total_documents": len(documents),
        "documents": [
            {
                "id": doc[0],
                "name": doc[1],
                "category": doc[2],
                "owner_id": doc[3],
                "created_at": doc[4],
                "owner_name": doc[5],
                "access_type": doc[6]
            }
            for doc in documents
        ]
    }


# ==========================================
# SEARCH DOCUMENTS
# ==========================================

@app.get("/documents/search")
def search_documents(
    name: str = "",
    category: str = "",
    owner: str = "",
    date_from: date | None = None,
    date_to: date | None = None,
    current_user: dict = Depends(
        require_roles("admin", "owner", "viewer")
    )
):
    if date_from and date_to and date_to < date_from:
        raise HTTPException(
            status_code=400,
            detail="End date must be on or after start date"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                  SELECT d.id, d.name, d.category, d.owner_id,
                      d.created_at, u.full_name,
                      CASE WHEN d.owner_id = %s THEN 'OWNER'
                        ELSE mine.access_type END
                FROM documents d
                  JOIN users u ON u.id = d.owner_id
                  LEFT JOIN permissions mine
                      ON mine.document_id = d.id AND mine.user_id = %s
                WHERE (
                    d.owner_id = %s
                    OR EXISTS (
                        SELECT 1
                        FROM permissions p
                        WHERE p.document_id = d.id
                        AND p.user_id = %s
                        AND p.access_type IN ('READ', 'EDIT')
                    )
                )
                AND (%s = '' OR d.name ILIKE %s)
                AND (%s = '' OR d.category ILIKE %s)
                AND (%s = '' OR u.full_name ILIKE %s OR u.email ILIKE %s)
                AND (%s::date IS NULL OR d.created_at::date >= %s::date)
                AND (%s::date IS NULL OR d.created_at::date <= %s::date)
                ORDER BY d.created_at DESC
                """,
                (
                    current_user["id"],
                    current_user["id"],
                    current_user["id"],
                    current_user["id"],
                    name, f"%{name}%",
                    category, f"%{category}%",
                    owner, f"%{owner}%", f"%{owner}%",
                    date_from, date_from,
                    date_to, date_to
                )
            )

            documents = cur.fetchall()

    return {
        "total_results": len(documents),
        "documents": [
            {
                "id": doc[0],
                "name": doc[1],
                "category": doc[2],
                "owner_id": doc[3],
                "created_at": doc[4],
                "owner_name": doc[5],
                "access_type": doc[6]
            }
            for doc in documents
        ]
    }


# ==========================================
# SECURE DOCUMENT DOWNLOAD
# ==========================================

@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    current_user: dict = Depends(
        require_roles("admin", "owner", "viewer")
    )
):

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, owner_id, storage_path
                FROM documents
                WHERE id = %s
                """,
                (document_id,)
            )

            document = cur.fetchone()

    if not document:
        add_audit_log(
            current_user["id"],
            None,
            "DOWNLOAD",
            f"Denied download attempt for document ID {document_id}: document not found",
            False
        )

        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    allowed = document[2] == current_user["id"]

    if not allowed:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id
                    FROM permissions
                    WHERE document_id = %s
                    AND user_id = %s
                    AND access_type IN ('READ', 'EDIT')
                    """,
                    (
                        document_id,
                        current_user["id"]
                    )
                )

                permission = cur.fetchone()

        if permission:
            allowed = True

    if not allowed:
        add_audit_log(
            current_user["id"],
            document_id,
            "DOWNLOAD",
            f"Denied download attempt for document: {document[1]}",
            False
        )

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to download this document"
        )

    file_path = Path(document[3]).resolve()

    if not file_path.is_relative_to(UPLOAD_DIR.resolve()) or not file_path.is_file():
        add_audit_log(
            current_user["id"], document_id, "DOWNLOAD",
            "Download rejected: stored file is missing or outside storage", False
        )
        raise HTTPException(
            status_code=404,
            detail="Stored document file not found"
        )

    add_audit_log(
        current_user["id"],
        document_id,
        "DOWNLOAD",
        f"Downloaded document: {document[1]}",
        True
    )

    return FileResponse(
        path=str(file_path),
        filename=document[1],
        media_type="application/octet-stream"
    )


# ==========================================
# DOCUMENT PERMISSIONS
# ==========================================

class PermissionRequest(BaseModel):
    user_email: EmailStr
    access_type: str


@app.get("/documents/{document_id}/permissions")
def list_document_permissions(
    document_id: int,
    current_user: dict = Depends(require_roles("owner"))
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM documents WHERE id = %s AND owner_id = %s",
                (document_id, current_user["id"])
            )
            if not cur.fetchone():
                raise HTTPException(
                    status_code=404,
                    detail="Document not found or you are not the owner"
                )

            cur.execute(
                """
                SELECT p.user_id, u.full_name, u.email,
                       p.access_type, p.granted_at
                FROM permissions p
                JOIN users u ON u.id = p.user_id
                WHERE p.document_id = %s
                ORDER BY u.full_name
                """,
                (document_id,)
            )
            permissions = cur.fetchall()

    return {
        "permissions": [
            {
                "user_id": permission[0],
                "full_name": permission[1],
                "email": permission[2],
                "access_type": permission[3],
                "granted_at": permission[4]
            }
            for permission in permissions
        ]
    }


@app.post("/documents/{document_id}/permissions")
def grant_permission(
    document_id: int,
    request: PermissionRequest,
    current_user: dict = Depends(require_roles("owner"))
):
    if request.access_type.upper() not in ["READ", "EDIT"]:
        add_audit_log(
            current_user["id"], document_id, "PERMISSION_GRANTED",
            "Permission grant rejected: invalid access type", False
        )
        raise HTTPException(
            status_code=400,
            detail="Access type must be READ or EDIT"
        )

    with get_connection() as conn:
        with conn.cursor() as cur:

            # Check document ownership
            cur.execute(
                """
                SELECT id FROM documents
                WHERE id = %s AND owner_id = %s
                """,
                (document_id, current_user["id"])
            )

            if not cur.fetchone():
                add_audit_log(
                    current_user["id"], document_id, "PERMISSION_GRANTED",
                    "Permission grant rejected: requester is not the owner",
                    False
                )
                raise HTTPException(
                    status_code=404,
                    detail="Document not found or you are not the owner"
                )

            # Resolve the named recipient and reject inactive accounts.
            cur.execute(
                """
                SELECT id, full_name, email
                FROM users
                WHERE lower(email) = lower(%s) AND is_active = TRUE
                """,
                (str(request.user_email),)
            )

            recipient = cur.fetchone()
            if not recipient:
                add_audit_log(
                    current_user["id"], document_id, "PERMISSION_GRANTED",
                    "Permission grant rejected: recipient not found or inactive",
                    False
                )
                raise HTTPException(
                    status_code=404,
                    detail="User not found"
                )

            # Grant or update permission
            cur.execute(
                """
                INSERT INTO permissions
                (document_id, user_id, access_type, granted_by)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (document_id, user_id)
                DO UPDATE SET
                    access_type = EXCLUDED.access_type,
                    granted_by = EXCLUDED.granted_by,
                    granted_at = CURRENT_TIMESTAMP
                """,
                (
                    document_id,
                    recipient[0],
                    request.access_type.upper(),
                    current_user["id"]
                )
            )
            insert_audit_log(
                cur, current_user["id"], document_id, "PERMISSION_GRANTED",
                f"{request.access_type.upper()} permission granted to {recipient[2]}",
                True
            )

    return {
        "message": "Permission granted successfully",
        "document_id": document_id,
        "user_id": recipient[0],
        "user_name": recipient[1],
        "user_email": recipient[2],
        "access_type": request.access_type.upper()
    }


@app.delete("/documents/{document_id}/permissions/{user_id}")
def revoke_permission(
    document_id: int,
    user_id: int,
    current_user: dict = Depends(require_roles("owner"))
):
    with get_connection() as conn:
        with conn.cursor() as cur:

            # Check document ownership
            cur.execute(
                """
                SELECT id FROM documents
                WHERE id = %s AND owner_id = %s
                """,
                (document_id, current_user["id"])
            )

            if not cur.fetchone():
                add_audit_log(
                    current_user["id"], document_id, "PERMISSION_REVOKED",
                    "Permission revocation rejected: requester is not the owner",
                    False
                )
                raise HTTPException(
                    status_code=404,
                    detail="Document not found or you are not the owner"
                )

            # Revoke permission
            cur.execute(
                """
                DELETE FROM permissions
                WHERE document_id = %s AND user_id = %s
                RETURNING id
                """,
                (document_id, user_id)
            )

            deleted = cur.fetchone()

            if not deleted:
                add_audit_log(
                    current_user["id"], document_id, "PERMISSION_REVOKED",
                    f"Permission revocation rejected for user {user_id}",
                    False
                )
                raise HTTPException(
                    status_code=404,
                    detail="Permission not found"
                )
            insert_audit_log(
                cur, current_user["id"], document_id, "PERMISSION_REVOKED",
                f"Permission revoked from user {user_id}", True
            )

    return {
        "message": "Permission revoked successfully",
        "document_id": document_id,
        "user_id": user_id
    }


# ==========================================
# UPDATE DOCUMENT
# ==========================================

@app.put("/documents/{document_id}")
def update_document(
    document_id: int,
    new_name: str = Form(...),
    new_category: str = Form(...),
    current_user: dict = Depends(require_roles("admin", "owner", "viewer"))
):
    with get_connection() as conn:
        with conn.cursor() as cur:

            # Check whether document exists
            cur.execute(
                "SELECT owner_id FROM documents WHERE id = %s",
                (document_id,)
            )

            document = cur.fetchone()

            if not document:
                raise HTTPException(
                    status_code=404,
                    detail="Document not found"
                )

            owner_id = document[0]

            # Check EDIT permission
            allowed = current_user["id"] == owner_id

            if not allowed:
                cur.execute(
                    """
                    SELECT access_type FROM permissions
                    WHERE document_id = %s AND user_id = %s
                    """,
                    (document_id, current_user["id"])
                )

                permission = cur.fetchone()

                if permission and permission[0] == "EDIT":
                    allowed = True

            if not allowed:
                add_audit_log(
                    current_user["id"],
                    document_id,
                    "UPDATE",
                    "Document update denied",
                    False
                )
                raise HTTPException(
                    status_code=403,
                    detail="You do not have EDIT permission"
                )

            # Update document details
            cur.execute(
                """
                UPDATE documents
                SET name = %s,
                    category = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (new_name, new_category, document_id)
            )
            insert_audit_log(
                cur, current_user["id"], document_id, "UPDATE",
                "Document details updated successfully", True
            )

    return {
        "message": "Document updated successfully",
        "document_id": document_id,
        "new_name": new_name,
        "new_category": new_category
    }


# ==========================================
# ADMIN - VIEW AUDIT LOGS
# ==========================================

@app.get("/admin/audit-logs")
def view_audit_logs(
    current_user: dict = Depends(require_roles("admin"))
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    a.id,
                    u.full_name,
                    u.email,
                    a.document_id,
                    a.action,
                    a.details,
                    a.success,
                    a.created_at,
                    a.prev_hash,
                    a.entry_hash
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.created_at DESC
                """
            )

            logs = cur.fetchall()

    return {
        "total_logs": len(logs),
        "audit_logs": [
            {
                "log_id": log[0],
                "user_name": log[1],
                "user_email": log[2],
                "document_id": log[3],
                "action": log[4],
                "details": log[5],
                "success": log[6],
                "created_at": log[7],
                "prev_hash": log[8].strip(),
                "entry_hash": log[9].strip()
            }
            for log in logs
        ]
    }


@app.get("/admin/users")
def list_users(
    current_user: dict = Depends(require_roles("admin"))
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, full_name, email, role, is_active, created_at
                FROM users
                ORDER BY full_name
                """
            )
            users = cur.fetchall()

    add_audit_log(
        current_user["id"], None, "USER_DIRECTORY_VIEWED",
        "Administrator viewed account status", True
    )
    return {
        "users": [
            {
                "id": user[0],
                "full_name": user[1],
                "email": user[2],
                "role": user[3],
                "is_active": user[4],
                "created_at": user[5]
            }
            for user in users
        ]
    }


# ==========================================
# DELETE DOCUMENT
# ==========================================

@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    current_user: dict = Depends(require_roles("owner"))
):
    file_path = None
    document_name = None

    with get_connection() as conn:
        with conn.cursor() as cur:

            # Check document ownership
            cur.execute(
                """
                SELECT name, storage_path
                FROM documents
                WHERE id = %s AND owner_id = %s
                """,
                (document_id, current_user["id"])
            )

            document = cur.fetchone()

            if not document:
                add_audit_log(
                    current_user["id"], document_id, "DELETE",
                    "Document deletion rejected: not found or not owned by requester",
                    False
                )
                raise HTTPException(
                    status_code=404,
                    detail="Document not found or you are not the owner"
                )

            document_name = document[0]
            file_path = Path(document[1]).resolve()

            # Delete document record
            cur.execute(
                "DELETE FROM documents WHERE id = %s",
                (document_id,)
            )

            # Record deletion without breaking audit history
            cur.execute(
                """
                INSERT INTO audit_logs
                (user_id, document_id, action, details, success)
                VALUES (%s, NULL, %s, %s, %s)
                """,
                (
                    current_user["id"],
                    "DELETE",
                    f"Document ID {document_id} ({document_name}) deleted",
                    True
                )
            )

    # Delete physical file after database transaction
    upload_directory = UPLOAD_DIR.resolve()

    if file_path.is_relative_to(upload_directory) and file_path.is_file():
        file_path.unlink()

    return {
        "message": "Document deleted successfully",
        "document_id": document_id,
        "document_name": document_name
    }


# ==========================================
# REPLACE DOCUMENT FILE
# ==========================================

@app.put("/documents/{document_id}/file")
def replace_document_file(
    document_id: int,
    file: UploadFile = File(...),
    current_user: dict = Depends(require_roles("admin", "owner", "viewer"))
):
    # Validate file extension
    original_name = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    extension = Path(original_name).suffix.lower()

    if not original_name or extension not in ALLOWED_EXTENSIONS:
        add_audit_log(
            current_user["id"], document_id, "FILE_REPLACED",
            "File replacement rejected: unsupported file type", False
        )
        raise HTTPException(
            status_code=400,
            detail="File type not allowed"
        )

    # Read and validate file size
    content = file.file.read(MAX_FILE_SIZE + 1)

    if not content:
        add_audit_log(
            current_user["id"], document_id, "FILE_REPLACED",
            "File replacement rejected: empty file", False
        )
        raise HTTPException(
            status_code=400,
            detail="File cannot be empty"
        )

    if len(content) > MAX_FILE_SIZE:
        add_audit_log(
            current_user["id"], document_id, "FILE_REPLACED",
            "File replacement rejected: file too large", False
        )
        raise HTTPException(
            status_code=400,
            detail="File size exceeds 5 MB"
        )

    new_filename = f"{uuid.uuid4()}{extension}"
    new_path = UPLOAD_DIR / new_filename

    old_path = None

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:

                # Get document
                cur.execute(
                    """
                    SELECT owner_id, storage_path
                    FROM documents
                    WHERE id = %s
                    """,
                    (document_id,)
                )

                document = cur.fetchone()

                if not document:
                    add_audit_log(
                        current_user["id"], document_id, "FILE_REPLACED",
                        "File replacement rejected: document not found", False
                    )
                    raise HTTPException(
                        status_code=404,
                        detail="Document not found"
                    )

                owner_id, old_storage_path = document

                # Check EDIT permission
                allowed = current_user["id"] == owner_id

                if not allowed:
                    cur.execute(
                        """
                        SELECT access_type
                        FROM permissions
                        WHERE document_id = %s AND user_id = %s
                        """,
                        (document_id, current_user["id"])
                    )

                    permission = cur.fetchone()

                    if permission and permission[0] == "EDIT":
                        allowed = True

                if not allowed:
                    add_audit_log(
                        current_user["id"], document_id, "FILE_REPLACED",
                        "File replacement rejected: missing EDIT permission",
                        False
                    )
                    raise HTTPException(
                        status_code=403,
                        detail="You do not have EDIT permission"
                    )

                # Save replacement file
                with open(new_path, "wb") as f:
                    f.write(content)

                # Update database
                cur.execute(
                    """
                    UPDATE documents
                    SET storage_path = %s,
                        name = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    """,
                    (str(new_path), file.filename, document_id)
                )

                # Record audit log
                cur.execute(
                    """
                    INSERT INTO audit_logs
                    (user_id, document_id, action, details, success)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        current_user["id"],
                        document_id,
                        "FILE_REPLACED",
                        "Document file replaced successfully",
                        True
                    )
                )

                old_path = Path(old_storage_path).resolve()

        # Delete old file after database update succeeds
        upload_directory = UPLOAD_DIR.resolve()

        if (
            old_path
            and old_path.is_relative_to(upload_directory)
            and old_path.is_file()
            and old_path != new_path.resolve()
        ):
            old_path.unlink()

        return {
            "message": "Document file replaced successfully",
            "document_id": document_id,
            "new_filename": file.filename
        }

    except Exception:
        if new_path.exists():
            new_path.unlink()
        raise

    finally:
        file.file.close()
