from datetime import datetime, timedelta
import jwt
import hashlib
import secrets
import logging
from typing import Dict, Optional, List
import re
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    SERVICE_ACCOUNT = "service_account"

class AuthenticationMethod(Enum):
    PASSWORD = "password"
    CERTIFICATE = "certificate"
    SSO = "sso"

@dataclass
class UserProfile:
    user_id: str
    username: str
    email: str
    role: UserRole
    department: str
    auth_methods: List[AuthenticationMethod]
    last_login: Optional[datetime] = None
    failed_attempts: int = 0
    is_locked: bool = False

class IAMService:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.users: Dict[str, UserProfile] = {}
        self.sessions: Dict[str, Dict] = {}
        self.password_hash_cache: Dict[str, str] = {}
        
    def _generate_salt(self) -> str:
        return secrets.token_hex(16)
    
    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # Number of iterations
        ).hex()
    
    def create_user(self, username: str, email: str, password: str, 
                   role: UserRole, department: str) -> UserProfile:
        """Create a new user with basic authentication setup."""
        if not self._validate_email(email):
            raise ValueError("Invalid email format")
        
        if not self._validate_password_strength(password):
            raise ValueError("Password doesn't meet security requirements")
            
        user_id = secrets.token_urlsafe(16)
        salt = self._generate_salt()
        hashed_password = self._hash_password(password, salt)
        
        user = UserProfile(
            user_id=user_id,
            username=username,
            email=email,
            role=role,
            department=department,
            auth_methods=[AuthenticationMethod.PASSWORD]
        )
        
        self.users[user_id] = user
        self.password_hash_cache[user_id] = f"{salt}:{hashed_password}"
        
        logger.info(f"Created new user: {username} with role {role}")
        return user
    
    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return a JWT token if successful."""
        user = self._get_user_by_username(username)
        if not user:
            logger.warning(f"Authentication failed: User {username} not found")
            return None
            
        if user.is_locked:
            logger.warning(f"Authentication attempted for locked account: {username}")
            raise ValueError("Account is locked. Please contact administrator.")
            
        if self._verify_password(user.user_id, password):
            token = self._generate_jwt_token(user)
            user.last_login = datetime.now()
            user.failed_attempts = 0
            logger.info(f"Successful authentication for user: {username}")
            return token
        else:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.is_locked = True
                logger.warning(f"Account locked for user: {username}")
                raise ValueError("Account locked due to multiple failed attempts")
            
            logger.warning(f"Failed authentication attempt for user: {username}")
            return None
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _validate_password_strength(self, password: str) -> bool:
        """
        Validate password strength:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character
        """
        if len(password) < 12:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True
    
    def _verify_password(self, user_id: str, password: str) -> bool:
        """Verify password against stored hash."""
        stored = self.password_hash_cache.get(user_id)
        if not stored:
            return False
        
        salt, stored_hash = stored.split(':')
        computed_hash = self._hash_password(password, salt)
        return secrets.compare_digest(computed_hash, stored_hash)
    
    def _generate_jwt_token(self, user: UserProfile) -> str:
        """Generate JWT token for authenticated user."""
        payload = {
            'user_id': user.user_id,
            'username': user.username,
            'email': user.email,
            'role': user.role.value,
            'department': user.department,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token and return payload if valid."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    def _get_user_by_username(self, username: str) -> Optional[UserProfile]:
        """Helper method to find user by username."""
        for user in self.users.values():
            if user.username == username:
                return user
        return None
