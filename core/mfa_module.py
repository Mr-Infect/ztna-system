import pyotp
import secrets
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, List
from enum import Enum
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
import json
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MFAMethod(Enum):
    TOTP = "totp"
    EMAIL = "email"
    SMS = "sms"
    BACKUP_CODES = "backup_codes"

@dataclass
class MFAConfiguration:
    user_id: str
    enabled_methods: List[MFAMethod]
    totp_secret: Optional[str] = None
    backup_codes: List[str] = None
    phone_number: Optional[str] = None
    last_verification: Optional[datetime] = None

class MFAService:
    def __init__(self, 
                 email_config: Dict,
                 sms_config: Dict,
                 backup_codes_count: int = 10):
        self.email_config = email_config
        self.sms_config = sms_config
        self.backup_codes_count = backup_codes_count
        self.mfa_configs: Dict[str, MFAConfiguration] = {}
        self.pending_verifications: Dict[str, Dict] = {}
        
    def setup_mfa(self, user_id: str, method: MFAMethod, 
                  phone_number: Optional[str] = None) -> Dict:
        """Set up MFA for a user with specified method."""
        if user_id not in self.mfa_configs:
            self.mfa_configs[user_id] = MFAConfiguration(
                user_id=user_id,
                enabled_methods=[],
                backup_codes=self._generate_backup_codes()
            )
            
        config = self.mfa_configs[user_id]
        
        if method == MFAMethod.TOTP:
            return self._setup_totp(config)
        elif method == MFAMethod.SMS and phone_number:
            return self._setup_sms(config, phone_number)
        elif method == MFAMethod.EMAIL:
            return self._setup_email(config)
        else:
            raise ValueError(f"Invalid MFA method or missing required information")

    def _setup_totp(self, config: MFAConfiguration) -> Dict:
        """Set up TOTP-based MFA."""
        if MFAMethod.TOTP not in config.enabled_methods:
            config.totp_secret = pyotp.random_base32()
            totp = pyotp.TOTP(config.totp_secret)
            provisioning_uri = totp.provisioning_uri(
                name=config.user_id,
                issuer_name="ZTNA System"
            )
            config.enabled_methods.append(MFAMethod.TOTP)
            
            return {
                "method": MFAMethod.TOTP.value,
                "secret": config.totp_secret,
                "provisioning_uri": provisioning_uri
            }
        else:
            raise ValueError("TOTP is already configured for this user")

    def _setup_sms(self, config: MFAConfiguration, phone_number: str) -> Dict:
        """Set up SMS-based MFA."""
        if MFAMethod.SMS not in config.enabled_methods:
            config.phone_number = phone_number
            config.enabled_methods.append(MFAMethod.SMS)
            
            # Send test verification code
            verification_code = self._generate_verification_code()
            self._send_sms(phone_number, 
                          f"Your ZTNA verification code is: {verification_code}")
            
            self.pending_verifications[config.user_id] = {
                "method": MFAMethod.SMS,
                "code": verification_code,
                "expires_at": datetime.now() + timedelta(minutes=5)
            }
            
            return {
                "method": MFAMethod.SMS.value,
                "phone_number": phone_number,
                "requires_verification": True
            }
        else:
            raise ValueError("SMS is already configured for this user")

    def _setup_email(self, config: MFAConfiguration) -> Dict:
        """Set up email-based MFA."""
        if MFAMethod.EMAIL not in config.enabled_methods:
            config.enabled_methods.append(MFAMethod.EMAIL)
            return {
                "method": MFAMethod.EMAIL.value,
                "requires_verification": True
            }
        else:
            raise ValueError("Email MFA is already configured for this user")

    def verify_mfa(self, user_id: str, method: MFAMethod, 
                   code: str, context: Dict = None) -> bool:
        """Verify MFA code for the specified method."""
        if user_id not in self.mfa_configs:
            logger.error(f"No MFA configuration found for user: {user_id}")
            return False
            
        config = self.mfa_configs[user_id]
        
        if method not in config.enabled_methods:
            logger.error(f"MFA method {method} not enabled for user: {user_id}")
            return False
            
        verified = False
        
        if method == MFAMethod.TOTP:
            verified = self._verify_totp(config, code)
        elif method == MFAMethod.SMS:
            verified = self._verify_sms(config, code)
        elif method == MFAMethod.EMAIL:
            verified = self._verify_email(config, code)
        elif method == MFAMethod.BACKUP_CODES:
            verified = self._verify_backup_code(config, code)
            
        if verified:
            config.last_verification = datetime.now()
            logger.info(f"Successful MFA verification for user: {user_id}")
            
        return verified

    def _verify_totp(self, config: MFAConfiguration, code: str) -> bool:
        """Verify TOTP code."""
        if not config.totp_secret:
            return False
            
        totp = pyotp.TOTP(config.totp_secret)
        return totp.verify(code)

    def _verify_sms(self, config: MFAConfiguration, code: str) -> bool:
        """Verify SMS code."""
        pending = self.pending_verifications.get(config.user_id)
        if not pending:
            return False
            
        if pending["method"] != MFAMethod.SMS:
            return False
            
        if datetime.now() > pending["expires_at"]:
            del self.pending_verifications[config.user_id]
            return False
            
        if secrets.compare_digest(pending["code"], code):
            del self.pending_verifications[config.user_id]
            return True
            
        return False

    def _verify_email(self, config: MFAConfiguration, code: str) -> bool:
        """Verify email code."""
        pending = self.pending_verifications.get(config.user_id)
        if not pending or pending["method"] != MFAMethod.EMAIL:
            return False
            
        if datetime.now() > pending["expires_at"]:
            del self.pending_verifications[config.user_id]
            return False
            
        if secrets.compare_digest(pending["code"], code):
            del self.pending_verifications[config.user_id]
            return True
            
        return False

    def _verify_backup_code(self, config: MFAConfiguration, code: str) -> bool:
        """Verify and consume a backup code."""
        if not config.backup_codes:
            return False
            
        if code in config.backup_codes:
            config.backup_codes.remove(code)
            return True
            
        return False

    def send_verification_code(self, user_id: str, method: MFAMethod) -> bool:
        """Send a verification code using the specified method."""
        if user_id not in self.mfa_configs:
            return False
            
        config = self.mfa_configs[user_id]
        verification_code = self._generate_verification_code()
        
        if method == MFAMethod.SMS and config.phone_number:
            return self._send_sms(
                config.phone_number, 
                f"Your verification code is: {verification_code}"
            )
        elif method == MFAMethod.EMAIL:
            return self._send_email(
                config.user_id,  # Assuming this is the email address
                "ZTNA Verification Code",
                f"Your verification code is: {verification_code}"
            )
        return False

    def _generate_verification_code(self, length: int = 6) -> str:
        """Generate a random verification code."""
        return ''.join(secrets.choice('0123456789') for _ in range(length))

    def _generate_backup_codes(self) -> List[str]:
        """Generate backup codes."""
        return [secrets.token_hex(4) for _ in range(self.backup_codes_count)]

    def _send_email(self, to_email: str, subject: str, body: str) -> bool:
        """Send email using configured SMTP server."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender']
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            context = ssl.create_default_context()
            with smtplib.SMTP(self.email_config['host'], 
                            self.email_config['port']) as server:
                server.starttls(context=context)
                server.login(self.email_config['username'], 
                           self.email_config['password'])
                server.send_message(msg)
            
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False

    def _send_sms(self, phone_number: str, message: str) -> bool:
        """Send SMS using configured SMS gateway."""
        try:
            response = requests.post(
                self.sms_config['api_url'],
                headers={
                    'Authorization': f"Bearer {self.sms_config['api_key']}",
                    'Content-Type': 'application/json'
                },
                json={
                    'to': phone_number,
                    'message': message
                }
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send SMS: {str(e)}")
            return False
