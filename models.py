"""
models.py
---------
SQLAlchemy database models for the real-time messaging application.
Defines User and Message entities with relationships.
"""

import hashlib
import os
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _hash_otp(raw_otp: str, salt: str) -> str:
    """Return a SHA-256 hex digest of ``raw_otp`` combined with ``salt``."""
    payload = f"{salt}{raw_otp}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model):
    """
    Represents a registered user.

    Columns
    -------
    id              : Integer primary key (auto-increment).
    phone_number    : Unique E.164-style phone number (e.g. '+201012345678').
    display_name    : Optional human-readable name chosen at signup.
    otp_hash        : SHA-256 hash of the most-recently issued OTP.
    otp_salt        : Random salt used when hashing the OTP.
    otp_expires_at  : UTC timestamp after which the stored OTP is invalid.
    is_verified     : True once the user has successfully verified one OTP.
    created_at      : UTC timestamp of account creation.
    """

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(64), nullable=True)
    otp_hash = db.Column(db.String(64), nullable=True)
    otp_salt = db.Column(db.String(32), nullable=True)
    otp_expires_at = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # One-to-many: a user can send many messages
    sent_messages = db.relationship(
        "Message",
        foreign_keys="Message.sender_id",
        back_populates="sender",
        lazy="dynamic",
    )

    # One-to-many: a user can receive many messages
    received_messages = db.relationship(
        "Message",
        foreign_keys="Message.recipient_id",
        back_populates="recipient",
        lazy="dynamic",
    )

    # ------------------------------------------------------------------
    # OTP helpers
    # ------------------------------------------------------------------

    def set_otp(self, raw_otp: str, expires_at: datetime) -> None:
        """Hash and store a new OTP together with a fresh random salt."""
        salt = os.urandom(16).hex()  # 32-character hex string
        self.otp_salt = salt
        self.otp_hash = _hash_otp(raw_otp, salt)
        self.otp_expires_at = expires_at

    def verify_otp(self, raw_otp: str) -> bool:
        """
        Return True when *raw_otp* matches the stored hash AND has not expired.
        Clears the stored OTP fields on a successful match to prevent replay.
        """
        if not self.otp_hash or not self.otp_salt or not self.otp_expires_at:
            return False
        if datetime.utcnow() > self.otp_expires_at:
            return False
        candidate = _hash_otp(raw_otp, self.otp_salt)
        if candidate == self.otp_hash:
            # Invalidate OTP after successful use
            self.otp_hash = None
            self.otp_salt = None
            self.otp_expires_at = None
            self.is_verified = True
            return True
        return False

    def __repr__(self) -> str:
        return f"<User id={self.id} phone={self.phone_number!r}>"


class Message(db.Model):
    """
    Represents a chat message exchanged between two users.

    Columns
    -------
    id           : Integer primary key (auto-increment).
    sender_id    : FK → users.id – who sent the message.
    recipient_id : FK → users.id – who should receive the message.
    body         : Plain-text message content (up to 4 096 characters).
    is_read      : True once the recipient has acknowledged the message.
    created_at   : UTC timestamp when the message was persisted.
    """

    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    body = db.Column(db.String(4096), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sender = db.relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = db.relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON / SocketIO emission."""
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "sender_phone": self.sender.phone_number if self.sender else None,
            "recipient_id": self.recipient_id,
            "body": self.body,
            "is_read": self.is_read,
            "created_at": self.created_at.isoformat() + "Z",
        }

    def __repr__(self) -> str:
        return f"<Message id={self.id} from={self.sender_id} to={self.recipient_id}>"
