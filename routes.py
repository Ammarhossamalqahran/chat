"""
routes.py
---------
Authentication routes for the real-time messaging application.

Endpoints
---------
POST /auth/signup        – Register a new phone number; issues an OTP.
POST /auth/verify        – Verify OTP and receive a session token.
POST /auth/login         – Re-issue an OTP for an existing account.
GET  /auth/me            – Return the currently authenticated user.
POST /auth/logout        – Invalidate the session token.

All responses are JSON.  A lightweight token-based session is implemented
with ``hashlib`` (no third-party JWT library required).
"""

import hashlib
import os
import random
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request

from models import User, db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OTP_LENGTH = 6                  # digits
OTP_TTL_MINUTES = 10            # how long an OTP remains valid
SESSION_TTL_HOURS = 72          # how long a session token remains valid

# In-memory session store  {token: {"user_id": int, "expires_at": datetime}}
# For production, replace with Redis or a DB-backed session table.
_SESSION_STORE: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_otp() -> str:
    """Return a zero-padded numeric OTP string of length OTP_LENGTH."""
    return "".join(random.choices(string.digits, k=OTP_LENGTH))


def _generate_token(user_id: int) -> str:
    """
    Create a deterministically unique session token bound to *user_id*.
    Uses SHA-256 over a random nonce so the token is unguessable.
    """
    nonce = os.urandom(32).hex()
    raw = f"{user_id}:{nonce}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _send_otp(phone_number: str, otp: str) -> None:
    """
    Placeholder for OTP dispatch.

    In a real deployment replace this body with an SMS gateway call
    (Twilio, AWS SNS, Vonage, etc.).  During development the OTP is
    printed to stdout so you can test without a live SMS provider.
    """
    current_app.logger.info(
        "[OTP] Send '%s' to phone number '%s'", otp, phone_number
    )
    print(f"[DEV OTP] {phone_number} -> {otp}")


def _store_session(user_id: int) -> str:
    """Persist a new session token and return it."""
    token = _generate_token(user_id)
    _SESSION_STORE[token] = {
        "user_id": user_id,
        "expires_at": datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS),
    }
    return token


def _resolve_token(token: str) -> User | None:
    """
    Look up *token* in the session store.
    Returns the associated :class:`User` or ``None`` if invalid / expired.
    """
    session = _SESSION_STORE.get(token)
    if not session:
        return None
    if datetime.utcnow() > session["expires_at"]:
        _SESSION_STORE.pop(token, None)
        return None
    return User.query.get(session["user_id"])


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def login_required(fn):
    """
    View decorator that enforces a valid Bearer token.

    Attaches the resolved :class:`User` to ``flask.g.current_user`` so
    protected views can access the authenticated user without re-querying.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header."}), 401
        token = auth_header[len("Bearer "):]
        user = _resolve_token(token)
        if not user:
            return jsonify({"error": "Invalid or expired session token."}), 401
        g.current_user = user
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/signup", methods=["POST"])
def signup():
    """
    Register a new user by phone number and dispatch an OTP.

    Request body (JSON)
    -------------------
    phone_number : str  – E.164 phone number, e.g. "+201012345678".
    display_name : str  – Optional display name (max 64 chars).

    Responses
    ---------
    201 – Account created; OTP dispatched.
    409 – Phone number already registered.
    422 – Validation error.
    """
    data = request.get_json(silent=True) or {}
    phone_number = (data.get("phone_number") or "").strip()
    display_name = (data.get("display_name") or "").strip()[:64]

    if not phone_number:
        return jsonify({"error": "phone_number is required."}), 422

    # Enforce E.164-ish format (starts with '+', 7–15 digits)
    digits = phone_number[1:] if phone_number.startswith("+") else ""
    if not digits.isdigit() or not (7 <= len(digits) <= 15):
        return jsonify({"error": "phone_number must be in E.164 format (e.g. +201012345678)."}), 422

    if User.query.filter_by(phone_number=phone_number).first():
        return jsonify({"error": "Phone number is already registered."}), 409

    otp = _generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)

    user = User(phone_number=phone_number, display_name=display_name or None)
    user.set_otp(otp, expires_at)
    db.session.add(user)
    db.session.commit()

    _send_otp(phone_number, otp)

    return jsonify({
        "message": "Account created. OTP sent to your phone number.",
        "otp_expires_in_minutes": OTP_TTL_MINUTES,
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Re-issue an OTP for an existing account.

    Request body (JSON)
    -------------------
    phone_number : str

    Responses
    ---------
    200 – OTP dispatched.
    404 – Phone number not found.
    422 – Validation error.
    """
    data = request.get_json(silent=True) or {}
    phone_number = (data.get("phone_number") or "").strip()

    if not phone_number:
        return jsonify({"error": "phone_number is required."}), 422

    user = User.query.filter_by(phone_number=phone_number).first()
    if not user:
        return jsonify({"error": "Phone number not found. Please sign up first."}), 404

    otp = _generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_TTL_MINUTES)
    user.set_otp(otp, expires_at)
    db.session.commit()

    _send_otp(phone_number, otp)

    return jsonify({
        "message": "OTP sent to your phone number.",
        "otp_expires_in_minutes": OTP_TTL_MINUTES,
    }), 200


@auth_bp.route("/verify", methods=["POST"])
def verify():
    """
    Verify an OTP and return a session token.

    Request body (JSON)
    -------------------
    phone_number : str
    otp          : str  – 6-digit code received via SMS.

    Responses
    ---------
    200 – Verified; returns session ``token``.
    400 – OTP invalid or expired.
    404 – Phone number not found.
    422 – Validation error.
    """
    data = request.get_json(silent=True) or {}
    phone_number = (data.get("phone_number") or "").strip()
    otp = (data.get("otp") or "").strip()

    if not phone_number or not otp:
        return jsonify({"error": "phone_number and otp are required."}), 422

    user = User.query.filter_by(phone_number=phone_number).first()
    if not user:
        return jsonify({"error": "Phone number not found."}), 404

    if not user.verify_otp(otp):
        return jsonify({"error": "Invalid or expired OTP."}), 400

    db.session.commit()  # persist is_verified + cleared OTP fields

    token = _store_session(user.id)

    return jsonify({
        "message": "Phone number verified successfully.",
        "token": token,
        "user": {
            "id": user.id,
            "phone_number": user.phone_number,
            "display_name": user.display_name,
        },
    }), 200


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    """
    Return the profile of the currently authenticated user.

    Headers
    -------
    Authorization: Bearer <token>

    Responses
    ---------
    200 – User profile JSON.
    401 – Unauthenticated.
    """
    user: User = g.current_user
    return jsonify({
        "id": user.id,
        "phone_number": user.phone_number,
        "display_name": user.display_name,
        "is_verified": user.is_verified,
        "created_at": user.created_at.isoformat() + "Z",
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    Invalidate the current session token.

    Headers
    -------
    Authorization: Bearer <token>

    Responses
    ---------
    200 – Logged out.
    401 – Unauthenticated.
    """
    token = request.headers["Authorization"][len("Bearer "):]
    _SESSION_STORE.pop(token, None)
    return jsonify({"message": "Logged out successfully."}), 200
