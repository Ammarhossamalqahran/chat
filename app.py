"""
app.py
------
Main entry point for the real-time messaging application.

Architecture overview
---------------------
  * Flask          – HTTP layer (REST auth endpoints).
  * Flask-SocketIO – WebSocket layer (real-time messaging).
  * SQLAlchemy     – ORM / SQLite persistence.
  * eventlet       – Production-grade async worker.

Quick-start
-----------
    pip install flask flask-socketio flask-sqlalchemy eventlet

    python app.py
    # Server listens on http://0.0.0.0:5000

SocketIO events (client → server)
----------------------------------
  authenticate   { token }                   – Bind socket to a user session.
  send_message   { recipient_id, body }      – Send a private message.
  mark_read      { message_id }              – Mark a message as read.
  typing         { recipient_id }            – Broadcast a typing indicator.

SocketIO events (server → client)
----------------------------------
  auth_success   { user_id, phone_number }   – Emitted after authentication.
  auth_error     { error }                   – Emitted on bad token.
  new_message    { ...message fields }       – Delivered to recipient room.
  message_sent   { ...message fields }       – Confirmed to sender.
  marked_read    { message_id }              – Confirmed read receipt.
  typing         { sender_id }               – Forwarded to recipient room.
  error          { error }                   – Generic error envelope.
"""
from flask import Flask, render_template  # أضفنا render_template هنا
import eventlet
eventlet.monkey_patch()  # Must be the very first call before other imports

from flask import Flask
from flask_socketio import SocketIO, emit, join_room, leave_room

from models import User, db
from routes import auth_bp, _resolve_token

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Construct and configure the Flask application."""
    app = Flask(__name__)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    app.config["SECRET_KEY"] = "CHANGE_ME_IN_PRODUCTION_USE_ENV_VAR"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///messaging.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ------------------------------------------------------------------
    # Extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    app.register_blueprint(auth_bp)

    # Create all tables on first run
    with app.app_context():
        db.create_all()

    return app


# ---------------------------------------------------------------------------
# Application & SocketIO instances
# ---------------------------------------------------------------------------

app = create_app()

socketio = SocketIO(
    app,
    async_mode="eventlet",
    cors_allowed_origins="*",   # Restrict to your domain in production
    logger=True,
    engineio_logger=False,
)

# ---------------------------------------------------------------------------
# In-memory socket ↔ user mapping
# {socket_id: user_id}  and  {user_id: socket_id}
# For horizontal scaling replace with a Redis-backed presence layer.
# ---------------------------------------------------------------------------
_socket_to_user: dict[str, int] = {}
_user_to_socket: dict[int, str] = {}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _room_name(user_id: int) -> str:
    """Each user occupies a private room named 'user_<id>'."""
    return f"user_{user_id}"


# ---------------------------------------------------------------------------
# Connection lifecycle
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    """Client connected – wait for an 'authenticate' event."""
    print(f"[WS] Client connected: {socketio.sid}")


@socketio.on("disconnect")
def on_disconnect():
    """Clean up presence maps when a client drops."""
    sid = socketio.sid
    user_id = _socket_to_user.pop(sid, None)
    if user_id is not None:
        _user_to_socket.pop(user_id, None)
        leave_room(_room_name(user_id))
        print(f"[WS] User {user_id} disconnected (sid={sid})")


# ---------------------------------------------------------------------------
# Authentication event
# ---------------------------------------------------------------------------

@socketio.on("authenticate")
def on_authenticate(data: dict):
    """
    Validate a session token and join the user's private room.

    Expected payload
    ----------------
    { "token": "<session token from /auth/verify>" }
    """
    token = (data or {}).get("token", "")
    with app.app_context():
        user = _resolve_token(token)

    if not user:
        emit("auth_error", {"error": "Invalid or expired token."})
        return

    sid = socketio.sid
    _socket_to_user[sid] = user.id
    _user_to_socket[user.id] = sid
    join_room(_room_name(user.id))

    emit("auth_success", {
        "user_id": user.id,
        "phone_number": user.phone_number,
    })
    print(f"[WS] User {user.id} authenticated (sid={sid})")


# ---------------------------------------------------------------------------
# Messaging events
# ---------------------------------------------------------------------------

@socketio.on("send_message")
def on_send_message(data: dict):
    """
    Persist a message and deliver it to the recipient in real time.

    Expected payload
    ----------------
    {
        "recipient_id": <int>,
        "body":         "<text up to 4096 chars>"
    }
    """
    sid = socketio.sid
    sender_id = _socket_to_user.get(sid)
    if not sender_id:
        emit("error", {"error": "Not authenticated."})
        return

    recipient_id = (data or {}).get("recipient_id")
    body = ((data or {}).get("body") or "").strip()

    if not recipient_id or not body:
        emit("error", {"error": "recipient_id and body are required."})
        return

    if len(body) > 4096:
        emit("error", {"error": "Message body exceeds 4096 characters."})
        return

    with app.app_context():
        from models import Message

        recipient = User.query.get(recipient_id)
        if not recipient:
            emit("error", {"error": "Recipient not found."})
            return

        msg = Message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            body=body,
        )
        db.session.add(msg)
        db.session.commit()
        payload = msg.to_dict()

    # Confirm delivery to sender
    emit("message_sent", payload)

    # Deliver to recipient's room (works even if they're offline;
    # they'll fetch history on next login via a REST endpoint)
    socketio.emit("new_message", payload, room=_room_name(recipient_id))
    print(f"[WS] Message {payload['id']} from {sender_id} to {recipient_id}")


@socketio.on("mark_read")
def on_mark_read(data: dict):
    """
    Mark a specific message as read by the authenticated recipient.

    Expected payload
    ----------------
    { "message_id": <int> }
    """
    sid = socketio.sid
    user_id = _socket_to_user.get(sid)
    if not user_id:
        emit("error", {"error": "Not authenticated."})
        return

    message_id = (data or {}).get("message_id")
    if not message_id:
        emit("error", {"error": "message_id is required."})
        return

    with app.app_context():
        from models import Message

        msg = Message.query.filter_by(id=message_id, recipient_id=user_id).first()
        if not msg:
            emit("error", {"error": "Message not found or access denied."})
            return

        msg.is_read = True
        db.session.commit()

    emit("marked_read", {"message_id": message_id})


@socketio.on("typing")
def on_typing(data: dict):
    """
    Broadcast a typing indicator to the recipient.

    Expected payload
    ----------------
    { "recipient_id": <int> }
    """
    sid = socketio.sid
    sender_id = _socket_to_user.get(sid)
    if not sender_id:
        return

    recipient_id = (data or {}).get("recipient_id")
    if not recipient_id:
        return

    socketio.emit(
        "typing",
        {"sender_id": sender_id},
        room=_room_name(recipient_id),
    )


# ---------------------------------------------------------------------------
# REST convenience: fetch message history between two users
# ---------------------------------------------------------------------------

@app.route("/messages/<int:other_user_id>", methods=["GET"])
def get_history(other_user_id: int):
    """
    Return the last N messages between the caller and *other_user_id*.

    Headers
    -------
    Authorization: Bearer <token>

    Query params
    ------------
    limit  : int  (default 50, max 200)
    offset : int  (default 0)

    Responses
    ---------
    200 – JSON array of message objects.
    401 – Unauthenticated.
    """
    from flask import jsonify, request
    from routes import _resolve_token

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or malformed Authorization header."}), 401

    token = auth_header[len("Bearer "):]
    user = _resolve_token(token)
    if not user:
        return jsonify({"error": "Invalid or expired session token."}), 401

    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return jsonify({"error": "limit and offset must be integers."}), 422

    from models import Message
    from sqlalchemy import or_, and_

    messages = (
        Message.query
        .filter(
            or_(
                and_(
                    Message.sender_id == user.id,
                    Message.recipient_id == other_user_id,
                ),
                and_(
                    Message.sender_id == other_user_id,
                    Message.recipient_id == user.id,
                ),
            )
        )
        .order_by(Message.created_at.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify([m.to_dict() for m in messages]), 200

@app.route("/")
def index():
    return render_template("index.html")
# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Starting messaging server on http://0.0.0.0:5000")
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,       # Set to False in production
    )
