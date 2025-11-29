# server_code.py (MongoDB version)
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING
from bson import ObjectId


# -----------------------------
# Config
# -----------------------------
CHAT_HOST = os.getenv("CHAT_HOST", "127.0.0.1")
CHAT_PORT = int(os.getenv("CHAT_PORT", "54678"))

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "chat_app")

AUTH_TIMEOUT_SECONDS = 200
READ_TIMEOUT_SECONDS = 300
MAX_PACKET_BYTES = 32_768

PW_MIN_LEN = 8
PBKDF2_ITERS = int(os.getenv("PBKDF2_ITERS", "200000"))
PBKDF2_DKLEN = 32

EMAIL_RE = re.compile(r"^[^@\s]+@gmail\.com$", re.IGNORECASE)


# -----------------------------
# helpers
# -----------------------------
def now_ts() -> float:
    return time.time()


def json_pack(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def safe_str(v: Any, max_len: int = 256) -> Optional[str]:
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s or len(s) > max_len:
        return None
    return s


def normalize_email(email: str) -> str:
    return email.strip().lower()


def email_ok(email: str) -> bool:
    return bool(EMAIL_RE.match(email.strip()))


def password_ok(pw: str) -> bool:
    return isinstance(pw, str) and len(pw) >= PW_MIN_LEN


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def pbkdf2_hash(password: str, salt: bytes, iters: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=PBKDF2_DKLEN)


def uid_format(raw8: str) -> str:
    # XXXX-XXXX style
    return raw8[:4] + "-" + raw8[4:]


def make_uid_raw8() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # avoid confusing chars
    return "".join(secrets.choice(alphabet) for _ in range(8))


@dataclass
class ClientSession:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    user_id: ObjectId
    email: str
    name: str
    public_uid: str


class ChatServer:
    def __init__(self) -> None:
        self.stop_event = asyncio.Event()
        self.mongo = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        self.db = self.mongo[MONGO_DB]

        # online maps
        self.online_by_userid: Dict[ObjectId, ClientSession] = {}
        self.online_by_uid: Dict[str, ClientSession] = {}

        self.server: asyncio.AbstractServer | None = None

    async def init_db(self) -> None:
        # users
        await self.db.users.create_index([("email", ASCENDING)], unique=True)
        await self.db.users.create_index([("public_uid", ASCENDING)], unique=True)

        # friend relationships (directional)
        await self.db.friends.create_index([("user_id", ASCENDING), ("friend_id", ASCENDING)], unique=True)

        # requests/invites
        await self.db.friend_requests.create_index([("to_id", ASCENDING), ("status", ASCENDING)])
        await self.db.friend_requests.create_index([("from_id", ASCENDING), ("to_id", ASCENDING), ("status", ASCENDING)])

        await self.db.groups.create_index([("group_uid", ASCENDING)], unique=True)
        await self.db.group_members.create_index([("group_id", ASCENDING), ("user_id", ASCENDING)], unique=True)
        await self.db.group_invites.create_index([("to_id", ASCENDING), ("status", ASCENDING)])
        await self.db.group_invites.create_index([("group_id", ASCENDING), ("to_id", ASCENDING), ("status", ASCENDING)])

        # messages
        await self.db.direct_messages.create_index([("receiver_id", ASCENDING), ("delivered", ASCENDING), ("ts", ASCENDING)])
        await self.db.direct_messages.create_index([("convo_key", ASCENDING), ("ts", ASCENDING)])
        await self.db.group_messages.create_index([("group_id", ASCENDING), ("ts", ASCENDING)])

    async def start(self) -> None:
        await self.init_db()
        self.server = await asyncio.start_server(self._handle_client, CHAT_HOST, CHAT_PORT)
        addrs = ", ".join(str(s.getsockname()) for s in (self.server.sockets or []))
        print(f"[server] listening on {addrs} | db={MONGO_DB} uri={MONGO_URI}")

    async def wait_closed(self) -> None:
        if self.server:
            await self.server.wait_closed()

    def stop(self) -> None:
        self.stop_event.set()
        if self.server:
            self.server.close()
        # close all clients
        for sess in list(self.online_by_userid.values()):
            try:
                sess.writer.close()
            except Exception:
                pass
        self.online_by_userid.clear()
        self.online_by_uid.clear()

    async def _send(self, writer: asyncio.StreamWriter, pkt: Dict[str, Any]) -> None:
        data = json_pack(pkt)
        if len(data) > MAX_PACKET_BYTES:
            # refuse huge packets
            data = json_pack({"type": "error", "message": "packet_too_large"})
        writer.write(data)
        await writer.drain()

    async def _read_packet(self, reader: asyncio.StreamReader) -> Optional[Dict[str, Any]]:
        line = await reader.readline()
        if not line:
            return None
        if len(line) > MAX_PACKET_BYTES:
            return {"type": "error", "message": "packet_too_large"}
        try:
            return json.loads(line.decode("utf-8").strip())
        except Exception:
            return {"type": "error", "message": "bad_json"}

    # -----------------------------
    # user helpers
    # -----------------------------
    async def _get_user_by_email(self, email: str) -> Optional[dict]:
        return await self.db.users.find_one({"email": normalize_email(email)})

    async def _get_user_by_uid(self, public_uid: str) -> Optional[dict]:
        return await self.db.users.find_one({"public_uid": public_uid})

    async def _ensure_unique_public_uid(self) -> str:
        # Try until unique
        for _ in range(50):
            uid = uid_format(make_uid_raw8())
            exists = await self.db.users.find_one({"public_uid": uid}, {"_id": 1})
            if not exists:
                return uid
        # If the universe is trolling us
        return uid_format(make_uid_raw8())

    async def _is_friends(self, a: ObjectId, b: ObjectId) -> bool:
        doc = await self.db.friends.find_one({"user_id": a, "friend_id": b}, {"_id": 1})
        return doc is not None

    async def _friend_ids(self, user_id: ObjectId) -> List[ObjectId]:
        cursor = self.db.friends.find({"user_id": user_id}, {"friend_id": 1})
        out: List[ObjectId] = []
        async for doc in cursor:
            out.append(doc["friend_id"])
        return out

    async def _contacts_payload(self, user_id: ObjectId) -> Dict[str, Any]:
        friend_ids = await self._friend_ids(user_id)
        if not friend_ids:
            return {"friends": []}

        cursor = self.db.users.find(
            {"_id": {"$in": friend_ids}},
            {"name": 1, "public_uid": 1, "email": 1},
        )
        friends = []
        async for u in cursor:
            uid = u["public_uid"]
            friends.append({
                "name": u.get("name", ""),
                "public_uid": uid,
                "online": uid in self.online_by_uid,
            })
        friends.sort(key=lambda x: (not x["online"], x["name"].lower(), x["public_uid"]))
        return {"friends": friends}

    async def _groups_payload(self, user_id: ObjectId) -> Dict[str, Any]:
        # groups where user is a member and group active
        memberships = self.db.group_members.find({"user_id": user_id}, {"group_id": 1, "role": 1})
        group_ids: List[ObjectId] = []
        role_by_gid: Dict[ObjectId, str] = {}
        async for m in memberships:
            gid = m["group_id"]
            group_ids.append(gid)
            role_by_gid[gid] = m.get("role", "member")

        if not group_ids:
            return {"groups": []}

        cursor = self.db.groups.find({"_id": {"$in": group_ids}, "is_active": True}, {"name": 1, "group_uid": 1, "admin_id": 1})
        groups = []
        async for g in cursor:
            gid = g["_id"]
            groups.append({
                "group_uid": g["group_uid"],
                "name": g.get("name", ""),
                "role": role_by_gid.get(gid, "member"),
                "admin_uid": (self.online_by_userid.get(g.get("admin_id")) and self.online_by_userid[g["admin_id"]].public_uid) or None,
            })
        groups.sort(key=lambda x: x["name"].lower())
        return {"groups": groups}

    async def _pending_friend_requests_payload(self, user_id: ObjectId) -> Dict[str, Any]:
        reqs = []
        cursor = self.db.friend_requests.find({"to_id": user_id, "status": "pending"}).sort("created_at", ASCENDING)
        async for r in cursor:
            from_user = await self.db.users.find_one({"_id": r["from_id"]}, {"name": 1, "public_uid": 1})
            if not from_user:
                continue
            reqs.append({
                "request_id": str(r["_id"]),
                "from_name": from_user.get("name", ""),
                "from_uid": from_user.get("public_uid", ""),
                "created_at": r.get("created_at", now_ts()),
            })
        return {"friend_requests": reqs}

    async def _pending_group_invites_payload(self, user_id: ObjectId) -> Dict[str, Any]:
        invites = []
        cursor = self.db.group_invites.find({"to_id": user_id, "status": "pending"}).sort("created_at", ASCENDING)
        async for inv in cursor:
            group = await self.db.groups.find_one({"_id": inv["group_id"], "is_active": True}, {"name": 1, "group_uid": 1})
            from_user = await self.db.users.find_one({"_id": inv["from_id"]}, {"name": 1, "public_uid": 1})
            if not group or not from_user:
                continue
            invites.append({
                "invite_id": str(inv["_id"]),
                "group_uid": group.get("group_uid", ""),
                "group_name": group.get("name", ""),
                "from_name": from_user.get("name", ""),
                "from_uid": from_user.get("public_uid", ""),
                "created_at": inv.get("created_at", now_ts()),
            })
        return {"group_invites": invites}

    async def _deliver_undelivered_dms(self, sess: ClientSession) -> None:
        cursor = self.db.direct_messages.find(
            {"receiver_id": sess.user_id, "delivered": False}
        ).sort("ts", ASCENDING)

        ids: List[ObjectId] = []
        async for msg in cursor:
            sender = await self.db.users.find_one({"_id": msg["sender_id"]}, {"name": 1, "public_uid": 1})
            if not sender:
                continue
            await self._send(sess.writer, {
                "type": "dm",
                "id": str(msg["_id"]),
                "from_uid": sender.get("public_uid", ""),
                "from_name": sender.get("name", ""),
                "text": msg.get("text", ""),
                "ts": msg.get("ts", now_ts()),
            })
            ids.append(msg["_id"])

        if ids:
            await self.db.direct_messages.update_many({"_id": {"$in": ids}}, {"$set": {"delivered": True, "delivered_at": now_ts()}})

    async def _broadcast_presence_to_friends(self, user_id: ObjectId, public_uid: str, name: str, online: bool) -> None:
        friend_ids = await self._friend_ids(user_id)
        for fid in friend_ids:
            fsess = self.online_by_userid.get(fid)
            if not fsess:
                continue
            await self._send(fsess.writer, {
                "type": "presence_update",
                "uid": public_uid,
                "name": name,
                "online": online,
                "ts": now_ts(),
            })

    async def _sync_everything(self, sess: ClientSession) -> None:
        contacts = await self._contacts_payload(sess.user_id)
        groups = await self._groups_payload(sess.user_id)
        reqs = await self._pending_friend_requests_payload(sess.user_id)
        invs = await self._pending_group_invites_payload(sess.user_id)

        await self._send(sess.writer, {
            "type": "sync",
            "me": {
                "name": sess.name,
                "email": sess.email,
                "public_uid": sess.public_uid,
            },
            **contacts,
            **groups,
            **reqs,
            **invs,
        })

        await self._deliver_undelivered_dms(sess)

    # -----------------------------
    # auth / register
    # -----------------------------
    async def _handle_register(self, writer: asyncio.StreamWriter, pkt: dict) -> Optional[dict]:
        name = safe_str(pkt.get("name"), 64)
        email = safe_str(pkt.get("email"), 128)
        password = safe_str(pkt.get("password"), 256)

        if not name or not email or not password:
            await self._send(writer, {"type": "register_fail", "message": "missing_fields"})
            return None

        if not email_ok(email):
            await self._send(writer, {"type": "register_fail", "message": "bad_email"})
            return None

        if not password_ok(password):
            await self._send(writer, {"type": "register_fail", "message": "bad_password"})
            return None

        email_n = normalize_email(email)
        existing = await self.db.users.find_one({"email": email_n}, {"_id": 1})
        if existing:
            await self._send(writer, {"type": "register_fail", "message": "email_exists"})
            return None

        salt = secrets.token_bytes(16)
        ph = pbkdf2_hash(password, salt, PBKDF2_ITERS)
        public_uid = await self._ensure_unique_public_uid()

        doc = {
            "name": name,
            "email": email_n,
            "public_uid": public_uid,
            "pass_salt": b64e(salt),
            "pass_hash": b64e(ph),
            "pass_iters": PBKDF2_ITERS,
            "created_at": now_ts(),
            "last_seen": now_ts(),
        }

        try:
            res = await self.db.users.insert_one(doc)
        except Exception:
            await self._send(writer, {"type": "register_fail", "message": "db_error"})
            return None

        user = await self.db.users.find_one({"_id": res.inserted_id})
        await self._send(writer, {
            "type": "register_ok",
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "public_uid": user.get("public_uid", ""),
        })
        return user

    async def _handle_auth(self, writer: asyncio.StreamWriter, pkt: dict) -> Optional[dict]:
        email = safe_str(pkt.get("email"), 128)
        password = safe_str(pkt.get("password"), 256)
        if not email or not password:
            await self._send(writer, {"type": "auth_fail", "message": "missing_fields"})
            return None

        email_n = normalize_email(email)
        user = await self.db.users.find_one({"email": email_n})
        if not user:
            await self._send(writer, {"type": "auth_fail", "message": "bad_credentials"})
            return None

        salt = b64d(user.get("pass_salt", ""))
        iters = int(user.get("pass_iters") or PBKDF2_ITERS)
        expected = b64d(user.get("pass_hash", ""))
        got = pbkdf2_hash(password, salt, iters)

        if not hmac.compare_digest(expected, got):
            await self._send(writer, {"type": "auth_fail", "message": "bad_credentials"})
            return None

        await self.db.users.update_one({"_id": user["_id"]}, {"$set": {"last_seen": now_ts()}})

        await self._send(writer, {
            "type": "auth_ok",
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "public_uid": user.get("public_uid", ""),
        })
        return user

    # -----------------------------
    # main connection handler
    # -----------------------------
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        sess: ClientSession | None = None

        try:
            # Must auth/register first
            authed_user: Optional[dict] = None
            start = now_ts()
            while now_ts() - start < AUTH_TIMEOUT_SECONDS:
                pkt = await asyncio.wait_for(self._read_packet(reader), timeout=AUTH_TIMEOUT_SECONDS)
                if pkt is None:
                    return
                t = pkt.get("type")
                if t == "register":
                    authed_user = await self._handle_register(writer, pkt)
                    if authed_user:
                        break
                elif t == "auth":
                    authed_user = await self._handle_auth(writer, pkt)
                    if authed_user:
                        break
                else:
                    await self._send(writer, {"type": "error", "message": "auth_required"})
            if not authed_user:
                await self._send(writer, {"type": "error", "message": "auth_timeout"})
                return

            user_id = authed_user["_id"]
            sess = ClientSession(
                reader=reader,
                writer=writer,
                user_id=user_id,
                email=authed_user.get("email", ""),
                name=authed_user.get("name", ""),
                public_uid=authed_user.get("public_uid", ""),
            )

            # replace old session if same user logs in again
            old = self.online_by_userid.get(user_id)
            if old:
                try:
                    await self._send(old.writer, {"type": "error", "message": "logged_in_elsewhere"})
                    old.writer.close()
                except Exception:
                    pass

            self.online_by_userid[user_id] = sess
            self.online_by_uid[sess.public_uid] = sess

            # presence broadcast to friends + initial sync
            await self._broadcast_presence_to_friends(user_id, sess.public_uid, sess.name, True)
            await self._sync_everything(sess)

            # main loop
            while not self.stop_event.is_set():
                try:
                    pkt = await asyncio.wait_for(self._read_packet(reader), timeout=READ_TIMEOUT_SECONDS)
                except asyncio.TimeoutError:
                    # silent timeout kick
                    break
                if pkt is None:
                    break

                await self._dispatch(sess, pkt)

        except Exception as e:
            # print for dev; you can log if you want
            print(f"[server] client error {peer}: {e}")
        finally:
            if sess:
                # remove online maps
                self.online_by_userid.pop(sess.user_id, None)
                self.online_by_uid.pop(sess.public_uid, None)
                # update last_seen
                try:
                    await self.db.users.update_one({"_id": sess.user_id}, {"$set": {"last_seen": now_ts()}})
                except Exception:
                    pass
                # broadcast offline presence
                try:
                    await self._broadcast_presence_to_friends(sess.user_id, sess.public_uid, sess.name, False)
                except Exception:
                    pass

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # -----------------------------
    # packet dispatcher
    # -----------------------------
    async def _dispatch(self, sess: ClientSession, pkt: dict) -> None:
        t = pkt.get("type")

        if t == "get_sync":
            await self._sync_everything(sess)
            return

        if t == "get_contacts":
            payload = await self._contacts_payload(sess.user_id)
            await self._send(sess.writer, {"type": "contacts_sync", **payload})
            return

        if t == "send_friend_request":
            await self._pkt_send_friend_request(sess, pkt)
            return

        if t == "respond_friend_request":
            await self._pkt_respond_friend_request(sess, pkt)
            return

        if t == "dm_send":
            await self._pkt_dm_send(sess, pkt)
            return

        if t == "dm_history":
            await self._pkt_dm_history(sess, pkt)
            return

        if t == "group_create":
            await self._pkt_group_create(sess, pkt)
            return

        if t == "group_invite":
            await self._pkt_group_invite(sess, pkt)
            return

        if t == "group_respond_invite":
            await self._pkt_group_respond_invite(sess, pkt)
            return

        if t == "group_send":
            await self._pkt_group_send(sess, pkt)
            return

        if t == "group_history":
            await self._pkt_group_history(sess, pkt)
            return

        if t == "group_disband":
            await self._pkt_group_disband(sess, pkt)
            return

        await self._send(sess.writer, {"type": "error", "message": "unknown_type"})

    # -----------------------------
    # friend requests
    # -----------------------------
    async def _pkt_send_friend_request(self, sess: ClientSession, pkt: dict) -> None:
        target_uid = safe_str(pkt.get("target_uid"), 16)
        if not target_uid:
            await self._send(sess.writer, {"type": "friend_request_fail", "message": "bad_uid"})
            return

        if target_uid == sess.public_uid:
            await self._send(sess.writer, {"type": "friend_request_fail", "message": "cant_add_self"})
            return

        target = await self._get_user_by_uid(target_uid)
        if not target:
            await self._send(sess.writer, {"type": "friend_request_fail", "message": "not_found"})
            return

        target_id = target["_id"]

        if await self._is_friends(sess.user_id, target_id):
            await self._send(sess.writer, {"type": "friend_request_fail", "message": "already_friends"})
            return

        # if pending already
        existing = await self.db.friend_requests.find_one({
            "from_id": sess.user_id,
            "to_id": target_id,
            "status": "pending",
        })
        if existing:
            await self._send(sess.writer, {"type": "friend_request_fail", "message": "already_pending"})
            return

        # anti-spam: if they denied recently, you could block temporarily. keeping simple.
        doc = {
            "from_id": sess.user_id,
            "to_id": target_id,
            "status": "pending",
            "created_at": now_ts(),
        }
        res = await self.db.friend_requests.insert_one(doc)

        await self._send(sess.writer, {"type": "friend_request_sent", "target_uid": target_uid})

        # notify target if online
        tsess = self.online_by_userid.get(target_id)
        if tsess:
            await self._send(tsess.writer, {
                "type": "friend_request",
                "request_id": str(res.inserted_id),
                "from_uid": sess.public_uid,
                "from_name": sess.name,
                "created_at": doc["created_at"],
            })

    async def _pkt_respond_friend_request(self, sess: ClientSession, pkt: dict) -> None:
        request_id = safe_str(pkt.get("request_id"), 64)
        decision = safe_str(pkt.get("decision"), 16)  # accept/deny
        if not request_id or decision not in ("accept", "deny"):
            await self._send(sess.writer, {"type": "friend_request_result", "ok": False, "message": "bad_request"})
            return

        try:
            rid = ObjectId(request_id)
        except Exception:
            await self._send(sess.writer, {"type": "friend_request_result", "ok": False, "message": "bad_request"})
            return

        req = await self.db.friend_requests.find_one({"_id": rid, "to_id": sess.user_id, "status": "pending"})
        if not req:
            await self._send(sess.writer, {"type": "friend_request_result", "ok": False, "message": "not_found"})
            return

        from_id = req["from_id"]
        from_user = await self.db.users.find_one({"_id": from_id}, {"name": 1, "public_uid": 1})
        if not from_user:
            # clean up broken request
            await self.db.friend_requests.update_one({"_id": rid}, {"$set": {"status": "denied", "responded_at": now_ts()}})
            await self._send(sess.writer, {"type": "friend_request_result", "ok": True, "status": "denied"})
            return

        if decision == "deny":
            await self.db.friend_requests.update_one({"_id": rid}, {"$set": {"status": "denied", "responded_at": now_ts()}})
            await self._send(sess.writer, {"type": "friend_request_result", "ok": True, "status": "denied", "from_uid": from_user["public_uid"]})

            fsess = self.online_by_userid.get(from_id)
            if fsess:
                await self._send(fsess.writer, {"type": "friend_request_outcome", "status": "denied", "to_uid": sess.public_uid})
            return

        # accept
        await self.db.friend_requests.update_one({"_id": rid}, {"$set": {"status": "accepted", "responded_at": now_ts()}})
        # create friends both directions
        try:
            await self.db.friends.insert_one({"user_id": sess.user_id, "friend_id": from_id, "created_at": now_ts()})
        except Exception:
            pass
        try:
            await self.db.friends.insert_one({"user_id": from_id, "friend_id": sess.user_id, "created_at": now_ts()})
        except Exception:
            pass

        await self._send(sess.writer, {"type": "friend_request_result", "ok": True, "status": "accepted", "from_uid": from_user["public_uid"]})

        # Notify requester if online
        fsess = self.online_by_userid.get(from_id)
        if fsess:
            await self._send(fsess.writer, {"type": "friend_request_outcome", "status": "accepted", "to_uid": sess.public_uid})

        # Sync contacts for both sides
        await self._send(sess.writer, {"type": "contacts_sync", **(await self._contacts_payload(sess.user_id))})
        if fsess:
            await self._send(fsess.writer, {"type": "contacts_sync", **(await self._contacts_payload(from_id))})

    # -----------------------------
    # direct messages
    # -----------------------------
    async def _pkt_dm_send(self, sess: ClientSession, pkt: dict) -> None:
        to_uid = safe_str(pkt.get("to_uid"), 16)
        text = safe_str(pkt.get("text"), 2000)
        if not to_uid or not text:
            await self._send(sess.writer, {"type": "dm_fail", "message": "bad_payload"})
            return

        to_user = await self._get_user_by_uid(to_uid)
        if not to_user:
            await self._send(sess.writer, {"type": "dm_fail", "message": "not_found"})
            return

        to_id = to_user["_id"]
        if not await self._is_friends(sess.user_id, to_id):
            await self._send(sess.writer, {"type": "dm_fail", "message": "not_friends"})
            return

        convo_key = "|".join(sorted([str(sess.user_id), str(to_id)]))
        msg_doc = {
            "convo_key": convo_key,
            "sender_id": sess.user_id,
            "receiver_id": to_id,
            "text": text,
            "ts": now_ts(),
            "delivered": False,
        }
        res = await self.db.direct_messages.insert_one(msg_doc)

        # sender ack (sent)
        await self._send(sess.writer, {
            "type": "dm_sent",
            "id": str(res.inserted_id),
            "to_uid": to_uid,
            "ts": msg_doc["ts"],
        })

        # deliver to receiver if online
        rsess = self.online_by_userid.get(to_id)
        if rsess:
            await self._send(rsess.writer, {
                "type": "dm",
                "id": str(res.inserted_id),
                "from_uid": sess.public_uid,
                "from_name": sess.name,
                "text": text,
                "ts": msg_doc["ts"],
            })
            await self.db.direct_messages.update_one({"_id": res.inserted_id}, {"$set": {"delivered": True, "delivered_at": now_ts()}})

    async def _pkt_dm_history(self, sess: ClientSession, pkt: dict) -> None:
        peer_uid = safe_str(pkt.get("peer_uid"), 16)
        limit = pkt.get("limit", 50)
        if not peer_uid:
            await self._send(sess.writer, {"type": "dm_history", "ok": False, "message": "bad_peer"})
            return
        try:
            limit_i = int(limit)
        except Exception:
            limit_i = 50
        limit_i = max(1, min(limit_i, 200))

        peer = await self._get_user_by_uid(peer_uid)
        if not peer:
            await self._send(sess.writer, {"type": "dm_history", "ok": False, "message": "not_found"})
            return

        peer_id = peer["_id"]
        if not await self._is_friends(sess.user_id, peer_id):
            await self._send(sess.writer, {"type": "dm_history", "ok": False, "message": "not_friends"})
            return

        convo_key = "|".join(sorted([str(sess.user_id), str(peer_id)]))
        cursor = self.db.direct_messages.find({"convo_key": convo_key}).sort("ts", -1).limit(limit_i)
        items = []
        async for m in cursor:
            sender = await self.db.users.find_one({"_id": m["sender_id"]}, {"name": 1, "public_uid": 1})
            if not sender:
                continue
            items.append({
                "id": str(m["_id"]),
                "from_uid": sender.get("public_uid", ""),
                "from_name": sender.get("name", ""),
                "text": m.get("text", ""),
                "ts": m.get("ts", now_ts()),
            })
        items.reverse()  # oldest->newest
        await self._send(sess.writer, {"type": "dm_history", "ok": True, "peer_uid": peer_uid, "messages": items})

    # -----------------------------
    # groups
    # -----------------------------
    async def _ensure_unique_group_uid(self) -> str:
        for _ in range(50):
            uid = "G-" + uid_format(make_uid_raw8())
            exists = await self.db.groups.find_one({"group_uid": uid}, {"_id": 1})
            if not exists:
                return uid
        return "G-" + uid_format(make_uid_raw8())

    async def _is_group_admin(self, group_id: ObjectId, user_id: ObjectId) -> bool:
        m = await self.db.group_members.find_one({"group_id": group_id, "user_id": user_id}, {"role": 1})
        return bool(m and m.get("role") == "admin")

    async def _is_group_member(self, group_id: ObjectId, user_id: ObjectId) -> bool:
        m = await self.db.group_members.find_one({"group_id": group_id, "user_id": user_id}, {"_id": 1})
        return m is not None

    async def _pkt_group_create(self, sess: ClientSession, pkt: dict) -> None:
        name = safe_str(pkt.get("name"), 64)
        invite_uids = pkt.get("invite_uids") or []
        if not name:
            await self._send(sess.writer, {"type": "group_create_result", "ok": False, "message": "bad_name"})
            return
        if not isinstance(invite_uids, list):
            invite_uids = []
        invite_uids = [u for u in invite_uids if isinstance(u, str)]
        invite_uids = [u.strip() for u in invite_uids if u.strip()]
        invite_uids = list(dict.fromkeys(invite_uids))[:20]  # unique, cap

        group_uid = await self._ensure_unique_group_uid()
        gdoc = {
            "group_uid": group_uid,
            "name": name,
            "admin_id": sess.user_id,
            "is_active": True,
            "created_at": now_ts(),
        }
        res = await self.db.groups.insert_one(gdoc)
        group_id = res.inserted_id

        await self.db.group_members.insert_one({"group_id": group_id, "user_id": sess.user_id, "role": "admin", "joined_at": now_ts()})

        # create invites
        created = 0
        for uid in invite_uids:
            if uid == sess.public_uid:
                continue
            u = await self._get_user_by_uid(uid)
            if not u:
                continue
            to_id = u["_id"]
            # already member? (no)
            existing = await self.db.group_invites.find_one({"group_id": group_id, "to_id": to_id, "status": "pending"})
            if existing:
                continue
            inv = {"group_id": group_id, "from_id": sess.user_id, "to_id": to_id, "status": "pending", "created_at": now_ts()}
            inv_res = await self.db.group_invites.insert_one(inv)
            created += 1

            # push invite if online
            tsess = self.online_by_userid.get(to_id)
            if tsess:
                await self._send(tsess.writer, {
                    "type": "group_invite",
                    "invite_id": str(inv_res.inserted_id),
                    "group_uid": group_uid,
                    "group_name": name,
                    "from_uid": sess.public_uid,
                    "from_name": sess.name,
                    "created_at": inv["created_at"],
                })

        await self._send(sess.writer, {"type": "group_create_result", "ok": True, "group_uid": group_uid, "invites_sent": created})
        await self._send(sess.writer, {"type": "groups_sync", **(await self._groups_payload(sess.user_id))})

    async def _pkt_group_invite(self, sess: ClientSession, pkt: dict) -> None:
        group_uid = safe_str(pkt.get("group_uid"), 32)
        target_uid = safe_str(pkt.get("target_uid"), 16)
        if not group_uid or not target_uid:
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "bad_payload"})
            return

        group = await self.db.groups.find_one({"group_uid": group_uid, "is_active": True})
        if not group:
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "group_not_found"})
            return

        group_id = group["_id"]
        if not await self._is_group_admin(group_id, sess.user_id):
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "not_admin"})
            return

        user = await self._get_user_by_uid(target_uid)
        if not user:
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "user_not_found"})
            return

        to_id = user["_id"]
        if await self._is_group_member(group_id, to_id):
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "already_member"})
            return

        existing = await self.db.group_invites.find_one({"group_id": group_id, "to_id": to_id, "status": "pending"})
        if existing:
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "already_pending"})
            return

        inv = {"group_id": group_id, "from_id": sess.user_id, "to_id": to_id, "status": "pending", "created_at": now_ts()}
        inv_res = await self.db.group_invites.insert_one(inv)

        await self._send(sess.writer, {"type": "group_invite_result", "ok": True, "invite_id": str(inv_res.inserted_id)})

        tsess = self.online_by_userid.get(to_id)
        if tsess:
            await self._send(tsess.writer, {
                "type": "group_invite",
                "invite_id": str(inv_res.inserted_id),
                "group_uid": group.get("group_uid", ""),
                "group_name": group.get("name", ""),
                "from_uid": sess.public_uid,
                "from_name": sess.name,
                "created_at": inv["created_at"],
            })

    async def _pkt_group_respond_invite(self, sess: ClientSession, pkt: dict) -> None:
        invite_id = safe_str(pkt.get("invite_id"), 64)
        decision = safe_str(pkt.get("decision"), 16)  # accept/deny
        if not invite_id or decision not in ("accept", "deny"):
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "bad_payload"})
            return
        try:
            iid = ObjectId(invite_id)
        except Exception:
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "bad_payload"})
            return

        inv = await self.db.group_invites.find_one({"_id": iid, "to_id": sess.user_id, "status": "pending"})
        if not inv:
            await self._send(sess.writer, {"type": "group_invite_result", "ok": False, "message": "not_found"})
            return

        group = await self.db.groups.find_one({"_id": inv["group_id"], "is_active": True})
        if not group:
            await self.db.group_invites.update_one({"_id": iid}, {"$set": {"status": "denied", "responded_at": now_ts()}})
            await self._send(sess.writer, {"type": "group_invite_result", "ok": True, "status": "denied"})
            return

        group_id = group["_id"]

        if decision == "deny":
            await self.db.group_invites.update_one({"_id": iid}, {"$set": {"status": "denied", "responded_at": now_ts()}})
            await self._send(sess.writer, {"type": "group_invite_result", "ok": True, "status": "denied", "group_uid": group["group_uid"]})
        else:
            await self.db.group_invites.update_one({"_id": iid}, {"$set": {"status": "accepted", "responded_at": now_ts()}})
            try:
                await self.db.group_members.insert_one({"group_id": group_id, "user_id": sess.user_id, "role": "member", "joined_at": now_ts()})
            except Exception:
                pass
            await self._send(sess.writer, {"type": "group_invite_result", "ok": True, "status": "accepted", "group_uid": group["group_uid"]})
            await self._send(sess.writer, {"type": "groups_sync", **(await self._groups_payload(sess.user_id))})

        # notify inviter/admin if online
        from_id = inv["from_id"]
        fsess = self.online_by_userid.get(from_id)
        if fsess:
            await self._send(fsess.writer, {
                "type": "group_invite_outcome",
                "status": "accepted" if decision == "accept" else "denied",
                "group_uid": group.get("group_uid", ""),
                "to_uid": sess.public_uid,
            })

    async def _pkt_group_send(self, sess: ClientSession, pkt: dict) -> None:
        group_uid = safe_str(pkt.get("group_uid"), 32)
        text = safe_str(pkt.get("text"), 2000)
        if not group_uid or not text:
            await self._send(sess.writer, {"type": "group_send_result", "ok": False, "message": "bad_payload"})
            return

        group = await self.db.groups.find_one({"group_uid": group_uid, "is_active": True})
        if not group:
            await self._send(sess.writer, {"type": "group_send_result", "ok": False, "message": "group_not_found"})
            return

        group_id = group["_id"]
        if not await self._is_group_member(group_id, sess.user_id):
            await self._send(sess.writer, {"type": "group_send_result", "ok": False, "message": "not_member"})
            return

        mdoc = {"group_id": group_id, "sender_id": sess.user_id, "text": text, "ts": now_ts()}
        res = await self.db.group_messages.insert_one(mdoc)

        # ack sender
        await self._send(sess.writer, {"type": "group_send_result", "ok": True, "id": str(res.inserted_id), "group_uid": group_uid, "ts": mdoc["ts"]})

        # broadcast to online members (except sender)
        members = self.db.group_members.find({"group_id": group_id}, {"user_id": 1})
        async for mem in members:
            uid = mem["user_id"]
            if uid == sess.user_id:
                continue
            msess = self.online_by_userid.get(uid)
            if not msess:
                continue
            await self._send(msess.writer, {
                "type": "group_message",
                "id": str(res.inserted_id),
                "group_uid": group_uid,
                "group_name": group.get("name", ""),
                "from_uid": sess.public_uid,
                "from_name": sess.name,
                "text": text,
                "ts": mdoc["ts"],
            })

    async def _pkt_group_history(self, sess: ClientSession, pkt: dict) -> None:
        group_uid = safe_str(pkt.get("group_uid"), 32)
        limit = pkt.get("limit", 50)
        if not group_uid:
            await self._send(sess.writer, {"type": "group_history", "ok": False, "message": "bad_group"})
            return
        try:
            limit_i = int(limit)
        except Exception:
            limit_i = 50
        limit_i = max(1, min(limit_i, 200))

        group = await self.db.groups.find_one({"group_uid": group_uid, "is_active": True})
        if not group:
            await self._send(sess.writer, {"type": "group_history", "ok": False, "message": "group_not_found"})
            return

        group_id = group["_id"]
        if not await self._is_group_member(group_id, sess.user_id):
            await self._send(sess.writer, {"type": "group_history", "ok": False, "message": "not_member"})
            return

        cursor = self.db.group_messages.find({"group_id": group_id}).sort("ts", -1).limit(limit_i)
        items = []
        async for m in cursor:
            sender = await self.db.users.find_one({"_id": m["sender_id"]}, {"name": 1, "public_uid": 1})
            if not sender:
                continue
            items.append({
                "id": str(m["_id"]),
                "from_uid": sender.get("public_uid", ""),
                "from_name": sender.get("name", ""),
                "text": m.get("text", ""),
                "ts": m.get("ts", now_ts()),
            })
        items.reverse()
        await self._send(sess.writer, {"type": "group_history", "ok": True, "group_uid": group_uid, "group_name": group.get("name", ""), "messages": items})

    async def _pkt_group_disband(self, sess: ClientSession, pkt: dict) -> None:
        group_uid = safe_str(pkt.get("group_uid"), 32)
        if not group_uid:
            await self._send(sess.writer, {"type": "group_disband_result", "ok": False, "message": "bad_group"})
            return

        group = await self.db.groups.find_one({"group_uid": group_uid, "is_active": True})
        if not group:
            await self._send(sess.writer, {"type": "group_disband_result", "ok": False, "message": "group_not_found"})
            return

        group_id = group["_id"]
        if not await self._is_group_admin(group_id, sess.user_id):
            await self._send(sess.writer, {"type": "group_disband_result", "ok": False, "message": "not_admin"})
            return

        await self.db.groups.update_one({"_id": group_id}, {"$set": {"is_active": False, "disbanded_at": now_ts()}})
        await self._send(sess.writer, {"type": "group_disband_result", "ok": True, "group_uid": group_uid})

        # notify online members
        members = self.db.group_members.find({"group_id": group_id}, {"user_id": 1})
        async for mem in members:
            uid = mem["user_id"]
            msess = self.online_by_userid.get(uid)
            if msess:
                await self._send(msess.writer, {"type": "group_disbanded", "group_uid": group_uid, "group_name": group.get("name", "")})
                await self._send(msess.writer, {"type": "groups_sync", **(await self._groups_payload(uid))})


async def main() -> None:
    server = ChatServer()

    def handle_signal(sig: int, _frame: Any = None) -> None:
        print(f"[signal] {sig} stopping server")
        server.stop()

    for sig_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, sig_name):
            signal.signal(getattr(signal, sig_name), handle_signal)

    await server.start()
    try:
        await server.stop_event.wait()
    finally:
        server.stop()
        await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
