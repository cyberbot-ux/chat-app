from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import tkinter as tk
import tkinter.messagebox as mbox
from tkinter import ttk

MAX_PACKET_BYTES = 32768


def json_pack(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def now_ts() -> float:
    return time.time()


def email_ok(e: str) -> bool:
    e = (e or "").strip().lower()
    return e.endswith("@gmail.com") and ("@" in e) and len(e) <= 128


# ---------------------------- Data classes ----------------------------


@dataclass
class Friend:
    name: str
    public_uid: str
    online: bool = False


@dataclass
class Group:
    group_uid: str
    name: str
    role: str = "member"


@dataclass
class ChatMessage:
    id: str
    kind: str  # "dm" or "group"
    peer: str  # peer_uid or group_uid
    from_uid: str
    from_name: str
    text: str
    ts: float = field(default_factory=now_ts)


@dataclass
class AppState:
    me_name: str = ""
    me_email: str = ""
    me_uid: str = ""

    friends: Dict[str, Friend] = field(default_factory=dict)  # key=public_uid
    groups: Dict[str, Group] = field(default_factory=dict)    # key=group_uid

    current_kind: str = "dm"
    current_peer: str = ""

    chat_cache: Dict[tuple, List[ChatMessage]] = field(default_factory=dict)  # (kind,peer)->msgs
    friend_requests: List[dict] = field(default_factory=list)
    group_invites: List[dict] = field(default_factory=list)


# ---------------------------- Low-level client ----------------------------


class ChatClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 54678):
        self.host = host
        self.port = port
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.incoming_task: asyncio.Task | None = None
        self.on_packet: Optional[Callable[[dict], None]] = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self.incoming_task = asyncio.create_task(self._incoming_loop())

    async def close(self):
        if self.incoming_task:
            self.incoming_task.cancel()
            try:
                await self.incoming_task
            except asyncio.CancelledError:
                pass
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass

    async def _send(self, obj: Dict[str, Any]):
        if not self.writer:
            raise RuntimeError("not connected")
        line = json_pack(obj)
        if len(line) > MAX_PACKET_BYTES:
            raise ValueError("packet too large")
        self.writer.write(line)
        await self.writer.drain()

    async def _incoming_loop(self):
        try:
            assert self.reader is not None
            while True:
                line = await self.reader.readline()
                if not line:
                    if self.on_packet:
                        self.on_packet({"type": "_closed"})
                    break
                try:
                    pkt = json.loads(line.decode("utf-8").strip())
                except Exception:
                    continue
                if self.on_packet:
                    self.on_packet(pkt)
        except asyncio.CancelledError:
            pass

    # --- auth/register ---
    async def register(self, name: str, email: str, password: str):
        await self._send({"type": "register", "name": name, "email": email, "password": password})

    async def auth(self, email: str, password: str):
        await self._send({"type": "auth", "email": email, "password": password})

    async def get_sync(self):
        await self._send({"type": "get_sync"})

    # --- friends ---
    async def send_friend_request(self, target_uid: str):
        await self._send({"type": "send_friend_request", "target_uid": target_uid})

    async def respond_friend_request(self, request_id: str, decision: str):
        await self._send({"type": "respond_friend_request", "request_id": request_id, "decision": decision})

    # --- dm ---
    async def dm_send(self, to_uid: str, text: str):
        await self._send({"type": "dm_send", "to_uid": to_uid, "text": text})

    async def dm_history(self, peer_uid: str, limit: int = 80):
        await self._send({"type": "dm_history", "peer_uid": peer_uid, "limit": limit})

    # --- groups ---
    async def group_create(self, name: str, invite_uids: List[str]):
        await self._send({"type": "group_create", "name": name, "invite_uids": invite_uids})

    async def group_invite(self, group_uid: str, target_uid: str):
        await self._send({"type": "group_invite", "group_uid": group_uid, "target_uid": target_uid})

    async def group_respond_invite(self, invite_id: str, decision: str):
        await self._send({"type": "group_respond_invite", "invite_id": invite_id, "decision": decision})

    async def group_send(self, group_uid: str, text: str):
        await self._send({"type": "group_send", "group_uid": group_uid, "text": text})

    async def group_history(self, group_uid: str, limit: int = 80):
        await self._send({"type": "group_history", "group_uid": group_uid, "limit": limit})

    async def group_disband(self, group_uid: str):
        await self._send({"type": "group_disband", "group_uid": group_uid})


# ---------------------------- Backend thread ----------------------------


@dataclass
class _Waiter:
    future: concurrent.futures.Future
    types: tuple


class Backend:
    def __init__(self, state: AppState):
        self.state = state
        self.events: "queue.Queue[dict]" = queue.Queue()
        self.last_error: str = ""

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._client: ChatClient | None = None

        self._connected = threading.Event()
        self._closing = threading.Event()

        self._lock = threading.Lock()
        self._waiters: Dict[str, List[_Waiter]] = {}

    def connect(self, host: str, port: int) -> bool:
        self.last_error = ""
        if self._thread and self._thread.is_alive() and self._connected.is_set():
            return True

        if not self._thread or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run_loop, args=(host, port), daemon=True)
            self._thread.start()

        ok = self._connected.wait(timeout=6.0)
        if not ok and not self.last_error:
            self.last_error = "Could not connect to server."
        return ok

    def close(self):
        self._closing.set()
        if self._loop and self._client:
            try:
                asyncio.run_coroutine_threadsafe(self._client.close(), self._loop)
            except Exception:
                pass
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass

    def _run_loop(self, host: str, port: int):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop

            self._client = ChatClient(host=host, port=port)
            self._client.on_packet = self._on_packet

            loop.run_until_complete(self._client.connect())
            self._connected.set()

            loop.run_forever()
        except Exception as e:
            self.last_error = str(e)
        finally:
            self._connected.clear()
            try:
                if self._client and self._loop and not self._loop.is_closed():
                    self._loop.run_until_complete(self._client.close())
            except Exception:
                pass
            try:
                if self._loop and not self._loop.is_closed():
                    self._loop.close()
            except Exception:
                pass

    def _on_packet(self, pkt: dict):
        t = pkt.get("type")
        if isinstance(t, str):
            with self._lock:
                lst = self._waiters.get(t) or []
                i = 0
                while i < len(lst):
                    w = lst[i]
                    if w.future.done():
                        lst.pop(i)
                        continue
                    lst.pop(i)
                    if not w.future.done():
                        w.future.set_result(pkt)
                    for ot in w.types:
                        if ot == t:
                            continue
                        olist = self._waiters.get(ot)
                        if not olist:
                            continue
                        self._waiters[ot] = [x for x in olist if x is not w]
                    break
                self._waiters[t] = lst

        self.events.put(pkt)

    def _add_waiter(self, types: List[str]) -> concurrent.futures.Future:
        fut: concurrent.futures.Future = concurrent.futures.Future()
        w = _Waiter(future=fut, types=tuple(types))
        with self._lock:
            for t in types:
                self._waiters.setdefault(t, []).append(w)
        return fut

    def _submit(self, coro) -> concurrent.futures.Future:
        if not self._loop:
            raise RuntimeError("Backend loop not running")
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    # --- blocking auth/register (called from worker thread in UI) ---
    def auth(self, email: str, password: str) -> bool:
        if not self._client or not self._loop:
            self.last_error = "Not connected."
            return False
        try:
            fut = self._add_waiter(["auth_ok", "auth_fail", "error", "_closed"])
            self._submit(self._client.auth(email, password))
            pkt = fut.result(timeout=10.0)
            t = pkt.get("type")
            if t == "auth_ok":
                return True
            if t == "auth_fail":
                self.last_error = str(pkt.get("message") or "Bad credentials")
                return False
            self.last_error = str(pkt.get("message") or "Auth error")
            return False
        except Exception as e:
            self.last_error = str(e)
            return False

    def register(self, name: str, email: str, password: str) -> bool:
        if not self._client or not self._loop:
            self.last_error = "Not connected."
            return False
        try:
            fut = self._add_waiter(["register_ok", "register_fail", "error", "_closed"])
            self._submit(self._client.register(name, email, password))
            pkt = fut.result(timeout=10.0)
            t = pkt.get("type")
            if t == "register_ok":
                return True
            if t == "register_fail":
                self.last_error = str(pkt.get("message") or "Register failed")
                return False
            self.last_error = str(pkt.get("message") or "Register error")
            return False
        except Exception as e:
            self.last_error = str(e)
            return False

    # --- fire-and-forget actions ---
    def add_friend(self, uid: str):
        if self._client and self._loop:
            self._submit(self._client.send_friend_request(uid))

    def respond_friend_request(self, request_id: str, decision: str):
        if self._client and self._loop:
            self._submit(self._client.respond_friend_request(request_id, decision))

    def create_group(self, name: str, invite_uids: List[str]):
        if self._client and self._loop:
            self._submit(self._client.group_create(name, invite_uids))

    def invite_to_group(self, group_uid: str, target_uid: str):
        if self._client and self._loop:
            self._submit(self._client.group_invite(group_uid, target_uid))

    def respond_group_invite(self, invite_id: str, decision: str):
        if self._client and self._loop:
            self._submit(self._client.group_respond_invite(invite_id, decision))

    def disband_group(self, group_uid: str):
        if self._client and self._loop:
            self._submit(self._client.group_disband(group_uid))

    def request_history(self, kind: str, peer: str, limit: int):
        if not self._client or not self._loop:
            return
        if kind == "dm":
            self._submit(self._client.dm_history(peer, limit))
        else:
            self._submit(self._client.group_history(peer, limit))

    def send_text(self, kind: str, peer: str, text: str):
        if not self._client or not self._loop:
            return
        if kind == "dm":
            self._submit(self._client.dm_send(peer, text))
        else:
            self._submit(self._client.group_send(peer, text))


# ---------------------------- Login window ----------------------------


class LoginWindow(tk.Toplevel):
    def __init__(self, master: tk.Tk, backend: Backend, on_authed: Callable[[], None]):
        super().__init__(master)
        self.backend = backend
        self.on_authed = on_authed
        self.title("Login")
        self.resizable(False, False)
        self._build()

    def _build(self):
        wrap = ttk.Frame(self, padding=14)
        wrap.pack(fill="both", expand=True)

        nb = ttk.Notebook(wrap)
        nb.pack(fill="both", expand=True)

        # Login tab
        f_login = ttk.Frame(nb, padding=12)
        nb.add(f_login, text="Login")

        ttk.Label(f_login, text="Email (@gmail.com)").pack(anchor="w")
        self.login_email = ttk.Entry(f_login, width=34)
        self.login_email.pack(fill="x", pady=(0, 8))

        ttk.Label(f_login, text="Password (min 8)").pack(anchor="w")
        self.login_pw = ttk.Entry(f_login, show="*", width=34)
        self.login_pw.pack(fill="x", pady=(0, 10))

        ttk.Button(f_login, text="Login", command=self.do_login).pack(fill="x")

        # Register tab
        f_reg = ttk.Frame(nb, padding=12)
        nb.add(f_reg, text="Register")

        ttk.Label(f_reg, text="Name").pack(anchor="w")
        self.reg_name = ttk.Entry(f_reg, width=34)
        self.reg_name.pack(fill="x", pady=(0, 8))

        ttk.Label(f_reg, text="Email (@gmail.com)").pack(anchor="w")
        self.reg_email = ttk.Entry(f_reg, width=34)
        self.reg_email.pack(fill="x", pady=(0, 8))

        ttk.Label(f_reg, text="Password (min 8)").pack(anchor="w")
        self.reg_pw = ttk.Entry(f_reg, show="*", width=34)
        self.reg_pw.pack(fill="x", pady=(0, 10))

        ttk.Button(f_reg, text="Register", command=self.do_register).pack(fill="x")

    def do_login(self):
        email = self.login_email.get().strip()
        pw = self.login_pw.get().strip()

        if not email_ok(email):
            mbox.showerror("Nope", "Email must end with @gmail.com")
            return
        if len(pw) < 8:
            mbox.showerror("Nope", "Password must be at least 8 characters")
            return

        def work():
            ok = self.backend.auth(email, pw)
            self.after(0, lambda: self._finish_login(ok))

        threading.Thread(target=work, daemon=True).start()

    def _finish_login(self, ok: bool):
        if not ok:
            mbox.showerror("Login failed", self.backend.last_error or "bad credentials")
            return
        self.on_authed()
        self.destroy()

    def do_register(self):
        name = self.reg_name.get().strip()
        email = self.reg_email.get().strip()
        pw = self.reg_pw.get().strip()

        if not name:
            mbox.showerror("Nope", "Name is required")
            return
        if not email_ok(email):
            mbox.showerror("Nope", "Email must end with @gmail.com")
            return
        if len(pw) < 8:
            mbox.showerror("Nope", "Password must be at least 8 characters")
            return

        def work():
            ok = self.backend.register(name, email, pw)
            self.after(0, lambda: self._finish_register(ok))

        threading.Thread(target=work, daemon=True).start()

    def _finish_register(self, ok: bool):
        if not ok:
            mbox.showerror("Register failed", self.backend.last_error or "register failed")
            return
        mbox.showinfo("Success", "Account created and logged in ✅")
        self.on_authed()
        self.destroy()


# ---------------------------- Requests window ----------------------------


class RequestsWindow(tk.Toplevel):
    def __init__(self, master: tk.Tk, backend: Backend, state: AppState):
        super().__init__(master)
        self.backend = backend
        self.state = state
        self.title("Requests")
        self.geometry("520x360")
        self._build()
        self.refresh()

    def _build(self):
        wrap = ttk.Frame(self, padding=10)
        wrap.pack(fill="both", expand=True)

        nb = ttk.Notebook(wrap)
        nb.pack(fill="both", expand=True)

        # Friend requests
        self.f_tab = ttk.Frame(nb, padding=8)
        nb.add(self.f_tab, text="Friend Requests")
        self.friend_list = tk.Listbox(self.f_tab)
        self.friend_list.pack(fill="both", expand=True)
        btns = ttk.Frame(self.f_tab)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="Accept", command=self.accept_friend).pack(side="left")
        ttk.Button(btns, text="Deny", command=self.deny_friend).pack(side="left", padx=(8, 0))

        # Group invites
        self.g_tab = ttk.Frame(nb, padding=8)
        nb.add(self.g_tab, text="Group Invites")
        self.group_list = tk.Listbox(self.g_tab)
        self.group_list.pack(fill="both", expand=True)
        btns2 = ttk.Frame(self.g_tab)
        btns2.pack(fill="x", pady=(8, 0))
        ttk.Button(btns2, text="Accept", command=self.accept_group).pack(side="left")
        ttk.Button(btns2, text="Deny", command=self.deny_group).pack(side="left", padx=(8, 0))

        self._friend_rows: List[dict] = []
        self._group_rows: List[dict] = []

    def refresh(self):
        self.friend_list.delete(0, tk.END)
        self.group_list.delete(0, tk.END)

        self._friend_rows = list(self.state.friend_requests)
        self._group_rows = list(self.state.group_invites)

        for r in self._friend_rows:
            self.friend_list.insert(tk.END, f'{r.get("from_name","")} ({r.get("from_uid","")})')

        for inv in self._group_rows:
            self.group_list.insert(
                tk.END,
                f'{inv.get("group_name","")} [{inv.get("group_uid","")}] from {inv.get("from_name","")}'
            )

    def _selected_friend(self) -> Optional[dict]:
        sel = self.friend_list.curselection()
        if not sel:
            return None
        return self._friend_rows[int(sel[0])]

    def _selected_group(self) -> Optional[dict]:
        sel = self.group_list.curselection()
        if not sel:
            return None
        return self._group_rows[int(sel[0])]

    def accept_friend(self):
        r = self._selected_friend()
        if not r:
            return
        self.backend.respond_friend_request(r["request_id"], "accept")
        self.state.friend_requests = [x for x in self.state.friend_requests if x.get("request_id") != r.get("request_id")]
        self.refresh()

    def deny_friend(self):
        r = self._selected_friend()
        if not r:
            return
        self.backend.respond_friend_request(r["request_id"], "deny")
        self.state.friend_requests = [x for x in self.state.friend_requests if x.get("request_id") != r.get("request_id")]
        self.refresh()

    def accept_group(self):
        inv = self._selected_group()
        if not inv:
            return
        self.backend.respond_group_invite(inv["invite_id"], "accept")
        self.state.group_invites = [x for x in self.state.group_invites if x.get("invite_id") != inv.get("invite_id")]
        self.refresh()

    def deny_group(self):
        inv = self._selected_group()
        if not inv:
            return
        self.backend.respond_group_invite(inv["invite_id"], "deny")
        self.state.group_invites = [x for x in self.state.group_invites if x.get("invite_id") != inv.get("invite_id")]
        self.refresh()


# ---------------------------- Main UI ----------------------------


class MainUI(ttk.Frame):
    def __init__(self, master: tk.Tk, backend: Backend, state: AppState):
        super().__init__(master, padding=10)
        self.master = master
        self.backend = backend
        self.state = state
        self.pack(fill="both", expand=True)

        self.requests_win: RequestsWindow | None = None

        # index -> uid / group_uid mapping for dropdowns
        self._friend_order: List[str] = []
        self._group_order: List[str] = []

        self._build()
        self._poll_events()

    def _build(self):
        self.master.title("Chat App")

        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        # top bar
        top = ttk.Frame(self)
        top.grid(row=0, column=0, columnspan=2, sticky="ew")
        top.columnconfigure(0, weight=1)

        self.me_label = ttk.Label(top, text="Not logged in")
        self.me_label.grid(row=0, column=0, sticky="w")

        self.lonely_btn = ttk.Button(top, text="lonely", command=self.show_uid)
        self.lonely_btn.grid(row=0, column=1, sticky="e")

        # left: friends + groups
        left = ttk.Frame(self)
        left.grid(row=1, column=0, sticky="nsw", padx=(0, 10))

        ttk.Label(left, text="Friends").grid(row=0, column=0, sticky="w")
        self.friend_combo = ttk.Combobox(left, state="readonly", width=25)
        self.friend_combo.grid(row=1, column=0, sticky="ew")
        self.friend_combo.bind("<<ComboboxSelected>>", self._on_select_friend)

        fbtns = ttk.Frame(left)
        fbtns.grid(row=2, column=0, sticky="ew", pady=(6, 10))
        ttk.Button(fbtns, text="Add Friend", command=self.add_friend_dialog).pack(side="left")
        ttk.Button(fbtns, text="Requests", command=self.open_requests).pack(side="left", padx=(6, 0))

        ttk.Label(left, text="Groups").grid(row=3, column=0, sticky="w", pady=(8, 0))
        self.group_combo = ttk.Combobox(left, state="readonly", width=25)
        self.group_combo.grid(row=4, column=0, sticky="ew")
        self.group_combo.bind("<<ComboboxSelected>>", self._on_select_group)

        gbtns = ttk.Frame(left)
        gbtns.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(gbtns, text="Create", command=self.create_group_dialog).pack(side="left")
        ttk.Button(gbtns, text="Invite", command=self.invite_group_dialog).pack(side="left", padx=(6, 0))
        ttk.Button(gbtns, text="Disband", command=self.disband_group).pack(side="left", padx=(6, 0))

        # right: chat
        right = ttk.Frame(self)
        right.grid(row=1, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        self.chat_title = ttk.Label(right, text="No chat selected")
        self.chat_title.grid(row=0, column=0, sticky="w")

        self.chat_box = tk.Text(right, height=18, wrap="word", state="disabled")
        self.chat_box.grid(row=1, column=0, sticky="nsew", pady=(6, 6))

        # message styling tags: only alignment + margins
        self.chat_box.tag_configure(
            "them",
            justify="left",
            lmargin1=8,
            lmargin2=8,
            rmargin=80,
            spacing1=2,
            spacing3=2,
        )
        self.chat_box.tag_configure(
            "me",
            justify="right",
            lmargin1=80,
            lmargin2=80,
            rmargin=8,
            spacing1=2,
            spacing3=2,
        )

        bottom = ttk.Frame(right)
        bottom.grid(row=2, column=0, sticky="ew")
        bottom.columnconfigure(0, weight=1)

        self.msg_entry = ttk.Entry(bottom)
        self.msg_entry.grid(row=0, column=0, sticky="ew")
        self.msg_entry.bind("<Return>", lambda _e: self.send_message())

        ttk.Button(bottom, text="Send", command=self.send_message).grid(row=0, column=1, padx=(6, 0))

        self.status = ttk.Label(right, text="")
        self.status.grid(row=3, column=0, sticky="w", pady=(6, 0))

    # ---------- UI helpers ----------

    def show_uid(self):
        if not self.state.me_uid:
            return
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(self.state.me_uid)
        except Exception:
            pass
        mbox.showinfo("Your UID", f"{self.state.me_uid}\n\nCopied to clipboard ✅")

    def add_friend_dialog(self):
        uid = simple_prompt(self.master, "Add Friend", "Enter friend public UID (like ABCD-1234):")
        if not uid:
            return
        self.backend.add_friend(uid.strip().upper())
        self.status["text"] = "Friend request sent (if UID exists)."

    def open_requests(self):
        if self.requests_win and self.requests_win.winfo_exists():
            self.requests_win.lift()
            self.requests_win.refresh()
        else:
            self.requests_win = RequestsWindow(self.master, self.backend, self.state)

    def create_group_dialog(self):
        name = simple_prompt(self.master, "Create Group", "Group name:")
        if not name:
            return
        raw = simple_prompt(self.master, "Create Group", "Invite UIDs (comma separated, optional):")
        invite_uids: List[str] = []
        if raw:
            invite_uids = [x.strip().upper() for x in raw.split(",") if x.strip()]
        self.backend.create_group(name.strip(), invite_uids)
        self.status["text"] = "Creating group..."

    def invite_group_dialog(self):
        g = self._selected_group_obj()
        if not g and self._group_order:
            # if only one group exists, use it automatically
            gid = self._group_order[0]
            g = self.state.groups.get(gid)
        if not g:
            mbox.showwarning("No group", "Select a group from the Groups dropdown first.")
            return
        uid = simple_prompt(self.master, "Invite to Group", "Friend UID to invite:")
        if not uid:
            return
        self.backend.invite_to_group(g.group_uid, uid.strip().upper())
        self.status["text"] = "Invite sent (if admin + UID valid)."

    def disband_group(self):
        g = self._selected_group_obj()
        if not g and self._group_order:
            gid = self._group_order[0]
            g = self.state.groups.get(gid)
        if not g:
            mbox.showwarning("No group", "Select a group from the Groups dropdown first.")
            return
        if g.role != "admin":
            mbox.showerror("Nope", "Only the group admin can disband.")
            return
        if not mbox.askyesno("Disband group", f'Disband "{g.name}"?\nThis will close the group for everyone.'):
            return
        self.backend.disband_group(g.group_uid)

    def _append_chat(self, text: str, tag: str):
        self.chat_box.configure(state="normal")
        self.chat_box.insert(tk.END, text + "\n", (tag,))
        self.chat_box.see(tk.END)
        self.chat_box.configure(state="disabled")

    # ---------- list / dropdown syncing ----------

    def _refresh_lists(self):
        # Friends dropdown
        friends = list(self.state.friends.values())
        friends.sort(key=lambda f: (not f.online, f.name.lower(), f.public_uid))

        friend_labels: List[str] = []
        self._friend_order = []
        for f in friends:
            dot = "🟢" if f.online else "⚫"
            friend_labels.append(f"{dot} {f.name}")
            self._friend_order.append(f.public_uid)

        self.friend_combo["values"] = friend_labels
        if self.state.current_kind == "dm" and self.state.current_peer in self._friend_order:
            idx = self._friend_order.index(self.state.current_peer)
            self.friend_combo.current(idx)
        else:
            self.friend_combo.set("")

        # Groups dropdown
        groups = list(self.state.groups.values())
        groups.sort(key=lambda g: g.name.lower())

        group_labels: List[str] = []
        self._group_order = []
        for g in groups:
            badge = "👑" if g.role == "admin" else "👥"
            group_labels.append(f"{badge} {g.name}")
            self._group_order.append(g.group_uid)

        self.group_combo["values"] = group_labels
        if self.state.current_kind == "group" and self.state.current_peer in self._group_order:
            idx = self._group_order.index(self.state.current_peer)
            self.group_combo.current(idx)
        else:
            self.group_combo.set("")

    def _selected_friend_obj(self) -> Optional[Friend]:
        idx = self.friend_combo.current()
        if idx is None or idx < 0 or idx >= len(self._friend_order):
            return None
        uid = self._friend_order[idx]
        return self.state.friends.get(uid)

    def _selected_group_obj(self) -> Optional[Group]:
        idx = self.group_combo.current()
        if idx is None or idx < 0 or idx >= len(self._group_order):
            return None
        gid = self._group_order[idx]
        return self.state.groups.get(gid)

    # ---------- selection handlers ----------

    def _on_select_friend(self, _e=None):
        f = self._selected_friend_obj()
        if not f:
            return
        self.state.current_kind = "dm"
        self.state.current_peer = f.public_uid
        self.chat_title["text"] = f"DM: {f.name}"
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0", tk.END)
        self.chat_box.configure(state="disabled")
        self.backend.request_history("dm", f.public_uid, 100)

    def _on_select_group(self, _e=None):
        g = self._selected_group_obj()
        if not g:
            return
        self.state.current_kind = "group"
        self.state.current_peer = g.group_uid
        self.chat_title["text"] = f"Group: {g.name}"
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0", tk.END)
        self.chat_box.configure(state="disabled")
        self.backend.request_history("group", g.group_uid, 120)

    # ---------- sending ----------

    def send_message(self):
        text = self.msg_entry.get().strip()
        if not text:
            return
        if not self.state.current_peer:
            mbox.showwarning("No chat", "Pick a friend or group first.")
            return
        kind = self.state.current_kind
        peer = self.state.current_peer
        self.backend.send_text(kind, peer, text)

        # Local echo: my message on the right, no "You:" prefix
        self._append_chat(text, "me")
        self.msg_entry.delete(0, tk.END)

    # ---------- events ----------

    def on_authed(self):
        self.status["text"] = "Logged in. Syncing…"

    def _poll_events(self):
        processed = 0
        while True:
            try:
                pkt = self.backend.events.get_nowait()
            except queue.Empty:
                break
            processed += 1
            self._handle_event(pkt)

        if processed:
            self._refresh_lists()
            if self.requests_win and self.requests_win.winfo_exists():
                self.requests_win.refresh()

        self.after(60, self._poll_events)

    def _handle_event(self, pkt: dict):
        t = pkt.get("type")

        if t == "_closed":
            self.status["text"] = "Disconnected."
            return

        if t == "sync":
            me = pkt.get("me") or {}
            self.state.me_name = str(me.get("name") or "")
            self.state.me_email = str(me.get("email") or "")
            self.state.me_uid = str(me.get("public_uid") or "")
            self.me_label["text"] = f'Logged in as {self.state.me_name} ({self.state.me_email})'

            self.state.friends.clear()
            for f in pkt.get("friends") or []:
                uid = str(f.get("public_uid") or "")
                if not uid:
                    continue
                self.state.friends[uid] = Friend(
                    name=str(f.get("name") or uid),
                    public_uid=uid,
                    online=bool(f.get("online")),
                )

            self.state.groups.clear()
            for g in pkt.get("groups") or []:
                gid = str(g.get("group_uid") or "")
                if not gid:
                    continue
                self.state.groups[gid] = Group(
                    group_uid=gid,
                    name=str(g.get("name") or gid),
                    role=str(g.get("role") or "member"),
                )

            self.state.friend_requests = list(pkt.get("friend_requests") or [])
            self.state.group_invites = list(pkt.get("group_invites") or [])

            self.status["text"] = f"Synced. UID: {self.state.me_uid}"
            return

        if t == "contacts_sync":
            self.state.friends.clear()
            for f in pkt.get("friends") or []:
                uid = str(f.get("public_uid") or "")
                if not uid:
                    continue
                self.state.friends[uid] = Friend(
                    name=str(f.get("name") or uid),
                    public_uid=uid,
                    online=bool(f.get("online")),
                )
            self.status["text"] = "Contacts updated."
            return

        if t == "groups_sync":
            self.state.groups.clear()
            for g in pkt.get("groups") or []:
                gid = str(g.get("group_uid") or "")
                if not gid:
                    continue
                self.state.groups[gid] = Group(
                    group_uid=gid,
                    name=str(g.get("name") or gid),
                    role=str(g.get("role") or "member"),
                )
            self.status["text"] = "Groups updated."
            return

        if t == "presence_update":
            uid = str(pkt.get("uid") or "")
            online = bool(pkt.get("online"))
            name = str(pkt.get("name") or uid)
            f = self.state.friends.get(uid)
            if not f:
                self.state.friends[uid] = Friend(name=name, public_uid=uid, online=online)
            else:
                was = f.online
                f.online = online
                if (not was) and online:
                    self.status["text"] = f"🟢 {f.name} is online"
            return

        if t == "friend_request":
            rid = str(pkt.get("request_id") or "")
            if rid and any(x.get("request_id") == rid for x in self.state.friend_requests):
                return
            self.state.friend_requests.append({
                "request_id": rid,
                "from_name": str(pkt.get("from_name") or ""),
                "from_uid": str(pkt.get("from_uid") or ""),
                "created_at": pkt.get("created_at", now_ts()),
            })
            self.status["text"] = "New friend request received."
            return

        if t in ("friend_request_sent", "friend_request_fail", "friend_request_result", "friend_request_outcome"):
            msg = str(pkt.get("message") or pkt.get("status") or t)
            self.status["text"] = f"Friend: {msg}"
            return

        if t == "group_invite":
            iid = str(pkt.get("invite_id") or "")
            if iid and any(x.get("invite_id") == iid for x in self.state.group_invites):
                return
            self.state.group_invites.append({
                "invite_id": iid,
                "group_uid": str(pkt.get("group_uid") or ""),
                "group_name": str(pkt.get("group_name") or ""),
                "from_name": str(pkt.get("from_name") or ""),
                "from_uid": str(pkt.get("from_uid") or ""),
                "created_at": pkt.get("created_at", now_ts()),
            })
            self.status["text"] = "New group invite received."
            return

        if t in ("group_invite_result", "group_invite_outcome", "group_create_result", "group_disband_result"):
            msg = str(pkt.get("message") or pkt.get("status") or t)
            self.status["text"] = f"Group: {msg}"
            return

        if t == "dm":
            msg = ChatMessage(
                id=str(pkt.get("id") or ""),
                kind="dm",
                peer=str(pkt.get("from_uid") or ""),
                from_uid=str(pkt.get("from_uid") or ""),
                from_name=str(pkt.get("from_name") or ""),
                text=str(pkt.get("text") or ""),
                ts=float(pkt.get("ts") or now_ts()),
            )
            self.state.chat_cache.setdefault(("dm", msg.peer), []).append(msg)

            # Incoming DM from someone else
            if msg.from_uid == self.state.me_uid:
                return

            if self.state.current_kind == "dm" and self.state.current_peer == msg.peer:
                display = f'{msg.from_name}: {msg.text}'
                self._append_chat(display, "them")
            else:
                self.status["text"] = f'New message from {msg.from_name}'
            return

        if t == "dm_history" and pkt.get("ok") is True:
            peer = str(pkt.get("peer_uid") or "")
            msgs: List[ChatMessage] = []
            for m in pkt.get("messages") or []:
                msgs.append(ChatMessage(
                    id=str(m.get("id") or ""),
                    kind="dm",
                    peer=peer,
                    from_uid=str(m.get("from_uid") or ""),
                    from_name=str(m.get("from_name") or ""),
                    text=str(m.get("text") or ""),
                    ts=float(m.get("ts") or now_ts()),
                ))
            self.state.chat_cache[("dm", peer)] = msgs
            if self.state.current_kind == "dm" and self.state.current_peer == peer:
                self.chat_box.configure(state="normal")
                self.chat_box.delete("1.0", tk.END)
                self.chat_box.configure(state="disabled")
                for m in msgs:
                    if m.from_uid == self.state.me_uid:
                        text = m.text
                        tag = "me"
                    else:
                        text = f"{m.from_name}: {m.text}"
                        tag = "them"
                    self._append_chat(text, tag)
            return

        if t in ("group_message", "group_msg"):
            gid = str(pkt.get("group_uid") or "")
            msg = ChatMessage(
                id=str(pkt.get("id") or ""),
                kind="group",
                peer=gid,
                from_uid=str(pkt.get("from_uid") or ""),
                from_name=str(pkt.get("from_name") or ""),
                text=str(pkt.get("text") or ""),
                ts=float(pkt.get("ts") or now_ts()),
            )
            self.state.chat_cache.setdefault(("group", gid), []).append(msg)

            if msg.from_uid == self.state.me_uid:
                return

            if self.state.current_kind == "group" and self.state.current_peer == gid:
                display = f'{msg.from_name}: {msg.text}'
                self._append_chat(display, "them")
            else:
                self.status["text"] = f'New group message in {pkt.get("group_name") or gid}'
            return

        if t == "group_history" and pkt.get("ok") is True:
            gid = str(pkt.get("group_uid") or "")
            msgs: List[ChatMessage] = []
            for m in pkt.get("messages") or []:
                msgs.append(ChatMessage(
                    id=str(m.get("id") or ""),
                    kind="group",
                    peer=gid,
                    from_uid=str(m.get("from_uid") or ""),
                    from_name=str(m.get("from_name") or ""),
                    text=str(m.get("text") or ""),
                    ts=float(m.get("ts") or now_ts()),
                ))
            self.state.chat_cache[("group", gid)] = msgs
            if self.state.current_kind == "group" and self.state.current_peer == gid:
                self.chat_box.configure(state="normal")
                self.chat_box.delete("1.0", tk.END)
                self.chat_box.configure(state="disabled")
                for m in msgs:
                    if m.from_uid == self.state.me_uid:
                        text = m.text
                        tag = "me"
                    else:
                        text = f"{m.from_name}: {m.text}"
                        tag = "them"
                    self._append_chat(text, tag)
            return

        if t == "group_disbanded":
            gid = str(pkt.get("group_uid") or "")
            if gid in self.state.groups:
                del self.state.groups[gid]
            if self.state.current_kind == "group" and self.state.current_peer == gid:
                self.state.current_peer = ""
                self.chat_title["text"] = "Group disbanded"
                self.chat_box.configure(state="normal")
                self.chat_box.delete("1.0", tk.END)
                self.chat_box.configure(state="disabled")
            self.status["text"] = f'Group disbanded: {pkt.get("group_name")}'
            return

        if t == "error":
            self.status["text"] = f'Error: {pkt.get("message")}'
            return


# ---------------------------- Small prompt ----------------------------


def simple_prompt(root: tk.Tk, title: str, label: str) -> Optional[str]:
    win = tk.Toplevel(root)
    win.title(title)
    win.resizable(False, False)

    out: Dict[str, Optional[str]] = {"val": None}

    frame = ttk.Frame(win, padding=12)
    frame.pack(fill="both", expand=True)

    ttk.Label(frame, text=label).pack(anchor="w")
    ent = ttk.Entry(frame, width=42)
    ent.pack(fill="x", pady=(6, 12))
    ent.focus_set()

    def ok():
        out["val"] = ent.get().strip()
        win.destroy()

    def cancel():
        out["val"] = None
        win.destroy()

    btns = ttk.Frame(frame)
    btns.pack(fill="x")
    ttk.Button(btns, text="OK", command=ok).pack(side="left")
    ttk.Button(btns, text="Cancel", command=cancel).pack(side="left", padx=(8, 0))

    win.bind("<Return>", lambda _e: ok())
    win.bind("<Escape>", lambda _e: cancel())

    win.transient(root)
    win.grab_set()
    root.wait_window(win)
    return out["val"]


# ---------------------------- main ----------------------------


def main():
    state = AppState()
    backend = Backend(state)

    root = tk.Tk()

    host = os.getenv("CHAT_HOST", "127.0.0.1")
    port_s = os.getenv("CHAT_PORT", "54678")
    try:
        port = int(port_s)
    except Exception:
        port = 54678

    if not backend.connect(host, port):
        mbox.showerror("Client", backend.last_error or "Could not connect.")
        root.destroy()
        return

    ui = MainUI(root, backend, state)

    def authed():
        ui.on_authed()

    LoginWindow(root, backend, authed)

    def on_close():
        backend.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
