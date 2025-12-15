import os
import re
import io
import json
import asyncio
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Tuple

import asyncpg
import httpx
import qrcode
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from zoneinfo import ZoneInfo
from nacl.signing import VerifyKey

KST = ZoneInfo("Asia/Seoul")

# ----------------------------
# Env
# ----------------------------
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_PUBLIC_KEY = os.getenv("DISCORD_PUBLIC_KEY", "").strip()
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()

DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "").strip()
DISCORD_ADMIN_CHANNEL_ID = os.getenv("DISCORD_ADMIN_CHANNEL_ID", "").strip()
DISCORD_ADMIN_ROLE_ID = os.getenv("DISCORD_ADMIN_ROLE_ID", "").strip()
DISCORD_PING_ROLE_ID = os.getenv("DISCORD_PING_ROLE_ID", "").strip()

SESSION_SECRET = os.getenv("SESSION_SECRET", "dev_secret_change_me")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "").strip()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
HTTPS_ONLY = os.getenv("HTTPS_ONLY", "true").lower() == "true"

BASE_URL = os.getenv("BASE_URL", "").strip()  # optional for local dev; otherwise derived from request

# ----------------------------
# App
# ----------------------------
app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=HTTPS_ONLY,
    same_site="lax",
)
templates = Jinja2Templates(directory="templates")

_db_pool: Optional[asyncpg.Pool] = None

# ----------------------------
# Helpers
# ----------------------------
def _now_kst() -> datetime:
    return datetime.now(tz=KST)

def _kst_date() -> date:
    return _now_kst().date()

def _format_hhmm_kst(dt: datetime) -> str:
    return dt.astimezone(KST).strftime("%H:%M")

def _safe_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^0-9a-z가-힣\-_]+", "", s)
    s = s.strip("-_")
    if not s:
        s = "place"
    return s[:32]

async def db() -> asyncpg.Pool:
    if _db_pool is None:
        raise RuntimeError("DB pool not initialized")
    return _db_pool

async def discord_api(method: str, path: str, *, json_body: Any = None, params: Dict[str, Any] | None = None) -> httpx.Response:
    if not DISCORD_BOT_TOKEN:
        raise RuntimeError("DISCORD_BOT_TOKEN not set")
    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "User-Agent": "qr-checkin-bot (https://railway.app, 0.1)",
    }
    url = f"https://discord.com/api/v10{path}"
    async with httpx.AsyncClient(timeout=20) as client:
        return await client.request(method, url, headers=headers, json=json_body, params=params)

async def get_guild_member_display(user_id: str) -> Tuple[str, str]:
    """
    Returns (server_display_name, username)
    """
    if not DISCORD_GUILD_ID:
        return (user_id, user_id)
    try:
        r = await discord_api("GET", f"/guilds/{DISCORD_GUILD_ID}/members/{user_id}")
        if r.status_code != 200:
            return (user_id, user_id)
        data = r.json()
        nick = (data.get("nick") or "").strip()
        u = data.get("user") or {}
        username = (u.get("username") or "").strip() or str(user_id)
        global_name = (u.get("global_name") or "").strip()
        server_display = nick or global_name or username
        return (server_display, username)
    except Exception:
        return (user_id, user_id)

def _is_admin_from_interaction(interaction: Dict[str, Any]) -> bool:
    member = interaction.get("member") or {}
    if DISCORD_ADMIN_ROLE_ID:
        roles = member.get("roles") or []
        return str(DISCORD_ADMIN_ROLE_ID) in [str(r) for r in roles]
    # fallback: Administrator permission bit (0x8)
    perms = member.get("permissions")
    try:
        perms_int = int(perms) if perms is not None else 0
        return (perms_int & 0x8) == 0x8
    except Exception:
        return False

def _ephemeral_message(content: str, *, components: Optional[List[Dict[str, Any]]] = None, embeds: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    data: Dict[str, Any] = {"content": content, "flags": 64}
    if components is not None:
        data["components"] = components
    if embeds is not None:
        data["embeds"] = embeds
    return {"type": 4, "data": data}

def _defer_ephemeral() -> Dict[str, Any]:
    return {"type": 5, "data": {"flags": 64}}

def _update_message(*, content: Optional[str] = None, components: Optional[List[Dict[str, Any]]] = None, embeds: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    if content is not None:
        data["content"] = content
    if components is not None:
        data["components"] = components
    if embeds is not None:
        data["embeds"] = embeds
    return {"type": 7, "data": data}

def _modal(custom_id: str, title: str, label: str, placeholder: str = "", value: str = "") -> Dict[str, Any]:
    return {
        "type": 9,
        "data": {
            "custom_id": custom_id,
            "title": title,
            "components": [
                {
                    "type": 1,
                    "components": [
                        {
                            "type": 4,
                            "custom_id": "text",
                            "style": 1,
                            "label": label,
                            "min_length": 1,
                            "max_length": 80,
                            "required": True,
                            "placeholder": placeholder,
                            **({"value": value} if value else {}),
                        }
                    ],
                }
            ],
        },
    }

def _select_menu(custom_id: str, placeholder: str, options: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "type": 1,
            "components": [
                {
                    "type": 3,
                    "custom_id": custom_id,
                    "placeholder": placeholder,
                    "min_values": 1,
                    "max_values": 1,
                    "options": options[:25],
                }
            ],
        }
    ]

async def _send_admin_log(text: str) -> None:
    if not DISCORD_ADMIN_CHANNEL_ID:
        return
    try:
        await discord_api("POST", f"/channels/{DISCORD_ADMIN_CHANNEL_ID}/messages", json_body={"content": text})
    except Exception:
        pass

async def _send_dm(user_id: str, text: str) -> bool:
    try:
        r = await discord_api("POST", "/users/@me/channels", json_body={"recipient_id": str(user_id)})
        if r.status_code != 200:
            return False
        ch_id = (r.json() or {}).get("id")
        if not ch_id:
            return False
        r2 = await discord_api("POST", f"/channels/{ch_id}/messages", json_body={"content": text})
        return r2.status_code in (200, 201)
    except Exception:
        return False

def _get_base_url(request: Request) -> str:
    if BASE_URL:
        return BASE_URL.rstrip("/")
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.hostname
    return f"{scheme}://{host}".rstrip("/")

# ----------------------------
# DB Schema
# ----------------------------
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS places (
  id SERIAL PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  nickname TEXT NOT NULL,
  created_by BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS visits (
  id SERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  place_id INT NOT NULL REFERENCES places(id) ON DELETE CASCADE,
  visit_date DATE NOT NULL,
  visit_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  server_display_name TEXT,
  username TEXT,
  UNIQUE(user_id, place_id, visit_date)
);

CREATE INDEX IF NOT EXISTS idx_visits_place_date ON visits(place_id, visit_date);
CREATE INDEX IF NOT EXISTS idx_visits_user_place ON visits(user_id, place_id);
"""

# ----------------------------
# OAuth (visitor login)
# ----------------------------
DISCORD_AUTH_URL = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_ME_URL = "https://discord.com/api/users/@me"

def _require_env() -> None:
    missing = []
    for k in ["DISCORD_CLIENT_ID","DISCORD_CLIENT_SECRET","DISCORD_PUBLIC_KEY","DISCORD_BOT_TOKEN","DATABASE_URL","OAUTH_REDIRECT_URI"]:
        if not os.getenv(k):
            missing.append(k)
    if missing:
        raise RuntimeError(f"Missing env vars: {', '.join(missing)}")

async def exchange_code_for_token(code: str) -> str:
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OAUTH_REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(DISCORD_TOKEN_URL, data=data, headers=headers)
        if r.status_code != 200:
            raise HTTPException(status_code=400, detail="OAuth token exchange failed")
        return (r.json() or {}).get("access_token")

async def fetch_discord_user(access_token: str) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(DISCORD_ME_URL, headers=headers)
        if r.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user")
        return r.json()

# ----------------------------
# Startup
# ----------------------------
async def ensure_commands() -> None:
    """
    Register guild commands for fast iteration.
    """
    if not DISCORD_GUILD_ID or not DISCORD_CLIENT_ID or not DISCORD_BOT_TOKEN:
        return

    commands = [
        {
            "name": "qr생성",
            "description": "QR 장소를 생성합니다 (닉네임 설정). 생성 시 QR 이미지는 표시하지 않습니다.",
            "options": [
                {"type": 3, "name": "닉네임", "description": "표시할 장소 닉네임", "required": True},
                {"type": 3, "name": "슬러그", "description": "URL용 키(선택). 비우면 자동 생성", "required": False},
            ],
        },
        {"name": "qr닉네임수정", "description": "기존 QR 장소의 닉네임을 수정합니다 (선택 후 입력)."},
        {"name": "qr조회", "description": "생성된 QR 코드를 조회합니다 (호출자에게만 표시)."},
        {"name": "qr삭제", "description": "생성된 QR 장소를 삭제합니다."},
        {
            "name": "유저방문기록",
            "description": "특정 유저의 장소별 방문기록을 조회합니다.",
            "options": [{"type": 6, "name": "유저", "description": "조회할 유저", "required": True}],
        },
        {"name": "장소방문기록", "description": "특정 장소의 유저별 방문기록을 조회합니다(10개 단위 페이지)."},
        {
            "name": "체크인초기화",
            "description": "특정 유저의 특정 장소 '오늘 체크인'을 초기화합니다.",
            "options": [{"type": 6, "name": "유저", "description": "대상 유저", "required": True}],
        },
        {
            "name": "방문기록삭제",
            "description": "특정 유저의 특정 장소 방문기록을 삭제합니다.",
            "options": [{"type": 6, "name": "유저", "description": "대상 유저", "required": True}],
        },
    ]
    r = await discord_api("PUT", f"/applications/{DISCORD_CLIENT_ID}/guilds/{DISCORD_GUILD_ID}/commands", json_body=commands)
    if r.status_code not in (200, 201):
        print("Command register failed:", r.status_code, r.text)

@app.on_event("startup")
async def on_startup():
    global _db_pool
    _require_env()
    _db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5, command_timeout=30)
    async with _db_pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)
    await ensure_commands()

@app.on_event("shutdown")
async def on_shutdown():
    global _db_pool
    if _db_pool:
        await _db_pool.close()
        _db_pool = None

# ----------------------------
# Web routes
# ----------------------------
@app.get("/health")
async def health():
    return {"ok": True}

async def get_place_by_slug(slug: str) -> Optional[Dict[str, Any]]:
    pool = await db()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id, slug, nickname FROM places WHERE slug=$1", slug)
    return dict(row) if row else None

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, loc: str = ""):
    slug = (loc or "").strip()
    if slug:
        place = await get_place_by_slug(slug)
        place_name = place["nickname"] if place else "등록되지 않은 장소"
    else:
        place_name = "장소 정보 없음"

    is_logged_in = bool(request.session.get("user"))
    status_text = "로그인 필요" if not is_logged_in else "로그인됨"
    logout_style = "" if is_logged_in else "display:none;"

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "loc": slug, "place_name": place_name, "is_logged_in": is_logged_in, "status_text": status_text, "logout_style": logout_style},
    )

@app.get("/login")
async def login(request: Request, loc: str = ""):
    if loc:
        request.session["return_loc"] = loc

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "prompt": "none",
    }
    url = str(httpx.URL(DISCORD_AUTH_URL).copy_merge_params(params))
    return RedirectResponse(url, status_code=302)

@app.get("/oauth/callback")
async def oauth_callback(request: Request, code: str = ""):
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")

    token = await exchange_code_for_token(code)
    user = await fetch_discord_user(token)

    request.session["user"] = {"id": user.get("id"), "username": user.get("username"), "global_name": user.get("global_name")}

    loc = (request.session.pop("return_loc", "") or "").strip()
    if loc:
        return RedirectResponse(f"/?loc={loc}", status_code=302)
    return RedirectResponse("/", status_code=302)

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=302)

@app.post("/api/checkin")
async def api_checkin(request: Request):
    body = await request.json()
    slug = (body.get("loc") or "").strip()
    if not slug:
        raise HTTPException(status_code=400, detail="loc is required")

    place = await get_place_by_slug(slug)
    if not place:
        raise HTTPException(status_code=404, detail="등록되지 않은 장소입니다.")

    user = request.session.get("user")
    if not user or not user.get("id"):
        raise HTTPException(status_code=401, detail="로그인 필요")

    user_id = str(user["id"])
    username = (user.get("username") or "").strip() or user_id

    # enrich with server nickname if possible
    server_display, _uname = await get_guild_member_display(user_id)
    if server_display == user_id:
        server_display = (user.get("global_name") or "").strip() or username

    today = _kst_date()
    now = _now_kst()
    pool = await db()

    inserted = False
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO visits(user_id, place_id, visit_date, server_display_name, username)
            VALUES($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
            RETURNING id
            """,
            int(user_id), int(place["id"]), today, server_display, username,
        )
        inserted = row is not None

        count = await conn.fetchval("SELECT COUNT(*) FROM visits WHERE user_id=$1 AND place_id=$2", int(user_id), int(place["id"]))

    place_nickname = place["nickname"]

    if inserted:
        dm_text = f"{server_display}님 {place_nickname} 방문을 환영합니다! (누적 {count}번째 방문이시네요)"
        dm_ok = await _send_dm(user_id, dm_text)
    else:
        dm_ok = True

    admin_label = "오늘 첫 방문" if inserted else "이미 오늘 방문"
    ping = f"\n<@&{DISCORD_PING_ROLE_ID}>" if DISCORD_PING_ROLE_ID else ""
    visitor_line = f"{server_display} ({username})"
    visit_time_str = _format_hhmm_kst(now)

    admin_text = (
        f"## [입장 알림] {server_display}님이 체크인했습니다! ({admin_label})\n"
        f"방문자 : {visitor_line}\n"
        f"방문 시간 : {visit_time_str} (KST)\n"
        f"방문 횟수 : {count}번째 방문\n"
        f"{place_nickname} : {slug}"
        + ("" if dm_ok else "\n※ DM 전송 실패(사용자 DM 차단 가능)")
        + ping
    )
    await _send_admin_log(admin_text)

    msg = f"{place_nickname} 체크인 완료" if inserted else f"오늘은 이미 {place_nickname} 체크인했습니다."
    return {"ok": True, "message": msg}

# ----------------------------
# Discord Interactions
# ----------------------------
def _verify_discord_signature(headers: Dict[str, str], raw_body: bytes) -> bool:
    try:
        sig = headers.get("x-signature-ed25519") or headers.get("X-Signature-Ed25519")
        ts = headers.get("x-signature-timestamp") or headers.get("X-Signature-Timestamp")
        if not sig or not ts or not DISCORD_PUBLIC_KEY:
            return False
        verify_key = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY))
        verify_key.verify(ts.encode("utf-8") + raw_body, bytes.fromhex(sig))
        return True
    except Exception:
        return False

async def _places_options() -> List[Dict[str, Any]]:
    pool = await db()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT id, nickname, slug FROM places ORDER BY id DESC LIMIT 200")
    opts = []
    for r in rows:
        label = str(r["nickname"])[:100]
        desc = f"loc={r['slug']}"[:100]
        opts.append({"label": label, "value": str(r["id"]), "description": desc})
    return opts

async def _place_by_id(place_id: int) -> Optional[Dict[str, Any]]:
    pool = await db()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id, slug, nickname FROM places WHERE id=$1", place_id)
    return dict(row) if row else None

def _make_qr_png(url: str) -> bytes:
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

async def _interaction_followup_send(interaction_token: str, *, content: str, file_bytes: Optional[bytes] = None, filename: str = "file.png") -> None:
    if not DISCORD_CLIENT_ID:
        return
    url = f"https://discord.com/api/v10/webhooks/{DISCORD_CLIENT_ID}/{interaction_token}"
    payload = {"content": content, "flags": 64}
    async with httpx.AsyncClient(timeout=20) as client:
        if file_bytes is None:
            await client.post(url, json=payload)
            return
        files = {
            "payload_json": (None, json.dumps(payload), "application/json"),
            "files[0]": (filename, file_bytes, "image/png"),
        }
        await client.post(url, files=files)

async def _render_place_history_update(*, place_id: int, page: int) -> JSONResponse:
    place = await _place_by_id(place_id)
    if not place:
        return JSONResponse(_ephemeral_message("장소를 찾을 수 없습니다."))

    per_page = 10
    pool = await db()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(DISTINCT user_id) FROM visits WHERE place_id=$1", int(place_id))
        total_pages = max(1, (int(total) + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))
        offset = (page - 1) * per_page
        rows = await conn.fetch(
            """
            SELECT user_id,
                   COALESCE(MAX(server_display_name), '') as server_display_name,
                   COALESCE(MAX(username), '') as username,
                   COUNT(*) as cnt,
                   MAX(visit_at) as last_at
            FROM visits
            WHERE place_id=$1
            GROUP BY user_id
            ORDER BY last_at DESC
            LIMIT $2 OFFSET $3
            """,
            int(place_id), per_page, offset,
        )

    lines = []
    for r in rows:
        name = (r["server_display_name"] or "").strip() or str(r["user_id"])
        uname = (r["username"] or "").strip() or str(r["user_id"])
        last_kst = r["last_at"].astimezone(KST).strftime("%Y-%m-%d %H:%M")
        lines.append(f"- **{name}** ({uname}): {r['cnt']}회 · 마지막 {last_kst}")

    if not lines:
        lines = ["(기록 없음)"]

    embed = {"title": f"장소 방문기록 — {place['nickname']}", "description": "\n".join(lines), "footer": {"text": f"{page}/{total_pages} 페이지"}}
    components = [
        {
            "type": 1,
            "components": [
                {"type": 2, "style": 2, "custom_id": f"place_history_page:{page-1}:{place_id}", "label": "◀", "disabled": page <= 1},
                {"type": 2, "style": 2, "custom_id": "noop", "label": f"{page}/{total_pages}", "disabled": True},
                {"type": 2, "style": 2, "custom_id": f"place_history_page:{page+1}:{place_id}", "label": "▶", "disabled": page >= total_pages},
            ],
        }
    ]
    return JSONResponse(_update_message(content="", embeds=[embed], components=components))

@app.post("/discord/interactions")
async def discord_interactions(request: Request):
    raw = await request.body()
    if not _verify_discord_signature(request.headers, raw):
        raise HTTPException(status_code=401, detail="bad signature")

    interaction = json.loads(raw.decode("utf-8"))

    if interaction.get("type") == 1:
        return JSONResponse({"type": 1})

    itype = interaction.get("type")
    data = interaction.get("data") or {}
    name = data.get("name")

    # ------------------ Commands ------------------
    if itype == 2:
        if not _is_admin_from_interaction(interaction):
            return JSONResponse(_ephemeral_message("권한이 없습니다."))

        if name == "qr생성":
            opts = {o["name"]: o.get("value") for o in (data.get("options") or [])}
            nickname = str(opts.get("닉네임") or "").strip()
            slug_in = str(opts.get("슬러그") or "").strip()
            if not nickname:
                return JSONResponse(_ephemeral_message("닉네임을 입력해주세요."))

            slug = _safe_slug(slug_in or nickname)

            pool = await db()
            async with pool.acquire() as conn:
                exists = await conn.fetchval("SELECT 1 FROM places WHERE slug=$1", slug)
                if exists:
                    slug = (slug + "-" + str(int(datetime.utcnow().timestamp()))[-4:])[:32]
                user_id = int(((interaction.get("member") or {}).get("user") or {}).get("id") or 0)
                await conn.execute("INSERT INTO places(slug, nickname, created_by) VALUES($1,$2,$3)", slug, nickname, user_id)

            base = _get_base_url(request)
            url = f"{base}/?loc={slug}"
            content = (
                "✅ QR 장소 생성 완료\n"
                f"- 닉네임: **{nickname}**\n"
                f"- loc: `{slug}`\n"
                f"- 링크(이걸로 QR 생성): {url}\n\n"
                "※ 생성 명령어에서는 QR 이미지를 표시하지 않습니다."
            )
            return JSONResponse(_ephemeral_message(content))

        if name == "qr조회":
            options = await _places_options()
            if not options:
                return JSONResponse(_ephemeral_message("등록된 장소가 없습니다. 먼저 `/qr생성`을 실행하세요."))
            return JSONResponse(_ephemeral_message("조회할 장소를 선택하세요.", components=_select_menu("qr_view_select", "장소 선택", options)))

        if name == "qr닉네임수정":
            options = await _places_options()
            if not options:
                return JSONResponse(_ephemeral_message("등록된 장소가 없습니다."))
            return JSONResponse(_ephemeral_message("닉네임을 수정할 장소를 선택하세요.", components=_select_menu("qr_rename_select", "장소 선택", options)))

        if name == "qr삭제":
            options = await _places_options()
            if not options:
                return JSONResponse(_ephemeral_message("등록된 장소가 없습니다."))
            return JSONResponse(_ephemeral_message("삭제할 장소를 선택하세요.", components=_select_menu("qr_delete_select", "장소 선택", options)))

        if name == "유저방문기록":
            opts = {o["name"]: o.get("value") for o in (data.get("options") or [])}
            uid = str(opts.get("유저") or "").strip()
            if not uid:
                return JSONResponse(_ephemeral_message("유저를 선택해주세요."))
            pool = await db()
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT p.nickname, p.slug, COUNT(*) as cnt, MAX(v.visit_at) as last_at
                    FROM visits v
                    JOIN places p ON p.id=v.place_id
                    WHERE v.user_id=$1
                    GROUP BY p.nickname, p.slug
                    ORDER BY last_at DESC
                    """,
                    int(uid),
                )
            if not rows:
                return JSONResponse(_ephemeral_message("해당 유저의 방문 기록이 없습니다."))
            lines = []
            for r in rows[:30]:
                last_kst = r["last_at"].astimezone(KST).strftime("%Y-%m-%d %H:%M")
                lines.append(f"- **{r['nickname']}** (`{r['slug']}`): {r['cnt']}회 (마지막 {last_kst})")
            if len(rows) > 30:
                lines.append(f"...외 {len(rows)-30}개 더")
            embed = {"title": "유저 방문기록", "description": "\n".join(lines)}
            return JSONResponse(_ephemeral_message("", embeds=[embed]))

        if name == "장소방문기록":
            options = await _places_options()
            if not options:
                return JSONResponse(_ephemeral_message("등록된 장소가 없습니다."))
            return JSONResponse(_ephemeral_message("조회할 장소를 선택하세요.", components=_select_menu("place_history_select", "장소 선택", options)))

        if name == "체크인초기화":
            opts = {o["name"]: o.get("value") for o in (data.get("options") or [])}
            uid = str(opts.get("유저") or "").strip()
            if not uid:
                return JSONResponse(_ephemeral_message("유저를 선택해주세요."))
            options = await _places_options()
            if not options:
                return JSONResponse(_ephemeral_message("등록된 장소가 없습니다."))
            return JSONResponse(_ephemeral_message("초기화할 장소를 선택하세요.", components=_select_menu(f"reset_select:{uid}", "장소 선택", options)))

        if name == "방문기록삭제":
            opts = {o["name"]: o.get("value") for o in (data.get("options") or [])}
            uid = str(opts.get("유저") or "").strip()
            if not uid:
                return JSONResponse(_ephemeral_message("유저를 선택해주세요."))
            options = await _places_options()
            if not options:
                return JSONResponse(_ephemeral_message("등록된 장소가 없습니다."))
            return JSONResponse(_ephemeral_message("삭제할 장소를 선택하세요.", components=_select_menu(f"delete_visits_select:{uid}", "장소 선택", options)))

        return JSONResponse(_ephemeral_message("알 수 없는 명령입니다."))

    # ------------------ Components ------------------
    if itype == 3:
        cid = (data.get("custom_id") or "")
        if cid == "noop":
            return JSONResponse(_update_message())

        if cid in ("qr_view_select", "qr_rename_select", "qr_delete_select", "place_history_select"):
            values = data.get("values") or []
            if not values:
                return JSONResponse(_ephemeral_message("선택값이 없습니다."))
            place_id = int(values[0])
            place = await _place_by_id(place_id)
            if not place:
                return JSONResponse(_ephemeral_message("장소를 찾을 수 없습니다."))

            if cid == "qr_view_select":
                token = interaction.get("token")
                base = _get_base_url(request)
                url = f"{base}/?loc={place['slug']}"
                png = _make_qr_png(url)
                asyncio.create_task(_interaction_followup_send(token, content=f"**{place['nickname']}** QR 코드", file_bytes=png, filename=f"{place['slug']}.png"))
                return JSONResponse(_defer_ephemeral())

            if cid == "qr_rename_select":
                return JSONResponse(_modal(f"qr_rename_modal:{place_id}", "QR 닉네임 수정", "새 닉네임", placeholder="예) 비트코인하우스오리진", value=place["nickname"]))

            if cid == "qr_delete_select":
                components = [
                    {
                        "type": 1,
                        "components": [
                            {"type": 2, "style": 4, "custom_id": f"qr_delete_confirm:{place_id}", "label": "삭제"},
                            {"type": 2, "style": 2, "custom_id": "qr_delete_cancel", "label": "취소"},
                        ],
                    }
                ]
                return JSONResponse(_update_message(content=f"정말 **{place['nickname']}** (`{place['slug']}`) 를 삭제할까요?", components=components))

            if cid == "place_history_select":
                return await _render_place_history_update(place_id=place_id, page=1)

        if cid.startswith("reset_select:"):
            uid = cid.split(":", 1)[1]
            values = data.get("values") or []
            if not values:
                return JSONResponse(_ephemeral_message("선택값이 없습니다."))
            place_id = int(values[0])
            today = _kst_date()
            pool = await db()
            async with pool.acquire() as conn:
                await conn.execute("DELETE FROM visits WHERE user_id=$1 AND place_id=$2 AND visit_date=$3", int(uid), int(place_id), today)
            return JSONResponse(_update_message(content=f"✅ 초기화 완료 (user={uid}, place_id={place_id})", components=[]))

        if cid.startswith("delete_visits_select:"):
            uid = cid.split(":", 1)[1]
            values = data.get("values") or []
            if not values:
                return JSONResponse(_ephemeral_message("선택값이 없습니다."))
            place_id = int(values[0])
            place = await _place_by_id(place_id)
            if not place:
                return JSONResponse(_ephemeral_message("장소를 찾을 수 없습니다."))
            components = [
                {
                    "type": 1,
                    "components": [
                        {"type": 2, "style": 4, "custom_id": f"delete_visits_confirm:{uid}:{place_id}", "label": "방문기록 삭제"},
                        {"type": 2, "style": 2, "custom_id": "delete_visits_cancel", "label": "취소"},
                    ],
                }
            ]
            return JSONResponse(_update_message(content=f"정말 **{place['nickname']}**에 대한 user={uid} 방문기록을 삭제할까요?", components=components))

        if cid == "qr_delete_cancel":
            return JSONResponse(_update_message(content="취소되었습니다.", components=[]))
        if cid.startswith("qr_delete_confirm:"):
            place_id = int(cid.split(":", 1)[1])
            pool = await db()
            async with pool.acquire() as conn:
                await conn.execute("DELETE FROM places WHERE id=$1", place_id)
            return JSONResponse(_update_message(content="✅ 삭제 완료", components=[]))

        if cid == "delete_visits_cancel":
            return JSONResponse(_update_message(content="취소되었습니다.", components=[]))
        if cid.startswith("delete_visits_confirm:"):
            _, uid, place_id = cid.split(":")
            pool = await db()
            async with pool.acquire() as conn:
                await conn.execute("DELETE FROM visits WHERE user_id=$1 AND place_id=$2", int(uid), int(place_id))
            return JSONResponse(_update_message(content="✅ 방문기록 삭제 완료", components=[]))

        if cid.startswith("place_history_page:"):
            _, page_s, place_id_s = cid.split(":")
            return await _render_place_history_update(place_id=int(place_id_s), page=int(page_s))

        return JSONResponse(_ephemeral_message("처리할 수 없는 컴포넌트입니다."))

    # ------------------ Modal Submit ------------------
    if itype == 5:
        cid = (data.get("custom_id") or "")
        if cid.startswith("qr_rename_modal:"):
            place_id = int(cid.split(":", 1)[1])
            comps = data.get("components") or []
            try:
                new_name = comps[0]["components"][0]["value"].strip()
            except Exception:
                new_name = ""
            if not new_name:
                return JSONResponse(_ephemeral_message("새 닉네임을 입력해주세요."))

            pool = await db()
            async with pool.acquire() as conn:
                await conn.execute("UPDATE places SET nickname=$1 WHERE id=$2", new_name, place_id)
                place = await conn.fetchrow("SELECT slug FROM places WHERE id=$1", place_id)
            return JSONResponse(_ephemeral_message(f"✅ 닉네임 수정 완료: **{new_name}** (loc=`{place['slug']}`)"))

        return JSONResponse(_ephemeral_message("알 수 없는 모달입니다."))

    return JSONResponse(_ephemeral_message("지원하지 않는 인터랙션 타입입니다."))
