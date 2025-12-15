import os
import secrets
import urllib.parse
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import asyncpg
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

DISCORD_API = "https://discord.com/api/v10"
KST = ZoneInfo("Asia/Seoul")

# -------------------------
# ENV (Railway Variables)
# -------------------------
DATABASE_URL = os.getenv("DATABASE_URL")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")  # https://<app>.railway.app/oauth/callback

DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
DISCORD_ADMIN_CHANNEL_ID = os.getenv("DISCORD_ADMIN_CHANNEL_ID")

SESSION_SECRET = os.getenv("SESSION_SECRET", "")  # 꼭 설정 추천
HTTPS_ONLY = os.getenv("HTTPS_ONLY", "true").lower() == "true"

# -------------------------
# App
# -------------------------
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

if not SESSION_SECRET:
    # Railway에서 재시작 시 세션이 깨지지 않게 반드시 고정값 권장
    SESSION_SECRET = secrets.token_urlsafe(32)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=HTTPS_ONLY,
)

pool: asyncpg.Pool | None = None
http: httpx.AsyncClient | None = None

# -------------------------
# DB schema (유저 전역 누적 + 체크인 로그)
# - visitors.visit_count: 누적 방문 횟수(전역)
# - checkins: loc + 시간 + KST날짜(하루 1회 유니크)
# -------------------------
INIT_SQL = """
CREATE TABLE IF NOT EXISTS visitors (
  discord_user_id BIGINT PRIMARY KEY,
  username TEXT NOT NULL,
  global_name TEXT,
  avatar TEXT,
  visit_count INTEGER NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS checkins (
  id BIGSERIAL PRIMARY KEY,
  discord_user_id BIGINT NOT NULL REFERENCES visitors(discord_user_id) ON DELETE CASCADE,
  location TEXT NOT NULL,
  checked_in_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  checked_in_kst_date DATE NOT NULL
);

-- ✅ 유저당 KST 기준 하루 1회(전역) 체크인만 허용
CREATE UNIQUE INDEX IF NOT EXISTS uniq_checkins_user_per_day
ON checkins (discord_user_id, checked_in_kst_date);

CREATE INDEX IF NOT EXISTS idx_checkins_user_time ON checkins(discord_user_id, checked_in_at DESC);
CREATE INDEX IF NOT EXISTS idx_checkins_loc_time ON checkins(location, checked_in_at DESC);
"""

@app.on_event("startup")
async def startup():
    global pool, http
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")

    if not (DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET and OAUTH_REDIRECT_URI):
        raise RuntimeError("Discord OAuth ENV(DISOCRD_CLIENT_ID/SECRET/OAUTH_REDIRECT_URI) is not set")

    if not (DISCORD_BOT_TOKEN and DISCORD_ADMIN_CHANNEL_ID):
        raise RuntimeError("Discord Bot ENV(DISCORD_BOT_TOKEN/DISCORD_ADMIN_CHANNEL_ID) is not set")

    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5)
    async with pool.acquire() as conn:
        await conn.execute(INIT_SQL)

    http = httpx.AsyncClient(timeout=10)

@app.on_event("shutdown")
async def shutdown():
    global pool, http
    if http:
        await http.aclose()
    if pool:
        await pool.close()

@app.get("/health")
async def health():
    return {"ok": True}

# -------------------------
# Discord OAuth helpers
# -------------------------
def build_discord_auth_url(state: str) -> str:
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,
    }
    return f"https://discord.com/oauth2/authorize?{urllib.parse.urlencode(params)}"

async def exchange_code(code: str) -> dict:
    assert http is not None
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OAUTH_REDIRECT_URI,
    }
    r = await http.post(f"{DISCORD_API}/oauth2/token", data=data)
    r.raise_for_status()
    return r.json()

async def get_user(access_token: str) -> dict:
    assert http is not None
    r = await http.get(
        f"{DISCORD_API}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    r.raise_for_status()
    return r.json()

# -------------------------
# Discord Bot REST helpers
# -------------------------
async def discord_post_message(channel_id: str, content: str):
    assert http is not None
    r = await http.post(
        f"{DISCORD_API}/channels/{channel_id}/messages",
        headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
        json={"content": content},
    )
    r.raise_for_status()

async def discord_send_dm(user_id: int, content: str) -> bool:
    """
    DM 차단/서버 DM 비활성화면 실패 가능 -> False 반환
    """
    assert http is not None
    try:
        r1 = await http.post(
            f"{DISCORD_API}/users/@me/channels",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            json={"recipient_id": str(user_id)},
        )
        r1.raise_for_status()
        dm_channel_id = r1.json()["id"]

        r2 = await http.post(
            f"{DISCORD_API}/channels/{dm_channel_id}/messages",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            json={"content": content},
        )
        r2.raise_for_status()
        return True
    except Exception:
        return False

# -------------------------
# Web pages
# -------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    loc = request.query_params.get("loc", "").strip()
    user = request.session.get("user")

    display_name = None
    if user:
        display_name = user.get("global_name") or user.get("username") or str(user.get("id"))

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "loc": loc, "is_authed": bool(user), "display_name": display_name},
    )

@app.get("/login")
async def login(request: Request):
    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state

    next_url = request.query_params.get("next", "/")
    request.session["next_url"] = next_url

    return RedirectResponse(build_discord_auth_url(state))

@app.get("/oauth/callback")
async def oauth_callback(request: Request):
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    saved = request.session.get("oauth_state")

    if not code or not state or not saved or state != saved:
        raise HTTPException(400, "OAuth state 검증 실패")

    token = await exchange_code(code)
    user = await get_user(token["access_token"])

    request.session["user"] = {
        "id": int(user["id"]),
        "username": user.get("username", ""),
        "global_name": user.get("global_name"),
        "avatar": user.get("avatar"),
    }

    next_url = request.session.get("next_url") or "/"
    return RedirectResponse(next_url)

@app.get("/logout")
async def logout(request: Request):
    loc = request.query_params.get("loc", "")
    request.session.clear()
    return RedirectResponse(f"/?loc={urllib.parse.quote(loc)}")

# -------------------------
# Check-in API (유저당 KST 하루 1회만 인정)
# -------------------------
@app.post("/api/checkin")
async def api_checkin(request: Request):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"detail": "Discord 로그인 후 시도해주세요."}, status_code=401)

    loc = (request.query_params.get("loc") or "").strip() or "기본장소"
    if len(loc) > 50:
        raise HTTPException(400, "loc 값이 너무 깁니다(50자 이하).")

    uid = int(user["id"])
    display_name = user.get("global_name") or user.get("username") or str(uid)

    now_utc = datetime.now(timezone.utc)
    kst_now = now_utc.astimezone(KST)
    kst_date = kst_now.date()
    visit_time_str = kst_now.strftime("%H:%M")

    assert pool is not None

    first_today = False
    visit_count = 0

    async with pool.acquire() as conn:
        async with conn.transaction():
            # visitors upsert
            await conn.execute(
                """
                INSERT INTO visitors (discord_user_id, username, global_name, avatar)
                VALUES ($1,$2,$3,$4)
                ON CONFLICT (discord_user_id) DO UPDATE
                  SET username=EXCLUDED.username,
                      global_name=EXCLUDED.global_name,
                      avatar=EXCLUDED.avatar,
                      last_seen_at=now()
                """,
                uid, user.get("username", ""), user.get("global_name"), user.get("avatar")
            )

            # ✅ 오늘 체크인 1회만: checkins insert 시도
            inserted_id = await conn.fetchval(
                """
                INSERT INTO checkins (discord_user_id, location, checked_in_at, checked_in_kst_date)
                VALUES ($1, $2, now(), $3)
                ON CONFLICT (discord_user_id, checked_in_kst_date) DO NOTHING
                RETURNING id
                """,
                uid, loc, kst_date
            )

            if inserted_id:
                first_today = True
                visit_count = await conn.fetchval(
                    """
                    UPDATE visitors
                       SET visit_count = visit_count + 1,
                           last_seen_at = now()
                     WHERE discord_user_id = $1
                 RETURNING visit_count
                    """,
                    uid
                )
            else:
                first_today = False
                visit_count = await conn.fetchval(
                    "SELECT visit_count FROM visitors WHERE discord_user_id=$1",
                    uid
                ) or 0

    # ---- Discord 알림은 "오늘 첫 방문"일 때만
    if first_today:
        dm_text = f"{display_name}님 {loc} 방문을 환영합니다! (누적 {visit_count}번째 방문이시네요)"
        dm_ok = await discord_send_dm(uid, dm_text)

        admin_label = f"누적 {visit_count}회차" if visit_count != 1 else "오늘 첫 방문"
        admin_text = (
            f"[입장 알림] {display_name}님이 체크인했습니다! ({admin_label})\n"
            f"방문자 : {uid}\n"
            f"방문 시간 : {visit_time_str} (KST)\n"
            f"방문 횟수 : {visit_count}번째 방문\n"
            f"장소 : {loc}"
            + ("" if dm_ok else "\n※ DM 전송 실패(사용자 DM 차단 가능)")
        )

        try:
            await discord_post_message(DISCORD_ADMIN_CHANNEL_ID, admin_text)
        except Exception:
            pass

        return {"ok": True, "already": False, "message": f"체크인 완료! (누적 {visit_count}번째)"}

    return {"ok": True, "already": True, "message": f"오늘은 이미 체크인했어요! (누적 {visit_count}번째)"}
