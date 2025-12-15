# Railway Discord Check-in

## What it does
- Visitors scan a QR code: `https://YOUR_DOMAIN/?loc=카페A` (loc = place name).
- On the web page, they press **Discord로 체크인**.
- If not logged in: shows **Discord 로그인 후 시도해주세요** + login button.
- If logged in: shows **환영합니다!** and records a check-in.
- **Daily limit**: Only **1 check-in per user per KST day** is counted.
- On first check-in of the day:
  - Sends the visitor a DM: `~님 ~방문을 환영합니다! (누적 ~번째 방문이시네요)`
  - Sends an admin message to your specified Discord channel.
- Data persists in Railway Postgres.

## Railway ENV you must set
- `DATABASE_URL` (Railway Postgres provides this)
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `OAUTH_REDIRECT_URI` = `https://YOUR_DOMAIN/oauth/callback`
- `DISCORD_BOT_TOKEN`
- `DISCORD_ADMIN_CHANNEL_ID` (the channel that receives admin logs)
- `SESSION_SECRET` (random long string)
- `HTTPS_ONLY` = `true` (default)

## Start command
Railway → Deploy settings → Start Command:
`uvicorn main:app --host 0.0.0.0 --port $PORT`

## Local run
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```
