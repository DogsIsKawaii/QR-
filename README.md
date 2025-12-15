# Discord QR Check-in (Railway + GitHub)

## Run locally
```bash
python -m venv .venv
# Windows PowerShell:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

## Deploy
Push this folder to GitHub, then deploy the repo on Railway (FastAPI).
Set Railway Start Command:
```
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Environment variables (Railway Web Service):
- DISCORD_CLIENT_ID
- DISCORD_CLIENT_SECRET
- DISCORD_BOT_TOKEN
- DISCORD_ADMIN_CHANNEL_ID
- OAUTH_REDIRECT_URI = https://<domain>/oauth/callback
- DATABASE_URL
- SESSION_SECRET
- HTTPS_ONLY=true
