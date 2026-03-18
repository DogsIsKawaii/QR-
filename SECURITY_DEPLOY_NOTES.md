# Security deploy notes

## Fixed in this patch
- Removed insecure fallback session secret (`dev-secret`)
- Added required `PUBLIC_BASE_URL` and stopped trusting Host/X-Forwarded-Host for public links
- Added OAuth state nonce generation and validation with expiry
- Removed client-side `innerHTML` usage from the check-in result box
- Added Discord interaction timestamp freshness validation
- Added permission check for `checkin_roles:*` pagination buttons
- Normalized place nicknames and escaped `@` mentions in Discord-visible text

## Railway environment variables
Required:
- `SESSION_SECRET` = long random secret
- `PUBLIC_BASE_URL` = your canonical HTTPS app URL (example: `https://your-app-name.up.railway.app`)

Optional hardening:
- `OAUTH_STATE_TTL_SECONDS=600`
- `DISCORD_SIGNATURE_MAX_AGE_SECONDS=300`

## Discord OAuth settings
Make sure the Discord application redirect URL exactly matches:
- `OAUTH_REDIRECT_URI`
- and that it points to: `https://<your-domain>/oauth/callback`
