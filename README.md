# Discord QR Check-in (FastAPI + Discord OAuth + Slash Commands via Interactions)

## 주요 기능
- QR로 접속하면 `/?loc=<slug>` 체크인 페이지가 열립니다.
- 방문자는 Discord OAuth로 로그인 후 체크인합니다.
- 체크인은 **장소별/일자별 1회**(같은 날 다른 장소는 가능).
- 체크인 시:
  - 방문자에게 DM(가능하면)
  - 관리자 채널에 로그 + (선택) 역할 멘션
