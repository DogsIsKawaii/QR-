# Discord QR Check-in (FastAPI + Discord OAuth + Slash Commands via Interactions)

## 주요 기능
- QR로 접속하면 `/?loc=<slug>` 체크인 페이지가 열립니다.
- 방문자는 Discord OAuth로 로그인 후 체크인합니다.
- 체크인은 **장소별/일자별 1회**(같은 날 다른 장소는 가능).
- 체크인 시:
  - 방문자에게 DM(가능하면)
  - 관리자 채널에 로그 + (선택) 역할 멘션

## 슬래시 명령어(인터랙션 엔드포인트 방식, gateway 없이)
- `/qr생성` : 장소 생성(닉네임/슬러그). 이 명령에서는 QR 이미지를 보여주지 않음.
- `/qr조회` : QR 이미지를 **명령어 실행자에게만** 표시(에페메랄).
- `/qr닉네임수정` : 기존 장소 선택 → 모달로 새 닉네임 입력.
- `/qr삭제` : 장소 삭제(확인 버튼).
- `/유저방문기록` : 특정 유저의 장소별 방문 집계.
- `/장소방문기록` : 특정 장소의 유저별 방문 집계(10개 단위 페이지, 좌/우 버튼).
- `/체크인초기화` : 특정 유저의 특정 장소 “오늘 체크인” 초기화.
- `/방문기록삭제` : 특정 유저의 특정 장소 방문 기록 삭제.

## Railway 환경 변수
필수:
- DISCORD_CLIENT_ID
- DISCORD_CLIENT_SECRET
- DISCORD_PUBLIC_KEY (Developer Portal → General Information → Public Key)
- DISCORD_BOT_TOKEN
- DISCORD_GUILD_ID
- DISCORD_ADMIN_CHANNEL_ID
- SESSION_SECRET
- OAUTH_REDIRECT_URI (예: https://<도메인>/oauth/callback)
- DATABASE_URL
- PORT

선택:
- DISCORD_ADMIN_ROLE_ID (슬래시 명령어 관리자 역할 제한)
- DISCORD_PING_ROLE_ID (관리자 로그 맨 아래 멘션할 역할)

## Discord 설정 순서
1) Developer Portal에서 Application 생성 → Bot 생성
2) Bot을 서버에 초대(관리자 로그 채널에 메시지 권한 필요)
3) Developer Portal에서 **Interactions Endpoint URL** 을
   `https://<도메인>/discord/interactions` 로 설정
4) Railway 재배포 → 부팅 시 길드 명령어 자동 등록
