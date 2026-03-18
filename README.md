# Discord QR Check-in (FastAPI + Discord OAuth + Slash Commands via Interactions)

## 주요 기능
- QR로 접속하면 `/?loc=<slug>` 체크인 페이지가 열립니다.
- 방문자는 Discord OAuth로 로그인 후 체크인합니다.
- 체크인은 **장소별/일자별 1회**(같은 날 다른 장소는 가능).
- 체크인 시:
  - 방문자에게 DM(가능하면)
  - 관리자 채널에 로그


## 추가: 방문 로그 엑셀 내보내기
- 슬래시 명령어: `/방문로그엑셀`
- 권한: `DISCORD_EXPORT_ROLE_IDS`(쉼표로 role id 여러 개) 또는 관리자(ADMIN 역할)
- 엑셀 구성: 요약 / 전체기록 / 장소별 시트
