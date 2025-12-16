# Discord QR Check-in (FastAPI + Slash Commands via Interactions)

이 프로젝트는 **Discord Gateway(봇이 온라인으로 떠야 하는 방식)** 없이도 동작하도록,
Discord의 **Interactions Endpoint URL**(웹훅)로 슬래시 명령어/버튼/모달을 처리합니다.

## 동작 방식 (A안: Discord 초대 링크 → 채널에서 DM 체크인)
1) 운영진이 `/qr생성`으로 장소를 만들면
   - 지정한 채널에 **안내 메시지 + “DM으로 체크인” 버튼**을 올리고(가능하면 **핀 고정**)
   - 해당 채널의 **Discord 초대 링크(만료 없음)** 를 생성해 DB에 저장합니다.
2) 방문자는 QR을 찍으면 **Discord 초대 링크로 이동**합니다.
3) 채널 메시지에서 **DM으로 체크인** 버튼을 누르면, 봇이 방문자 DM으로 **체크인 버튼**을 보냅니다.
4) 방문자가 DM의 체크인 버튼을 누르면
   - DB에 방문 기록 저장(장소별/날짜별 1회)
   - (처음 체크인인 경우에만) 운영진 채널로 로그 출력
   - 방문자 DM에 “환영합니다(누적 n번째)” 표시

> 체크인이 이미 되어 있으면(같은 장소/같은 날짜), 운영진 채널에는 아무것도 출력하지 않습니다.

## 주요 기능
- 체크인: **장소별/일자별 1회** (같은 날 다른 장소는 가능)
- 체크인 성공 시:
  - 방문자 DM: “체크인 완료 + 누적 n번째 방문”
  - 운영진 채널 로그(중복 체크인 시 미출력) + (선택) 역할 멘션
- QR: **Discord 초대 링크**로 생성 / `/qr조회`에서만 QR 이미지 보여줌(에페메랄)

## 슬래시 명령어(인터랙션 엔드포인트 방식)
- `/qr생성` : 장소 생성(닉네임/채널/슬러그 선택). 이 명령에서는 QR 이미지를 보여주지 않음.
- `/qr조회` : QR 이미지를 **명령어 실행자에게만** 표시(에페메랄).
- `/qr닉네임수정` : 기존 장소 선택 → 모달로 새 닉네임 입력.
- `/qr삭제` : 장소 삭제(확인 버튼).
- `/유저방문기록` : 특정 유저의 장소별 방문 집계.
- `/장소방문기록` : 특정 장소의 유저별 방문 집계(10개 단위 페이지, ◀/▶ 버튼).
- `/체크인초기화` : 특정 유저의 특정 장소 “오늘 체크인” 초기화(오늘 기록만 삭제).
- `/방문기록삭제` : 특정 유저의 특정 장소 방문 기록 전체 삭제.

## DB에 저장되는 것
- `places`:
  - 장소 slug/닉네임
  - 안내 메시지 올린 채널 id
  - 초대 링크(invite_url)
  - (가능하면) 채널에 올린 안내 메시지 id
- `visits`:
  - user_id, place_id, visit_date(UNIQUE), visit_at
  - server_display_name / username (가독성용)

## 필수 환경변수 (Railway Variables)
- `DISCORD_CLIENT_ID`
- `DISCORD_PUBLIC_KEY` (Developer Portal → General Information → Public Key)
- `DISCORD_BOT_TOKEN`
- `DISCORD_GUILD_ID`
- `DISCORD_ADMIN_CHANNEL_ID`
- `DATABASE_URL`

선택:
- `DISCORD_ADMIN_ROLE_ID` : 슬래시 명령어 관리자 역할 제한
- `DISCORD_PING_ROLE_ID` : 운영진 로그 맨 아래 멘션할 역할
- `BASE_URL` : 로컬/프록시 환경에서 URL을 고정하고 싶으면 사용

## Discord 설정 순서
1) Developer Portal에서 Application 생성 → Bot 생성
2) Bot을 서버에 초대(필수 권한: 메시지 보내기, 채널 보기, DM 보내기 / 초대 링크 생성 / 핀 고정은 있으면 좋음)
3) Developer Portal에서 **Interactions Endpoint URL**을
   `https://<Railway도메인>/discord/interactions` 로 설정
4) Railway 재배포 후, `/qr생성`을 실행하면 길드 명령어가 자동 등록됩니다.

## 로컬 실행
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

