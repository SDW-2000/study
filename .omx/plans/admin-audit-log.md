# 관리자용 감사 로그 페이지 계획

## 목표

관리자가 `/admin/audit`에서 로그인 시도·성공·실패와 주요 사용자 행동을 시간순으로 확인하고, 기간·결과·행동 종류·사용자·IP로 필터링할 수 있게 한다. Docker 원본 로그를 노출하는 기능이 아니라, 애플리케이션이 의미 있는 보안·업무 이벤트를 구조화해 SQLite에 기록하는 기능이다.

## 기본 범위와 해석

- “접속 시도”는 로그인 폼 제출을 뜻한다. 단순 로그인 페이지 열람이나 모든 GET 요청은 기록하지 않는다.
- “어떤 행동”은 상태를 바꾸는 주요 행동을 뜻한다. 메모 목록/상세 조회 같은 일반 열람은 기본적으로 기록하지 않아 불필요한 로그 폭주와 사생활 침해를 피한다.
- 감사 로그는 관리자만 열람할 수 있고 수정·삭제 UI는 제공하지 않는다.
- 기본 보존 기간은 90일로 제안한다. 환경 변수로 7~365일 범위에서 조정 가능하게 한다.
- 시각은 기존 화면과 동일하게 KST로 표시하되 DB에는 Unix timestamp로 저장한다 (`app.py:45`, `app.py:747-749`).

## 기록할 이벤트

| 분류 | 이벤트 | 결과 | 남길 대상 정보 |
| --- | --- | --- | --- |
| 인증 | 로그인 | 성공 / 실패 / 제한됨 | 시도한 아이디, 성공 시 사용자 ID, IP, User-Agent |
| 인증 | 로그아웃 | 성공 | 사용자 ID·아이디, IP |
| 계정 | 회원가입 | 성공 / 실패 / 제한됨 | 시도한 아이디, 성공 시 사용자 ID, IP |
| 계정 | 본인 비밀번호 변경 | 성공 / 실패 / 제한됨 | 사용자 ID, 실패 사유 코드 |
| 관리자 | 다른 회원 비밀번호 변경 | 성공 / 실패 / 권한 거부 | 관리자, 대상 사용자 ID·아이디 |
| 메모 | 생성 / 수정 / 삭제 | 성공 | 사용자 ID, 메모 ID, 요청 경로가 HTML/API인지 |
| 보안 | 관리자 페이지 접근 거부 | 권한 거부 | 로그인 사용자 또는 익명, endpoint, IP |

다음은 절대 기록하지 않는다: 비밀번호, 비밀번호 해시, 세션 토큰·해시, CSRF 토큰, 쿠키, Authorization 헤더, 메모 제목·본문, 전체 요청 본문, 예외 원문, 임의 쿼리 문자열.

## 현재 구조와 변경 지점

- 요청 전 처리에서 실제 peer IP를 사용하고, 운영 Docker에서는 신뢰하는 Caddy 한 대의 전달 정보만 적용한다 (`app.py:83-86`, `app.py:521-542`, `app.py:545-583`). 감사 로그도 반드시 `request.remote_addr`만 사용한다.
- 로그인 성공/실패 분기는 `app.py:841-874`, 로그아웃은 `app.py:885-893`에 있다.
- 회원가입 성공/실패 분기는 `app.py:814-838`, 비밀번호 변경은 `app.py:896-944`에 있다.
- 메모 생성·수정·삭제는 HTML과 API 경로가 분리되어 있다 (`app.py:775-799`, `app.py:990-1054`).
- 관리자 화면은 단일 `PAGE` 템플릿과 `/admin` 라우트로 구성되어 있다 (`app.py:88-401`, `app.py:1057-1072`).
- DB 초기화와 스키마 마이그레이션은 앱 시작 시 직렬화된 트랜잭션 안에서 실행된다 (`app.py:421-515`).

## 데이터 모델

새 `audit_events` 테이블을 추가한다.

```sql
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY,
    created_at INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'rate_limited')),
    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_username TEXT,
    attempted_username TEXT,
    target_type TEXT,
    target_id INTEGER,
    target_label TEXT,
    source_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('web', 'api')),
    reason_code TEXT,
    request_id TEXT NOT NULL
);
```

인덱스:

- `(created_at DESC, id DESC)` — 기본 최신순 목록과 보존 기간 삭제
- `(event_type, created_at DESC)` — 행동 필터
- `(outcome, created_at DESC)` — 성공/실패 필터
- `(actor_user_id, created_at DESC)` — 사용자 필터
- `(source_ip, created_at DESC)` — IP별 조사

`actor_username`, `target_label`은 계정 정보가 나중에 바뀌거나 삭제되더라도 당시 표시값을 남기기 위한 제한 길이 snapshot이다. 상세 payload를 임의 JSON으로 저장하지 않고 고정 컬럼과 제한된 `reason_code`만 사용해 민감정보가 우연히 들어갈 경로를 줄인다.

## 기록 정책

### 성공 이벤트

- 실제 데이터 변경과 감사 이벤트 INSERT를 같은 SQLite 트랜잭션에 둔다.
- 예: 메모 생성이 커밋됐는데 감사 로그가 없거나, 감사 로그만 있는데 메모 생성이 롤백되는 상태를 허용하지 않는다.
- 로그인 성공은 auth session INSERT와 같은 트랜잭션, 비밀번호 변경은 비밀번호 갱신·세션 폐기와 같은 트랜잭션에서 기록한다 (`app.py:861-870`, `app.py:915-935`).

### 실패 이벤트

- 로그인 실패처럼 업무 트랜잭션이 없는 경우 독립된 짧은 INSERT로 기록한다.
- 사용자에게 보여 주는 메시지는 현재처럼 계정 존재 여부를 숨기고, 감사 로그의 `reason_code`도 `invalid_credentials`, `invalid_input`, `conflict`, `current_password_mismatch`처럼 제한된 값만 사용한다.
- `reason_code`는 관리자에게 계정 존재 여부를 과도하게 노출하지 않도록 로그인 실패를 모두 `invalid_credentials`로 통합한다.

### 요청 식별자

- `before_request`에서 무작위 request ID를 만들고 `g.request_id`에 저장한다.
- 응답에 `X-Request-ID`를 추가해 관리자 화면의 이벤트와 서버 오류 보고를 연결할 수 있게 한다 (`app.py:545-549`, `app.py:607-622`).
- 외부에서 전달된 request ID는 신뢰하지 않고 서버가 항상 새로 만든다.

### 보존·용량

- `AUDIT_RETENTION_DAYS` 기본값 90, 허용 범위 7~365.
- 매 감사 이벤트마다 전체 삭제를 실행하지 않고, 프로세스별로 최대 1시간에 한 번 `created_at < cutoff` 행을 작은 배치로 삭제한다.
- 감사 페이지 상단에 현재 보존 기간을 표시한다.
- 사용자가 UI에서 개별/전체 로그를 삭제하는 기능은 제공하지 않는다.

## 관리자 화면

### 목록

- 관리자 내비게이션에 `활동 기록` 링크를 추가한다 (`app.py:219-228`).
- `/admin/audit`는 한 페이지 50건, 최신순으로 표시한다.
- 열: 시각, 결과 배지, 행동, 사용자/시도 아이디, 대상, IP, 채널, 상세.
- 행동명은 내부 코드 대신 `로그인 성공`, `로그인 실패`, `메모 삭제`, `회원 비밀번호 변경`처럼 한국어로 표시한다.
- 긴 User-Agent와 request ID는 `<details>` 안에 넣어 목록 밀도를 유지한다.
- 로그 값은 기존 Jinja autoescape를 그대로 사용하고 `|safe`를 사용하지 않는다.
- 첫 페이지에서는 3초마다 마지막 event ID 이후의 새 이벤트만 조회해 목록 맨 위에 추가한다. 연결 상태와 마지막 갱신 시각을 함께 표시한다.
- 자동 갱신 일시정지/재개와 수동 새로고침을 제공하며, 화면에는 최신 200건까지만 유지한다. 과거 페이지를 보고 있을 때는 자동 갱신하지 않는다.

### 요약

최근 24시간 기준으로 다음 네 가지 숫자를 상단에 표시한다.

- 로그인 성공 수
- 로그인 실패·제한 수
- 활동한 고유 사용자 수
- 권한 거부 수

요약 쿼리는 모두 인덱스를 사용하고 페이지당 별도 대용량 집계를 하지 않도록 24시간 범위로 고정한다.

### 필터

- 기간: 최근 24시간 / 7일 / 30일 / 보존 기간 전체
- 결과: 전체 / 성공 / 실패 / 거부·제한
- 행동: 전체 / 로그인 / 계정 / 메모 / 관리자
- 사용자: 정확한 아이디 또는 시도 아이디
- IP: 정확 일치
- 모든 query parameter는 단일값, 길이, 허용값을 검증하고 잘못된 필터는 400으로 처리한다.
- 페이지 이동 시 필터를 그대로 유지한다.

실시간 갱신은 장기 연결을 점유하는 SSE 대신 3초 incremental polling으로 구현한다. `/admin/audit/events?after_id=<id>`는 현재 필터에 맞는 새 이벤트를 최대 100건 반환하고, 더 많은 이벤트가 있으면 `has_more`로 즉시 다음 batch를 요청하게 한다. 응답에는 갱신된 24시간 요약도 포함한다.

## 구현 단계

### 1. 스키마 v2 마이그레이션

- 현재 `PRAGMA user_version` 상한을 2로 올리고 기존 v0→v1 메모 마이그레이션 뒤 v1→v2 감사 테이블 생성을 순차 적용한다 (`app.py:421-449`).
- 기존 회원/메모가 있는 DB는 v2 적용 전 현재 백업 정책과 동일하게 권한 0600 백업을 만든다.
- 새 DB는 처음부터 v2 스키마로 생성한다 (`app.py:452-515`).
- 미래 버전 DB 거부, 다중 worker 동시 시작, 마이그레이션 실패 rollback 테스트를 v2에 맞춰 갱신한다 (`tests/test_api.py:268-334`).

### 2. 감사 기록 헬퍼

- 고정된 event type·outcome·reason code allowlist를 상수로 정의한다.
- `audit_event(...)` 헬퍼는 전달받은 기존 DB connection을 사용할 수 있게 해 성공 이벤트가 업무 트랜잭션에 참여하도록 한다.
- actor snapshot, IP 최대 길이, User-Agent 최대 300자, target label 최대 120자, request ID 형식을 중앙에서 검증한다.
- retention cleanup은 별도 helper로 두고 이벤트 기록 실패 때문에 인증/업무 성공이 조용히 진행되지 않도록 한다. 같은 트랜잭션이면 함께 실패·rollback하고 500을 반환한다.

대상: `app.py:41-63`, `app.py:406-542`.

### 3. 인증·계정 이벤트 연결

- 로그인: invalid input, invalid credentials, concurrent password change, success를 각각 기록한다 (`app.py:841-874`).
- rate limit은 최초 차단 시점 한 건만 `rate_limited`로 기록하고, 이후 같은 window의 반복 요청은 행을 계속 만들지 않아 로그 증폭 공격을 막는다 (`app.py:521-542`).
- 회원가입: success, validation failure, username conflict, rate-limited를 기록한다 (`app.py:814-838`).
- 로그아웃은 세션 삭제 전에 actor snapshot을 확보하고 같은 트랜잭션에서 기록한다 (`app.py:885-893`).
- 본인/관리자 비밀번호 변경은 성공과 주요 실패를 기록하되 비밀번호 길이·값은 저장하지 않는다 (`app.py:896-944`).

### 4. 메모·권한 이벤트 연결

- HTML/API 메모 생성 시 새 note ID와 channel만 기록한다 (`app.py:775-799`, `app.py:990-1008`).
- 수정/삭제 성공은 소유자 조건 쿼리와 같은 트랜잭션에서 기록한다 (`app.py:1020-1054`).
- 일반적인 404 탐색은 기록하지 않는다. 관리자 endpoint에 대한 403만 `authorization.admin_denied`로 기록해 노이즈와 공격자 유발 DB 증가를 제한한다 (`app.py:625-650`, `app.py:958-970`, `app.py:1057-1061`).

### 5. 관리자 감사 페이지

- 관리자 확인을 `admin_required` 데코레이터로 추출해 회원 관리와 감사 페이지가 같은 정책을 사용하게 한다 (`app.py:693-700`, `app.py:1057-1061`).
- 필터 파서와 pagination을 별도 함수로 두고 동적 SQL은 허용된 고정 절만 조합하며 값은 모두 parameter binding한다.
- `PAGE` 템플릿에 요약 카드, 필터 폼, 감사 테이블, 필터 보존 pagination을 추가한다 (`app.py:88-401`).
- 모바일에서는 덜 중요한 열을 상세 영역으로 이동하고, 기존 다크 모드·고대비·키보드 포커스 스타일을 유지한다 (`app.py:186-212`).
- `GET /admin/audit/events`는 관리자 전용 JSON endpoint로 두고 `after_id`, 현재 필터, 최대 100건의 엄격한 입력 제한을 적용한다.
- 새 `static/admin_audit.js`가 첫 페이지에서 3초마다 incremental endpoint를 호출하고, DOM 삽입에는 `textContent`만 사용한다.
- CSP에 `script-src 'self'`와 `connect-src 'self'`를 추가하고 스크립트는 감사 페이지에서만 로드한다 (`app.py:607-614`).

### 6. 문서·설정

- `AUDIT_RETENTION_DAYS`를 `.env.example`, `compose.yaml`, README 환경 변수 표에 추가한다 (`compose.yaml:4-13`, `README.md:112-120`).
- 기록 이벤트, 미기록 데이터, 90일 기본 보존, IP/User-Agent 저장 사실, 관리자 전용 접근을 문서화한다 (`README.md:80-110`).
- 운영 개인정보 정책에 맞춰 보존 기간을 조정해야 한다는 안내를 추가한다.

## 인수 조건

- 익명 사용자는 `/admin/audit`에서 로그인 화면으로 이동하고, 일반 회원은 403을 받는다.
- 관리자는 최신 50건과 최근 24시간 요약을 볼 수 있다.
- 올바른 로그인, 잘못된 비밀번호 로그인, 존재하지 않는 사용자 로그인은 각각 감사 이벤트를 만들며 사용자 응답은 모두 기존과 동일하게 계정 존재 여부를 숨긴다.
- 로그인 11번째 시도에서 rate-limited 이벤트가 한 건 생기고 같은 window의 추가 차단 요청은 감사 행을 계속 늘리지 않는다.
- 회원가입, 로그아웃, 본인 비밀번호 변경, 관리자에 의한 회원 비밀번호 변경, 메모 생성·수정·삭제가 정확히 한 건씩 기록된다.
- HTML과 API 메모 생성 이벤트는 `channel`로 구분된다.
- 감사 행 어디에도 테스트 비밀번호, 세션 토큰, CSRF 토큰, 메모 제목/본문이 존재하지 않는다.
- 업무 트랜잭션을 강제로 실패시키면 해당 감사 이벤트도 남지 않고, 감사 INSERT를 강제로 실패시키면 업무 변경도 rollback된다.
- 기간·결과·행동·사용자·IP 필터와 필터 유지 pagination이 동작한다.
- 첫 페이지에 머물면 새 이벤트가 3초 이내에 목록 상단과 24시간 요약에 반영되고, 일시정지 중에는 자동 요청이 발생하지 않는다.
- polling 응답이 401/403/500이거나 네트워크가 끊기면 기존 목록은 유지되고 연결 상태만 오류로 바뀌며, 재개 후 자동 복구한다.
- 잘못된/중복 query parameter는 400이며 SQL injection 문자열은 데이터로만 처리된다.
- 90일보다 오래된 이벤트는 cleanup 후 사라지고 최신 이벤트는 유지된다.
- 기존 로그인, 메모 CRUD, 관리자 비밀번호 변경, API 계약과 보안 헤더 테스트가 모두 통과한다.

## 테스트 계획

### 단위·통합 테스트

- `AuditEventTests`: 이벤트별 성공/실패/제한 기록, snapshot, channel, request ID, 민감정보 미기록.
- `AuditAuthorizationTests`: 익명 redirect, 일반 회원 403, 관리자 200, 관리자 거부 이벤트.
- `AuditFilterTests`: 기간·결과·행동·사용자·IP 조합, pagination, 중복/잘못된 parameter, escape 처리.
- `AuditPollingTests`: after_id cursor, 필터 적용, batch 상한·has_more, 관리자 권한, 새 이벤트 순서, 요약 갱신.
- `AuditTransactionTests`: 업무 변경과 감사 INSERT의 원자성, 동시 로그인/비밀번호 변경 경합.
- `AuditRetentionTests`: 7/90/365일 경계, cleanup 주기, batch 삭제.
- `NotesMigrationTests`: v0→v1→v2, v1→v2, 병렬 worker, 백업, 실패 rollback, 미래 version 거부 (`tests/test_api.py:268-334`).

### 회귀·운영 검증

- `.venv/bin/python -m unittest discover -s tests -v` 전체 통과.
- 임시 DB에서 수천 건을 생성한 뒤 최신 50건 페이지 응답이 인덱스를 사용하며 목표 로컬 p95 200ms 이내인지 확인한다.
- `docker compose config --quiet`, 앱 이미지 빌드, healthcheck를 확인한다.
- Caddy 뒤에서 로그인 실패를 발생시켜 감사 로그 IP가 프록시 주소가 아니라 실제 client IP인지 확인한다.

## 위험과 완화

- **개인정보 축적:** IP와 User-Agent는 개인정보가 될 수 있다. 관리자 전용, 90일 기본 보존, 7~365일 설정 범위, 자동 삭제, export 미제공으로 제한한다.
- **민감정보 유출:** 임의 details JSON과 요청 본문 저장을 금지하고 고정 컬럼·reason allowlist만 사용한다.
- **로그 증폭 공격:** rate-limit 차단 반복은 window당 한 건만 기록하고, 일반 404·GET 열람은 기록하지 않는다.
- **감사 누락:** 성공 이벤트는 업무 변경과 같은 트랜잭션에 넣고 감사 INSERT 실패 시 전체를 rollback한다.
- **관리자에 의한 로그 변조:** 수정·삭제 endpoint를 만들지 않는다. 다만 DB 파일에 직접 접근 가능한 서버 운영자는 변조할 수 있으므로, 규제 수준의 비가역 감사가 필요하면 2차로 외부 append-only 저장소 전송이 필요하다.
- **SQLite 성장/조회 지연:** 복합 인덱스, 90일 retention, 한 페이지 50건, 24시간 제한 집계로 제어한다.
- **Polling 부하:** 관리자 첫 페이지에서만 3초 간격으로 실행하고, incremental ID 인덱스 조회·최대 100건 응답·탭 비활성화 시 일시정지로 제한한다.

## 1차 범위에서 제외

- Docker/Caddy 원본 로그와 daemon 로그
- 모든 페이지 조회 기록
- 메모 내용 또는 변경 전후 diff
- CSV 다운로드와 외부 SIEM 연동
- 밀리초 단위 스트리밍과 SSE/WebSocket 장기 연결
- 관리자 화면에서 감사 로그 삭제·수정

## 완료 기준

모든 인수 조건과 단위·마이그레이션·회귀 테스트가 통과하고, 생성된 감사 DB 행을 검사했을 때 금지된 민감정보가 없으며, 일반 회원이 페이지와 데이터에 접근할 수 없음을 확인하면 완료로 본다.
