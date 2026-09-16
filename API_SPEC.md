# Notes API

제공된 Notes API 스펙에 세션·CSRF·입력 검증을 추가한 구현 명세입니다. 기존 HTML 로그인·메모·관리자 화면은 그대로 사용할 수 있습니다.

## 인증과 CSRF

모든 `/api/*` 요청에는 유효한 로그인 세션 쿠키가 필요합니다. 세션이 없거나 만료·폐기되었으면 HTML 또는 리다이렉트 대신 `401` JSON을 반환합니다. 로그아웃 또는 비밀번호 변경으로 폐기된 세션도 사용할 수 없습니다.

1. `GET /login`으로 폼의 숨겨진 `csrf_token`과 세션 쿠키를 받습니다.
2. 같은 쿠키로 `POST /login`에 `username`, `password`, `csrf_token`을 폼 인코딩(`application/x-www-form-urlencoded`)하여 보냅니다.
3. 로그인 성공 시 세션이 교체됩니다. 응답의 새 쿠키를 저장합니다.
4. `GET /api/csrf`로 로그인 후 CSRF 토큰을 받습니다. **이 응답의 `Set-Cookie`도 저장**합니다.
5. `POST /api/notes`에 세션 쿠키와 `X-CSRF-Token` 헤더, JSON 본문을 함께 보냅니다.

```json
{ "csrf_token": "세션에 연결된 64자리 토큰" }
```

`GET /api/csrf`는 로그인한 세션에 토큰이 없으면 발급하고 있으면 같은 토큰을 반환합니다. 로그인 전 토큰, 다른 세션의 토큰은 사용할 수 없습니다. 다시 로그인하거나 관리자 비밀번호 변경 작업을 수행해 토큰이 바뀌면 새 토큰을 받으세요. 조회 API는 CSRF 헤더가 필요하지 않습니다.

로그인 폼은 HTML 응답을 유지합니다. 새 비밀번호는 기존 정책대로 15~128자입니다. 원본 문서의 CSRF 없는 로그인·작성 예제는 사용할 수 없습니다. 쿠키 인증에 대한 CSRF 검증은 [Flask 보안 문서](https://flask.palletsprojects.com/en/stable/web-security/#cross-site-request-forgery-csrf)의 원칙을 따릅니다.

## Note 객체

```json
{
  "id": 1,
  "title": "회의 기록",
  "body": "오후 3시, 회의실 2",
  "created_at": "2026-09-16 14:02:00",
  "updated_at": "2026-09-16 14:02:00"
}
```

`id`는 정수, 나머지는 문자열입니다. 날짜는 **한국 시간(KST, UTC+09:00)**의 `YYYY-MM-DD HH:MM:SS` 형식입니다. DB의 `content`를 API에서는 `body`로 반환합니다. 사용자 번호, 비밀번호 해시, 로그인 토큰은 포함하지 않습니다.

## 엔드포인트

| 요청 | 성공 응답 | 동작 |
| --- | --- | --- |
| `GET /api/csrf` | `200 {"csrf_token": "..."}` | 현재 로그인 세션의 CSRF 토큰 |
| `GET /api/notes` | `200 {"notes": [<note>, ...]}` | 본인 메모 전체, 수정 시각 내림차순·동률이면 ID 내림차순 |
| `POST /api/notes` | `201 <note>` | 본인 메모 생성, `Location` 헤더에 상세 API 경로 |
| `GET /api/notes/<id>` | `200 <note>` | 본인 메모 상세 |

API 목록은 페이지 구분 없이 모든 본문을 반환합니다. 메모가 없으면 `{"notes": []}`입니다. 웹 화면의 20개 페이지 제한과 본문 미리보기 제한은 API에 적용하지 않습니다. 데이터가 커지면 클라이언트와 합의한 별도 페이지네이션 명세가 필요합니다.

수정·삭제 API는 이번 스펙에 없으므로 추가하지 않았습니다. 기존 HTML 화면에서는 수정·삭제할 수 있습니다.

### 작성 입력

```http
POST /api/notes
Content-Type: application/json
X-CSRF-Token: <GET /api/csrf로 받은 토큰>
Cookie: <로그인 세션 쿠키>
```

```json
{ "title": "회의 기록", "body": "오후 3시" }
```

- `title`: 필수 문자열. 앞뒤 공백 제거 후 1~120자. 줄바꿈·제어 문자는 허용하지 않습니다.
- `body`: 선택 문자열. 생략 시 `""`. 빈 문자열·공백만 있는 본문도 허용하며 그대로 보존합니다. 최대 10,000자, 줄바꿈·탭을 제외한 C0 제어 문자는 거부합니다.
- 두 필드 모두 정상적인 유니코드 문자열이어야 합니다. `null`, 숫자, 배열 등으로 자동 변환하지 않습니다.
- `title`, `body` 외의 입력 필드는 거부합니다. 작성자는 세션으로 결정합니다.
- JSON 요청 본문은 최대 128KiB입니다. 유효한 세션·CSRF·Content-Type을 가진 작성 요청은 계정당 60초에 30회까지 허용합니다. 이 단계 이후의 입력 검증 실패도 횟수에 포함됩니다.

## 오류와 권한

```json
{ "error": "로그인이 필요합니다." }
```

| 코드 | 조건 |
| --- | --- |
| `400` | 잘못된 JSON·필드·길이·CSRF, 허용하지 않는 Host 또는 운영 앱으로의 직접 HTTP 요청 |
| `401` | 유효한 로그인 세션 없음 |
| `404` | 메모 없음, 다른 사람의 메모, 알 수 없는 API 경로 |
| `405` | 지원하지 않는 메서드 (`Allow` 헤더 유지) |
| `413` | 요청 본문 크기 초과 |
| `415` | 작성 요청의 Content-Type이 `application/json`이 아님 |
| `429` | 작성 요청 횟수 초과 (`Retry-After` 초 단위) |
| `500` | 내부 오류. 상세 예외·DB 정보는 응답에 포함하지 않음 |

인증은 API의 경로·메서드 오류보다 먼저 확인합니다. 따라서 로그인하지 않은 상태로 없는 API 경로나 지원하지 않는 메서드를 요청해도 `401`입니다. Host·HTTPS 등 요청의 기본 신뢰 검증은 예외입니다. `HEAD`는 HTTP 규칙에 따라 본문 없이 상태·헤더만 반환합니다. 유효한 세션으로 보내는 자동 `OPTIONS` 응답도 본문 없이 `200`과 `Allow` 헤더를 반환합니다.

관리자도 다른 회원의 메모를 조회할 수 없습니다. 존재하지 않는 메모와 다른 회원 메모는 동일한 `404` 오류입니다. 조회·생성 쿼리는 서버가 정한 작성자 ID와 매개변수 바인딩을 사용합니다. JSON의 사용자 문자열은 일반 텍스트이므로 외부 클라이언트에서 표시할 때도 `innerHTML` 대신 `textContent` 등 안전한 출력 방식을 사용하세요.

API의 데이터·오류 응답은 `application/json`을 사용합니다. 모든 응답에 `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`를 적용합니다. 외부 origin을 허용하는 CORS 설정은 추가하지 않았습니다. 운영 환경은 HTTPS와 Secure·HttpOnly 세션 쿠키를 유지합니다.

## 호출 예제 (Python 표준 라이브러리)

기존 계정으로 로그인하고 메모 하나를 작성·조회하는 예제입니다. 테스트용 계정에 실행하세요. 비밀번호는 화면에 표시되거나 명령 기록에 남지 않도록 입력받고, 쿠키는 메모리에서만 유지합니다. 실행할 서버를 `BASE_URL` 환경 변수로 지정할 수 있습니다. 기본값은 로컬 개발 서버입니다.

```python
import getpass
import http.cookiejar
import json
import os
from html.parser import HTMLParser
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener

base = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
address = urlsplit(base)
if address.scheme != "https" and not (
    address.scheme == "http" and address.hostname in {"localhost", "127.0.0.1", "::1"}
):
    raise ValueError("외부 서버에는 HTTPS 주소를 사용하세요.")
client = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))


class LoginForm(HTMLParser):
    token = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("name") == "csrf_token":
            self.token = fields.get("value")


form = LoginForm()
with client.open(base + "/login", timeout=10) as response:
    form.feed(response.read().decode("utf-8"))
if not form.token:
    raise RuntimeError("로그인 폼의 CSRF 토큰을 찾을 수 없습니다.")
credentials = urlencode({
    "username": input("아이디: "),
    "password": getpass.getpass("비밀번호: "),
    "csrf_token": form.token,
}).encode("utf-8")

try:
    with client.open(base + "/login", data=credentials, timeout=10) as response:
        response.read()
    with client.open(base + "/api/csrf", timeout=10) as response:
        token = json.load(response)["csrf_token"]
    request = Request(base + "/api/notes", method="POST",
        data=json.dumps({"title": "회의 기록", "body": "오후 3시"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-CSRF-Token": token})
    with client.open(request, timeout=10) as response:
        note = json.load(response)
        print("생성:", response.status, note)
    with client.open(base + f'/api/notes/{note["id"]}', timeout=10) as response:
        print("상세:", json.load(response))
    with client.open(base + "/api/notes", timeout=10) as response:
        print("목록:", json.load(response))
finally:
    # 로그인 후 오류가 발생해도 가능한 경우 세션을 폐기합니다.
    try:
        with client.open(base + "/api/csrf", timeout=10) as response:
            token = json.load(response)["csrf_token"]
        with client.open(base + "/logout", data=urlencode({"csrf_token": token}).encode(), timeout=10) as response:
            response.read()
    except HTTPError:
        pass
```

내부 CA를 쓰는 Docker 서버는 검증된 루트 인증서를 `SSL_CERT_FILE`로 지정하거나 기기의 신뢰 저장소에 등록해야 합니다. 인증서 검증을 끄지 마세요.

## DB 이전과 검증

기존 DB는 앱 시작 시 한 번 이전합니다. 메모 ID·작성자·제목·본문·시각을 보존하고 빈 본문을 허용하도록 CHECK 제약을 변경합니다. SQLite `user_version`은 `1`이 됩니다. 회원이 있는 기존 DB는 같은 디렉터리에 `users.db.before-api-v1-<무작위값>.db` 형태의 권한 `600` 백업을 먼저 만듭니다. Docker에서는 `/data` 볼륨에 생성됩니다. 백업에는 회원·메모·세션 데이터가 포함되며 Git과 이미지에서 제외됩니다.

이전은 트랜잭션으로 처리하고 여러 Gunicorn worker가 동시에 시작해도 한 번만 수행합니다. 복사에 실패하면 기존 테이블과 스키마 버전을 유지하고 시작을 중단합니다. 디스크 여유 공간은 DB 복사본과 SQLite 저널을 만들 수 있어야 합니다. 별도의 운영 백업 정책은 계속 필요합니다. 백업 복원은 실행 중인 앱을 중지한 뒤 수행해야 합니다.

```bash
.venv/bin/python -m unittest discover -s tests -v
```

테스트는 임시 DB만 사용합니다. 실제 `users.db`, `.env`, 관리자 초기 비밀번호 파일을 변경하지 않습니다.
