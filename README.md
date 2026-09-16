# 메모 서비스

Flask와 SQLite로 만든 회원가입·로그인·개인 메모 서비스입니다. 화면과 서버 코드는 `app.py` 하나에 있습니다.

## 실행

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

브라우저에서 `http://127.0.0.1:8000`으로 접속합니다. 코드 수정 후에는 실행 중인 서버를 `Ctrl+C`로 종료하고 다시 실행합니다. 이 명령은 개발용이며 Docker 배포는 아래 구성을 사용합니다.

다른 포트가 필요하면 `PORT=5050 .venv/bin/python app.py`처럼 실행합니다. `PORT`에는 1~65535의 정수를 지정합니다.

현재 작업 폴더의 관리자 계정은 초기화되어 있습니다. 아이디는 `admin`이며 초기 비밀번호는 `.admin-initial-password`에 있습니다. 이 파일은 소유자만 읽을 수 있고 Git에서 제외됩니다. 관리자 비밀번호를 변경한 뒤에는 초기 비밀번호를 사용할 수 없으며, 새 비밀번호를 이 파일에 저장하지 않습니다.

새 DB를 사용하는 경우 첫 실행 전에 `ADMIN_PASSWORD` 환경 변수에 15~128자의 비밀번호를 설정해야 합니다. 초기화 시에만 사용하며 이후 실행에서 관리자 비밀번호를 덮어쓰지 않습니다. `ADMIN_NOTE` 환경 변수로 초기 메모를 `SBOB{your_identifier}` 형식으로 지정할 수 있습니다. 생략하면 `SBOB{daewon_무작위식별자}` 형식으로 생성됩니다. 기존 일반 회원이 `admin` 아이디를 사용하고 있다면 자동으로 권한을 올리지 않고 초기화를 중단합니다.

## Docker 배포

구성은 `브라우저 → Caddy(HTTPS) → Gunicorn → Flask → SQLite`입니다. 외부에는 Caddy의 80·443번 포트만 공개하며 앱의 8000번 포트는 내부 Docker 네트워크에서만 사용합니다. 앱은 일반 사용자 UID/GID `10001:10001`로 실행하고 코드 파일 시스템은 읽기 전용으로 둡니다.

첫 Docker 실행은 프로젝트 폴더에서 아래 명령으로 시작합니다. 서버의 **IPv4 주소 또는 접속할 도메인 하나**를 입력하면 `.env.example`을 바탕으로 `.env`를 권한 600으로 만들고 `SECRET_KEY`와 초기 `ADMIN_PASSWORD`를 각각 무작위로 생성합니다. `Caddyfile`이 없으면 `Caddyfile.example`에서 복사한 뒤 Docker Compose를 실행합니다. 생성된 비밀 값은 터미널에 한 번만 표시됩니다. 관리자 아이디는 `admin`입니다. 이 값들을 채팅·스크린샷·Git에 올리지 마세요.

`docker compose up`은 이 Python 스크립트를 자동으로 호출하지 않습니다. **처음에는 아래 Python 명령을 실행**해야 하며, 이 명령이 설정을 만든 뒤 `docker compose up -d --build`까지 실행합니다. `.env`가 준비된 이후에는 Docker Compose 명령을 직접 사용할 수 있습니다.

```bash
python3 docker_setup.py
```

`SITE_ADDRESS`에는 `https://`, 경로, 포트 없이 서버 IPv4 주소 또는 도메인을 넣습니다. Compose가 이 주소를 Flask의 `TRUSTED_HOSTS`와 Caddy 설정에 동일하게 적용합니다. `.env`는 Git과 이미지 빌드 대상에서 제외되므로 GitHub에서 내려받은 새 서버에서도 이 명령을 실행해야 합니다.

`Caddyfile`은 서버별 설정으로 Git에서 제외합니다. 저장소의 `Caddyfile.example`은 새 서버의 기본 설정이며, 이미 있는 `Caddyfile`은 초기 설정과 CD 배포에서 유지합니다. 예제 파일을 나중에 바꿔도 서버 파일에는 자동 반영되지 않습니다. `.env`만 만든 뒤 Compose를 직접 실행할 때는 `Caddyfile`이 없으면 `cp Caddyfile.example Caddyfile`을 먼저 실행하세요.

이미 `.env`가 있으면 비밀키와 관리자 비밀번호를 유지합니다. `SITE_ADDRESS=localhost`인 경우 새 주소를 묻고, 주소를 나중에 바꾸려면 `python3 docker_setup.py --site-address memo.example.com`을 실행합니다. 이 명령은 변경된 설정으로 컨테이너를 다시 생성합니다. `.env`만 준비하려면 `--configure-only`를 사용할 수 있습니다. Docker의 기존 DB에서는 `.env`의 `ADMIN_PASSWORD`를 바꿔도 실제 관리자 계정 비밀번호가 변경되지 않습니다. 로그인 후 앱의 **비밀번호 변경** 화면에서 변경하세요. 로컬 실행용 `.admin-initial-password`와는 별개입니다.

IP 주소로 접속할 때 클라이언트가 TLS SNI를 보내지 않는 경우를 위해 Caddy는 `SITE_ADDRESS`를 기본 SNI로 사용합니다. 클라우드 NAT 뒤에 있는 서버에서는 이 설정이 없으면 인증서를 발급한 뒤에도 TLS 연결이 실패할 수 있습니다.

`BIND_IP`는 기본 `0.0.0.0`으로 둡니다. 클라우드 VM의 공인 IP가 내부 네트워크 인터페이스에 직접 할당되지 않은 경우, 공인 IP를 `BIND_IP`로 넣으면 Caddy의 80·443번 포트 연결이 실패합니다. 확인에는 `docker compose ps`와 `docker compose logs --tail=100 app caddy`를 사용합니다.

브라우저에서 `https://설정한주소`로 접속합니다. 도메인을 사용하는 경우 DNS A/AAAA 레코드가 배포 서버를 가리켜야 하며 서버 방화벽·클라우드 보안 그룹·공유기에서 TCP 80/443 접근을 허용해야 합니다. 방화벽 규칙이 실제 배포 서버에 적용되는지도 확인하세요. Caddy가 공개 인증서 발급과 갱신, HTTP에서 HTTPS로 전환을 처리합니다. 앱의 8000번 포트를 추가로 공개하지 마세요.

IP 또는 localhost를 사용하면 Caddy의 내부 CA가 인증서를 발급합니다. 접속하는 각 기기가 이 CA를 신뢰해야 인증서 오류 없이 사용할 수 있습니다. 아래 명령으로 **공개 루트 인증서만** 추출할 수 있습니다. 추출 파일의 출처와 지문을 확인한 후 해당 기기의 신뢰 저장소에 등록하세요. 루트 인증서의 자동 설치는 수행하지 않습니다.

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./memo-root.crt
openssl x509 -in memo-root.crt -noout -fingerprint -sha256
```

Caddy 설정은 [공식 HTTPS 문서](https://caddyserver.com/docs/automatic-https)와 [프록시 문서](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)를 따릅니다. 앱은 `TRUST_PROXY=1`일 때 Caddy 한 대가 설정한 원래 IP와 HTTPS 정보를 신뢰합니다. Caddy가 사용자 입력 헤더를 덮어쓰고 앱 포트를 비공개로 유지하는 구성을 함께 사용해야 합니다. 프록시를 더 추가할 때는 이 신뢰 범위를 다시 검토하세요.

## Docker 데이터 보존과 이전

회원·메모 DB는 `memo_data`, 인증서는 `caddy_data` 및 `caddy_config`라는 Compose 볼륨에 저장합니다. `docker compose down`이나 이미지 재빌드로 삭제되지 않습니다. **`docker compose down -v`는 DB와 인증서 볼륨까지 삭제하므로 데이터 보존이 필요하면 사용하지 마세요.**

기본 Docker 실행은 새 DB를 생성합니다. 기존 `users.db`는 이미지에 복사하지 않습니다. 기존 회원과 메모를 이어 쓰려면 새 컨테이너를 처음 시작하기 전에 다음처럼 SQLite 백업 API로 일관된 복사본을 만든 뒤 비어 있는 Docker 볼륨에 가져옵니다. 기존 계정을 가져오면 해당 비밀번호가 그대로 유지되며 `.env`의 초기 관리자 비밀번호로 덮어쓰지 않습니다.

```bash
mkdir -p backups
python3 - <<'PY'
from contextlib import closing
from pathlib import Path
import os
import sqlite3

target = Path('backups/users.db')
fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(fd)
with closing(sqlite3.connect('file:users.db?mode=ro', uri=True)) as source:
    with closing(sqlite3.connect(target)) as destination:
        source.backup(destination)
PY
docker compose build app
docker compose run -T --rm --no-deps app python -c 'import os, shutil, sys; f=open("/data/users.db","xb"); os.fchmod(f.fileno(),0o600); shutil.copyfileobj(sys.stdin.buffer,f); f.close()' < backups/users.db
docker compose up -d
```

백업 파일이나 대상 DB가 이미 있으면 이 절차는 덮어쓰지 않고 실패합니다. 이미 사용 중인 Docker DB로 이전하려면 앱을 중지하고 기존 데이터를 별도로 백업한 뒤 진행해야 합니다. 실행 중인 DB를 파일 복사만으로 백업하지 마세요.

## 기능과 접근 권한

- 로그인 후 `/notes`에서 메모 작성, 목록·상세 조회, 수정, 삭제를 할 수 있습니다.
- 메모는 작성자만 접근할 수 있습니다. 관리자도 다른 회원의 메모에 접근할 수 없습니다.
- `/admin`은 관리자 전용 회원 목록입니다. 회원 번호, 아이디, 역할만 표시합니다.
- 상단의 **비밀번호 변경** (`/account/password`)에서 현재 비밀번호와 새 비밀번호, 새 비밀번호 확인을 입력해 본인 비밀번호를 변경합니다.
- 관리자는 회원 목록의 **비밀번호 변경**에서 대상 회원의 새 비밀번호를 설정할 수 있습니다. 이때 **관리자 본인의 현재 비밀번호**를 다시 확인합니다.
- 새 비밀번호는 15~128자이며 기존 비밀번호와 달라야 합니다. 변경된 계정의 모든 로그인 세션을 폐기하므로 새 비밀번호로 다시 로그인해야 합니다. 다른 회원을 변경한 관리자의 로그인은 유지됩니다.
- 메모와 회원 목록은 한 페이지에 20개씩 표시합니다.
- 메모 제목은 120자, 내용은 10,000자까지 입력할 수 있습니다.
- 삭제 확인 화면을 거친 뒤 POST 요청으로 삭제합니다.

## 보안 설정

모든 메모 쿼리에서 작성자를 확인하며, 작성자와 관리자 역할을 폼 입력으로 받지 않습니다. 변경 요청에는 CSRF 검증을 적용하고 사용자 텍스트는 HTML로 해석하지 않고 이스케이프합니다. 비밀번호는 scrypt 해시로, 로그인 토큰은 SHA-256 해시로 DB에 저장합니다. 서버에서 세션 만료와 로그아웃을 확인하며 응답에 CSP와 캐시 금지 헤더를 적용합니다.

로그인은 IP당 5분에 10회, 회원가입은 IP당 1시간에 5회로 제한합니다. 인증 폼은 16KiB, 메모 작성·수정 폼은 128KiB 이내로 제한합니다.

비밀번호 변경은 요청자 계정당 5분에 5회로 제한하며 본인 변경과 관리자 변경 화면이 같은 제한을 공유합니다. 모든 변경 요청에서 CSRF와 서버의 권한을 검증합니다. 비밀번호 해시 갱신과 대상 계정의 세션 폐기를 하나의 트랜잭션으로 처리하고, 동시에 진행 중인 로그인에서도 변경 전 비밀번호로 새 세션이 생성되지 않도록 확인합니다.

운영 배포 시에는 HTTPS를 제공하는 WSGI 서버에서 아래 환경 변수를 설정합니다. HTTPS 사용 여부와 클라이언트 주소가 신뢰할 수 있는 서버·프록시를 통해 전달되어야 합니다. 앱은 임의의 전달 헤더를 자동으로 신뢰하지 않습니다.

| 환경 변수 | 설정 |
| --- | --- |
| `APP_ENV` | `production` |
| `SECRET_KEY` | 최소 32바이트의 고정된 무작위 비밀키 |
| `TRUSTED_HOSTS` | 허용할 호스트 이름을 쉼표로 구분 |
| `DATABASE_PATH` | 선택 사항. 기본값은 `app.py` 옆의 `users.db` |
| `TRUST_PROXY` | 기본 `0`. 위의 비공개 Docker 네트워크와 Caddy 한 대를 사용할 때만 `1` |

로컬에서는 `SECRET_KEY`를 생략하면 실행할 때마다 새 키를 만듭니다. 서버 재시작 후에도 기존 로그인 세션을 유지하려면 같은 비밀키를 환경 변수로 제공해야 합니다.
