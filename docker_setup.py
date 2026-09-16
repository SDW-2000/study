"""Create a private Compose .env file and start the Docker deployment."""

import argparse
import ipaddress
import os
import re
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path


MANAGED_KEYS = {"SITE_ADDRESS", "SECRET_KEY", "ADMIN_PASSWORD"}
COMPOSE_KEYS = MANAGED_KEYS | {"BIND_IP", "HTTP_PORT", "HTTPS_PORT", "ADMIN_NOTE"}
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def site_address(value):
    value = value.strip()
    if not value or any(character in value for character in ":/@\\ \t\r\n"):
        raise ValueError("SITE_ADDRESS에는 https://, 경로, 포트 없이 도메인 또는 IPv4 주소만 넣으세요.")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass
    if all(character in "0123456789." for character in value):
        raise ValueError("올바른 IPv4 주소를 입력하세요.")
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("올바른 도메인을 입력하세요.") from error
    labels = domain.split(".")
    if len(domain) > 253 or (len(labels) == 1 and domain != "localhost") or not all(
        LABEL.fullmatch(label) for label in labels
    ):
        raise ValueError("올바른 도메인을 입력하세요. 예: testsite.example.com")
    return domain


def env_values(text):
    values = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in MANAGED_KEYS and key in values:
            raise ValueError(f".env에 {key}가 두 번 정의되어 있습니다.")
        values[key] = value.strip()
    return values


def updated_env(text, updates):
    lines = []
    seen = set()
    for line in text.splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line and not line.lstrip().startswith("#") else ""
        if key in updates:
            lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            lines.append(line)
    for key in updates:
        if key not in seen:
            lines.append(f"{key}={updates[key]}")
    return "\n".join(lines) + "\n"


def write_private_env(path, text, existed):
    if existed:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".env.", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                file.write(text)
            os.replace(temporary_name, path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as file:
                file.write(text)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    path.chmod(0o600)


def configure(root, requested_site=None, input_fn=input, output=print):
    path = root / ".env"
    if path.is_symlink():
        raise ValueError(".env가 심볼릭 링크입니다. 일반 파일로 바꾼 뒤 다시 실행하세요.")
    existed = path.exists()
    if existed and not path.is_file():
        raise ValueError(".env가 일반 파일이 아닙니다.")
    text = path.read_text(encoding="utf-8") if existed else (root / ".env.example").read_text(encoding="utf-8")
    values = env_values(text)

    current_site = values.get("SITE_ADDRESS", "")
    if requested_site is not None:
        address = site_address(requested_site)
    elif not existed or not current_site or current_site == "localhost":
        prompt = "서버 도메인 또는 IPv4 주소 (예: testsite.example.com): "
        if current_site == "localhost":
            prompt = "서버 도메인 또는 IPv4 주소 (Enter: localhost 유지): "
        answer = input_fn(prompt).strip()
        address = site_address(answer or current_site)
    else:
        address = site_address(current_site)

    updates = {}
    if address != current_site:
        updates["SITE_ADDRESS"] = address
    generated = {}
    if not values.get("SECRET_KEY"):
        generated["SECRET_KEY"] = secrets.token_hex(32)
    elif len(values["SECRET_KEY"].encode("utf-8")) < 32:
        raise ValueError("기존 SECRET_KEY가 너무 짧습니다. 새 무작위 키로 교체하세요.")
    if not values.get("ADMIN_PASSWORD"):
        generated["ADMIN_PASSWORD"] = secrets.token_urlsafe(24)
    elif not 15 <= len(values["ADMIN_PASSWORD"]) <= 128:
        raise ValueError("기존 ADMIN_PASSWORD는 15~128자여야 합니다.")
    updates.update(generated)

    if updates or not existed:
        write_private_env(path, updated_env(text, updates), existed)
        output(f"설정을 {path}에 저장했습니다 (권한 600).")
    else:
        path.chmod(0o600)
        output("기존 .env 설정을 유지합니다.")
    return address, bool(updates or not existed), generated


def show_generated(generated, output=print):
    if generated:
        output("새로 생성한 값은 이번 실행에서만 표시합니다. 채팅·스크린샷·Git에 올리지 마세요.")
        for key, value in generated.items():
            output(f"{key}={value}")
        output("관리자 아이디: admin (기존 DB의 관리자 비밀번호는 변경되지 않습니다.)")


def start_compose(root, force_recreate=False):
    environment = os.environ.copy()
    for key in COMPOSE_KEYS:
        environment.pop(key, None)
    subprocess.run(["docker", "compose", "config", "--quiet"], cwd=root, env=environment, check=True)
    command = ["docker", "compose", "up", "-d", "--build"]
    if force_recreate:
        command.append("--force-recreate")
    subprocess.run(command, cwd=root, env=environment, check=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="첫 Docker 배포 설정과 실행")
    parser.add_argument("--site-address", help="입력 질문 없이 사용할 도메인 또는 IPv4 주소")
    parser.add_argument("--configure-only", action="store_true", help=".env만 설정하고 Docker는 실행하지 않음")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    generated = {}
    try:
        address, changed, generated = configure(root, requested_site=args.site_address)
        if not args.configure_only:
            start_compose(root, force_recreate=changed)
            print(f"접속 주소: https://{address}")
    except (ValueError, EOFError, FileNotFoundError, subprocess.CalledProcessError, OSError) as error:
        print(f"설정 또는 Docker 실행 실패: {error}", file=sys.stderr)
        return 1
    finally:
        show_generated(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
