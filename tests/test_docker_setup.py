import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import docker_setup


class DockerSetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.joinpath(".env.example").write_text(
            "SITE_ADDRESS=localhost\nSECRET_KEY=\nADMIN_PASSWORD=\n"
            "HTTP_PORT=80\nHTTPS_PORT=443\nBIND_IP=0.0.0.0\n",
            encoding="utf-8",
        )

    def test_first_setup_creates_private_env_and_displays_credentials_once(self):
        messages = []
        address, changed, generated = docker_setup.configure(
            self.root,
            input_fn=lambda prompt: "testsite.capybara.cat",
            output=messages.append,
        )
        self.assertEqual(address, "testsite.capybara.cat")
        self.assertTrue(changed)
        path = self.root / ".env"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        values = docker_setup.env_values(path.read_text(encoding="utf-8"))
        self.assertEqual(values["SITE_ADDRESS"], address)
        self.assertEqual(len(values["SECRET_KEY"]), 64)
        self.assertGreaterEqual(len(values["ADMIN_PASSWORD"]), 15)
        self.assertNotEqual(values["SECRET_KEY"], values["ADMIN_PASSWORD"])
        docker_setup.show_generated(generated, output=messages.append)
        self.assertTrue(any(values["ADMIN_PASSWORD"] in message for message in messages))

        rerun_messages = []
        _, changed, generated = docker_setup.configure(self.root, output=rerun_messages.append)
        self.assertFalse(changed)
        self.assertFalse(generated)
        self.assertFalse(any(values["ADMIN_PASSWORD"] in message for message in rerun_messages))
        self.assertEqual(docker_setup.env_values(path.read_text(encoding="utf-8")), values)

    def test_address_change_preserves_existing_credentials_and_other_settings(self):
        path = self.root / ".env"
        path.write_text(
            "SITE_ADDRESS=34.47.68.123\nSECRET_KEY=" + "a" * 64 + "\n"
            "ADMIN_PASSWORD=" + "b" * 20 + "\nADMIN_NOTE=SBOB{example}\n",
            encoding="utf-8",
        )
        messages = []
        address, changed, generated = docker_setup.configure(
            self.root, requested_site="TESTSITE.CAPYBARA.CAT", output=messages.append
        )
        self.assertEqual(address, "testsite.capybara.cat")
        self.assertTrue(changed)
        self.assertFalse(generated)
        values = docker_setup.env_values(path.read_text(encoding="utf-8"))
        self.assertEqual(values["SECRET_KEY"], "a" * 64)
        self.assertEqual(values["ADMIN_PASSWORD"], "b" * 20)
        self.assertEqual(values["ADMIN_NOTE"], "SBOB{example}")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(any("ADMIN_PASSWORD=" in message for message in messages))

    def test_invalid_address_does_not_create_env(self):
        with self.assertRaises(ValueError):
            docker_setup.configure(self.root, requested_site="https://example.com:443")
        self.assertFalse((self.root / ".env").exists())

    def test_first_run_displays_password_after_compose_output(self):
        output = io.StringIO()
        with patch("docker_setup.__file__", str(self.root / "docker_setup.py")):
            with patch("docker_setup.start_compose", side_effect=lambda *args, **kwargs: print("빌드 완료")):
                with redirect_stdout(output):
                    code = docker_setup.main(["--site-address", "testsite.capybara.cat"])
        self.assertEqual(code, 0)
        password = docker_setup.env_values((self.root / ".env").read_text(encoding="utf-8"))["ADMIN_PASSWORD"]
        self.assertGreater(output.getvalue().index(password), output.getvalue().index("빌드 완료"))

    def test_compose_uses_env_file_values_and_recreates_when_address_changes(self):
        with patch.dict(os.environ, {"SITE_ADDRESS": "wrong.example", "SECRET_KEY": "wrong"}):
            with patch("docker_setup.subprocess.run") as run:
                docker_setup.start_compose(self.root, force_recreate=True)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0], ["docker", "compose", "config", "--quiet"])
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["docker", "compose", "up", "-d", "--build", "--force-recreate"],
        )
        self.assertNotIn("SITE_ADDRESS", run.call_args_list[1].kwargs["env"])
        self.assertNotIn("SECRET_KEY", run.call_args_list[1].kwargs["env"])


if __name__ == "__main__":
    unittest.main()
