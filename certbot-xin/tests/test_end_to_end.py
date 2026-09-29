"""End-to-end tests for certbot-xin against a real xin binary.

Unlike src/certbot_xin/_internal/tests/ (the forked-and-adapted
certbot-nginx unit test suite, run in the venv against the certbot core
being tested), this module builds a small standalone /etc/xin-style fixture
from scratch and drives the real, forked configurator against it -- ending
with an actual `xin -t` invocation on the config certbot produced. That last
assertion is the key proof available without a live ACME server: certbot's
parser/writer round-trip produced a config xin itself is willing to load.

Run with a built Xin binary and certbot-xin installed (editable or
otherwise) in the active venv:

    pytest certbot-xin/tests/test_end_to_end.py

Set XIN_BIN to a built Xin binary to run the real configuration check.
Without it, that assertion is skipped.

This reuses certbot.tests.util.ConfigTestCase (the same base the forked
unit suite in src/certbot_xin/_internal/tests/test_util.py uses) rather
than hand-rolling a NamespaceConfig, since XinConfigurator.conf() and the
Reverter base class expect a real argparse-backed config object with a
specific set of attributes -- a bare MagicMock satisfies neither.
"""
import datetime
import os
import shutil
import subprocess
import tempfile
from unittest import mock

import pytest

from certbot.tests import util as certbot_test_util

from certbot_xin._internal import configurator as configurator_mod

XIN_BIN = os.environ.get("XIN_BIN", "")

XIN_CONF_TEMPLATE = """\
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    server {
        listen 80;
        server_name example.com;

        location / {
            return 200 "ok\\n";
        }
    }
}
"""

XIN_V_OUTPUT = (
    "xin version: xin/0.1.5-preview\n"
    "built with rustc (target aarch64-unknown-linux-gnu)\n"
    "TLS: rustls with aws-lc-rs (not the FIPS module)\n"
)


def _make_self_signed_cert(cert_path, key_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


class EndToEndTest(certbot_test_util.ConfigTestCase):
    """Fixture: a throwaway /etc/xin-style tree (xin.conf plus the
    packages' compat nginx.conf -> xin.conf symlink -- see
    packaging/build-deb.sh) with a real xin binary run against the config
    certbot's writer produces.
    """

    def setUp(self):
        super().setUp()

        self.etc_xin = tempfile.mkdtemp(prefix="xin-etc-")
        self.addCleanup(shutil.rmtree, self.etc_xin, ignore_errors=True)
        self.logs_dir = tempfile.mkdtemp(prefix="xin-logs-")
        self.addCleanup(shutil.rmtree, self.logs_dir, ignore_errors=True)
        self.cert_dir = tempfile.mkdtemp(prefix="xin-certs-")
        self.addCleanup(shutil.rmtree, self.cert_dir, ignore_errors=True)

        with open(os.path.join(self.etc_xin, "xin.conf"), "w") as f:
            f.write(XIN_CONF_TEMPLATE)

        self.cert_path = os.path.join(self.cert_dir, "cert.pem")
        self.key_path = os.path.join(self.cert_dir, "key.pem")
        _make_self_signed_cert(self.cert_path, self.key_path)

        backups = os.path.join(self.config.work_dir, "backups")
        self.config.xin_server_root = self.etc_xin
        self.config.xin_ctl = "xin"
        self.config.xin_sleep_seconds = 0
        self.config.le_vhost_ext = "-le-ssl.conf"
        self.config.logs_dir = self.logs_dir
        self.config.backup_dir = backups
        self.config.temp_checkpoint_dir = os.path.join(self.config.work_dir, "temp_checkpoints")
        self.config.in_progress_dir = os.path.join(backups, "IN_PROGRESS")
        self.config.server = "https://acme-server.example/directory"
        self.config.http01_port = 80
        self.config.https_port = 443
        os.makedirs(self.config.config_dir, exist_ok=True)
        os.makedirs(self.config.work_dir, exist_ok=True)

        with mock.patch("certbot_xin._internal.configurator.XinConfigurator.config_test"), \
             mock.patch("certbot_xin._internal.configurator.util.exe_exists",
                        return_value=True), \
             mock.patch("certbot_xin._internal.configurator.subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = XIN_V_OUTPUT
            self.configurator = configurator_mod.XinConfigurator(self.config, name="xin")
            self.configurator.prepare()

    def test_server_root_resolves_to_xin_conf(self):
        assert self.configurator.nginx_conf == os.path.join(self.etc_xin, "xin.conf")

    def test_version_detection_maps_xin_v_output(self):
        assert self.configurator.xin_version == (0, 1, 5)
        assert (self.configurator.version
                == configurator_mod.XinConfigurator.NGINX_CAPABILITY_VERSION)

    def test_deploy_cert_writes_ssl_directives_xin_loads(self):
        with mock.patch("certbot_xin._internal.configurator.display_util.notify"):
            self.configurator.deploy_cert(
                "example.com", self.cert_path, self.key_path,
                self.cert_path, self.cert_path)
            self.configurator.save()

        with open(os.path.join(self.etc_xin, "xin.conf")) as conf_file:
            xin_conf_text = conf_file.read()
        assert "ssl_certificate" in xin_conf_text
        assert "ssl_certificate_key" in xin_conf_text
        assert self.cert_path in xin_conf_text
        assert self.key_path in xin_conf_text

        # The key end-to-end assertion: xin itself is willing to load the
        # config certbot's writer produced. -c must be absolute (same
        # convention as nginx: a relative path resolves against the
        # compiled prefix, not cwd).
        if not XIN_BIN or not os.path.isfile(XIN_BIN):
            pytest.skip("set XIN_BIN to an existing Xin binary for this check")
        result = subprocess.run(
            [XIN_BIN, "-t", "-c", os.path.join(self.etc_xin, "xin.conf")],
            capture_output=True, text=True)
        assert result.returncode == 0, (
            "xin -t rejected certbot's edited config:\nstdout=%s\nstderr=%s"
            % (result.stdout, result.stderr))

    def test_reload_invokes_ctl_with_s_reload(self):
        with mock.patch("certbot_xin._internal.configurator.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""
            self.configurator.restart()
        args = mock_run.call_args[0][0]
        assert args[0] == "xin"
        assert "-s" in args and "reload" in args
        assert args[args.index("-s") + 1] == "reload"
