# certbot-xin

Certbot support for the Xin web server. The plugin and its `xin` entry point
live entirely in this package. Install it alongside your distribution's
Certbot package; no replacement Certbot build is needed. Python 3.6 or newer
is required.

```sh
certbot -a xin -i xin -d example.com
```

The plugin reads `/etc/xin/xin.conf`. Certbot keeps certificates and renewal
state in its normal `/etc/letsencrypt` directory. `--xin-server-root` changes
the Xin configuration directory.

This code began as a modified fork of `certbot-nginx` 4.0.0. Its original
Apache and MIT license text is preserved in [LICENSE.txt](LICENSE.txt), with
changes identified in [NOTICE](NOTICE) and the modified files. Upstream's
current Nginx implementation lives under `certbot/src/certbot/_internal/plugins/nginx/`.
