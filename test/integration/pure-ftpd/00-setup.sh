#!/usr/bin/with-contenv sh
# Bind-mounted into crazymax/pure-ftpd at /etc/cont-init.d/00-setup.sh so it runs
# before the image's own 01-config.sh. It provisions everything the integration
# tests need: a self-signed TLS cert (test use only), the `--tls 1` flag so the
# server offers explicit FTPS (AUTH TLS), and a writable virtual user.
set -e

PEM=/data/pureftpd.pem
FLAGS=/data/pureftpd.flags
PASSWD=/data/pureftpd.passwd
FTP_HOME=/home/testuser

# Self-signed cert+key in a single PEM, the layout pure-ftpd expects. Regenerated
# only when absent so restarts keep the same cert. NOT for any real deployment.
if [ ! -f "$PEM" ]; then
  echo "[00-setup] generating self-signed TLS certificate"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout /tmp/pureftpd-key.pem -out /tmp/pureftpd-cert.pem \
    -subj "/CN=localhost" >/dev/null 2>&1
  cat /tmp/pureftpd-key.pem /tmp/pureftpd-cert.pem > "$PEM"
  rm -f /tmp/pureftpd-key.pem /tmp/pureftpd-cert.pem
  chmod 600 "$PEM"
fi

# Offer explicit TLS (AUTH TLS) without requiring it, so the same server answers
# both `secure: true` and `secure: "control"` clients. 01-config.sh appends the
# contents of this file to pure-ftpd's flags.
printf -- "--tls 1\n" > "$FLAGS"

# Virtual user mapped onto the system ftp account (uid/gid 21). pure-pw reads the
# password twice from stdin when it isn't attached to a tty.
mkdir -p "$FTP_HOME"
chown ftp:ftp "$FTP_HOME"
if ! pure-pw show "$FTP_USER" -f "$PASSWD" >/dev/null 2>&1; then
  echo "[00-setup] creating virtual user $FTP_USER"
  printf '%s\n%s\n' "$FTP_PASSWORD" "$FTP_PASSWORD" | \
    pure-pw useradd "$FTP_USER" -f "$PASSWD" -u ftp -g ftp -d "$FTP_HOME"
fi
