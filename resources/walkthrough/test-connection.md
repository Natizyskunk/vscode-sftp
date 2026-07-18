# Test the connection

Before syncing any files, confirm SFTPresso can reach your server.

Run **SFTP: Test Connection** — it connects to the active profile's remote using
your `sftp.json` and reports success or a specific failure (auth, refused,
timeout, DNS, …). A **Test Connection** CodeLens also sits at the top of the
config file, and the status-bar indicator shows the live connection state.

If it fails, reopen `sftp.json` and check the host, port, username, and
authentication, then try again.
