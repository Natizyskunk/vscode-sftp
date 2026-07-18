# Create your config

Every connection starts from a `.vscode/sftp.json` in your open folder.

Run **SFTP: Config** and pick **Quick setup** — a guided wizard prompts for
protocol, host, port, username, authentication, and remote path, then writes
`sftp.json` for you. Prefer to write it by hand? Choose **Edit JSON** for a
starter template.

A minimal config looks like this:

```jsonc
{
  "host": "server.example.com",
  "protocol": "sftp",
  "username": "user1",
  "remotePath": "/var/www/project",
  "uploadOnSave": false
}
```

Leave `password` out to be prompted on connect, with an offer to remember it in
your OS keychain. `sftp.json` is read as JSONC, so comments and trailing commas
are fine.
