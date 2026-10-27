## SFTP configuration

### agent
Path to ssh-agent's UNIX socket for ssh-agent-based user authentication. <br>
Windows users must set to 'pageant' for authenticating with Pagenat or (actual) path to a Cygwin "UNIX socket". <br>
It'd get more stability because some client/server have some sort of configured/hard coded limit.

| Key | Value |
| --- | --- |
| *agent* | *string* |

```json
{
  "agent": "/_subfolder_/agent"
}
```

### privateKeyPath
Absolute path to user private key.

| Key | Value |
| --- | --- |
| *privateKeyPath* | *string* |

```json
{
  "privateKeyPath": "/.ssh/key.pem"
}
```

### passphrase
For an encrypted private key, this is the passphrase string used to decrypt it. <br>
Set to 'true' for enable passphrase dialog. This will prevent from using cleartext passphrase in this config.

| Key | Value |
| --- | --- |
| *passphrase* | *mixed* |

```json
{
  "passphrase": true
}
```

### interactiveAuth
Enable keyboard interaction authentication mechanism. Set to 'true' to enable `verifyCode` dialog. <br>
For example using Google Authentication (multi-factor). Or pass array of predefined phrases to automatically enter them without user prompting.

| 💡 Note |
| :--- |
| *Requires the server to have keyboard-interactive authentication enabled.* | 

| Key | Value | Default |
| --- | --- | --- |
| *interactiveAuth* | *boolean*\|*string[]* | 'false' |

```json
{
  "interactiveAuth": true
}
```

### algorithms
Explicit overrides for the default transport layer algorithms used for the connection.

**Default**:
```json
{
  "algorithms": {
    "kex": [
      "ecdh-sha2-nistp256",
      "ecdh-sha2-nistp384",
      "ecdh-sha2-nistp521",
      "diffie-hellman-group-exchange-sha256"
    ],
    "cipher": [
      "aes128-gcm",
		"aes128-gcm@openssh.com",
		"aes256-gcm",
		"aes256-gcm@openssh.com",
		"aes128-cbc",
		"aes192-cbc",
		"aes256-cbc",
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr"
    ],
    "serverHostKey": [
      "ssh-rsa",
      "ssh-dss",
      "ssh-ed25519",
      "ecdsa-sha2-nistp256",
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp521",
      "rsa-sha2-512",
      "rsa-sha2-256"
    ],
    "hmac": [
      "hmac-sha2-256",
      "hmac-sha2-512"
    ]
  },
}
```

### sshConfigPath
Absolute path to your SSH configuration file.

| Key | Value | Default |
| --- | --- | --- |
| *sshConfigPath* | *string* | `~/.ssh/config` |

```json
{
  "sshConfigPath": "~/.ssh/config"
}
```

### sshCustomParams
Extra parameters appended to the SSH command used by "Open SSH in Terminal".

| Key | Value |
| --- | --- |
| *sshCustomParams* | *string* |

```json
{
  "sshCustomParams": "-g"
}
```
