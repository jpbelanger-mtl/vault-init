# vault-init

Simple wrapper over the vault init API.

Will call the init API passing it the same parameters as the CLI. But instead of printing the KEYs on stdout, it will email the keys to all the email addresses of the PGP key.

For now it only support keybase key. Used part of the CLI wrapper to fetch the keybase. Could be easily adapted to accept both keybase and base64 keys on the command line.

```
  -keybase string
    	Comma-separated list of keybase account to fetch key from
  -secretShares int
    	Number of secret shared key to generate (default 5)
  -secretThreshold int
    	Secret threshold for unsealing the vault (default 3)
  -smtpFrom string
    	From email address
  -smtpHost string
    	SMTP host to use in <host>:<port> format (default "localhost:25")
  -vaultURL string
    	Vault cluster url in http(s)://<host>:<port> format (default "http://127.0.0.1:8200")
```