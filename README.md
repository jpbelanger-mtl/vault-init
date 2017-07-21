# vault-init

Simple wrapper over the vault init API.

Will call the init API passing it the same parameters as the CLI. But instead of printing the KEYs on stdout, it will email the keys to all the email addresses of the PGP key.

For now it only support keybase key. Used part of the CLI wrapper to fetch the keybase. Could be easily adapted to accept both keybase and base64 keys on the command line.

```
  -keybase string
    	Comma-separated list of keybase account to fetch key from
  -noonce string
    	Nonce used for rekey progress
  -rekey
    	This will be a rekey operation
  -secretThreshold int
    	Secret threshold for unsealing the vault (default 3)
  -smtpFrom string
    	From email address
  -smtpHost string
    	SMTP host to use in <host>:<port> format (default "localhost:25")
  -vaultURL string
    	Vault cluster url in http(s)://<host>:<port> format (default "http://127.0.0.1:8200")
```

## Initializing a vault

example:
```
vault-init -keybase=keybase:jpbelanger -smtpFrom=no-reply@example.com -secretThreshold=1
```

This will initialize your vault and generate as many keys as CSV value in the keybase parameter. One the initialization is done, it will use the Keybase email address to send them their unseal key (encrypted with their PGP key)

## Rekeying

Similar to initializing, you can rekey by passing the `-rekey` parameter
```
vault-init -rekey -keybase=keybase:jpbelanger,keybase:anotheruser,keybase:mymom -smtpFrom=no-reply@example.com -secretThreshold=2
```

Once the rekey initialization is done, it will output a nonce token and ask you for your unseal key, so the operateur that triggers the rekey needs to be a unseal key owner. 
You will need to provide the `nonce` token to the next unseal (if required) and they would type the following command:
```
vault-init -rekey -nonce=<value> -keybase=keybase:jpbelanger,keybase:anotheruser,keybase:mymom -smtpFrom=no-reply@example.com -secretThreshold=2
```

On the last required unseal key, the tool will receive the new unseal key (encrypted), output them at the console and send them by email to the PGP owner.