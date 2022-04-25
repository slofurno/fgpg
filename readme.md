
#### export your existing pgp key

```sh
gpg --armor --export-secret-keys <fingerprint> > myprivate.key
```

#### unlock if your key is password protected

```sh
cd unlock
go build
./unlock <myprivate.key> <passphrase> > myunlocked.private.key
```

#### update the signer script with the path to your key

```sh
export PGP_PRIVATE_KEY=/home/user/myunlocked.private.key
```

#### configure git to use it

```toml
[commit]
  gpgsign = true

[gpg]
  program = /home/user/signer
```
