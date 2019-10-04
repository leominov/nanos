# vault-crypt

## Usage

### Encrypt

```shell
vault-crypt -k hashivault://transit-key-id?version=latest ./source-file ./encrypted-file
```

### Decrypt

```shell
vault-crypt -d -k base64key://ZW5jb2RlZC1rZXk= ./encrypted-file ./decrypted-file
```
