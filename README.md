# op_client 

This is a small client to get started with the Go package "github.com/1password/onepassword-sdk-go"

# How to run?

## Set env Variable

OP_SERVICE_ACCOUNT_TOKEN value must starts with ops_..

## Powershell 

```
$env:OP_SERVICE_ACCOUNT_TOKEN="ops_XXXX"
```

## Linux

export OP_SERVICE_ACCOUNT_TOKEN="ops_XXXX"

## Run the CLI-APP wihout compilation

### Fetch password only

```
go run . --secret-ref="op://<VAULT_NAME OR VAULT_ID>/<VAULT_ITEM_ID>/Login/password"
```

### create password and ssh key

```
go run . --create-password --create-ssh --create-password-memorable
```

