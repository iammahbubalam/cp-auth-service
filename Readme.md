# Commands

```
docker run -d --name auth_postgres \
-e POSTGRES_USER=root \
-e POSTGRES_PASSWORD=root \
-e POSTGRES_DB=auth_db \
-p 5432:5432 \
postgres:18rc1-alpine3.22
```

```
docker run -d \
  --name auth_redis \
  -p 6379:6379 \
  redis:7 \
  redis-server --requirepass root

```

## Generate Public and Private Keys

```
# Generate a 4096-bit private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096

# Extract the public key from the private key
openssl rsa -pubout -in private_key.pem -out public_key.pem}
```

## Descriptor File

```
 protoc --proto_path=src/main/proto --descriptor_set_out=src/main/resources/descriptors/auth.desc --include_imports auth.proto
```