# Commands

```
docker run -d 
--name auth_postgres \
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