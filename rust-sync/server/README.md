# 验证server
```bash
grpcurl -plaintext -d '{"username": "admin", "password": "admin", "device_id": "device-001"}' \
    -proto proto/sync.proto \
    '[::1]:50051' sync.SyncService/Login

grpcurl -plaintext -H "Authorization: Bearer <TOKEN>" \
    -proto proto/sync.proto \
    '[::1]:50051' sync.SyncService/WhoAmI
```