1. Test Pii

```sh

curl -s http://localhost:8080/v1/eval \
  -H "Content-Type: application/json" \
  -d '{
    "kind": "response",
    "text": "Email e@example.com and ip 8.8.8.8"
  }' | jq

```
