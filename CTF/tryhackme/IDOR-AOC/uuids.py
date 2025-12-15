import datetime
import uuid
TIME_HI_VERSION = 0x11f0
CLOCK_SEQ_HI = 0xac
CLOCK_SEQ_LOW = 0x99
NODE = 0x026ccdf7d769
def uuid_from_timestamp(ts):
    base = datetime.datetime(1582, 10, 15)
    intervals = int((ts - base).total_seconds() * 10**7)
    time_low = intervals & 0xffffffff
    time_mid = (intervals >> 32) & 0xffff
    time_hi_version = ((intervals >> 48) & 0x0fff) | (1 << 12)
    fields = (
    time_low,
    time_mid,
    time_hi_version,
    CLOCK_SEQ_HI | 0x80,
    CLOCK_SEQ_LOW,
    NODE
    )
    return uuid.UUID(fields=fields)
    

start = datetime.datetime(2025, 11, 20, 20, 0, 0)
end = datetime.datetime(2025, 11, 21, 0, 0, 0)
current = start

with open("uuids.txt", "w") as f:
    while current < end:
        u = str(uuid_from_timestamp(current))
        f.write(u + "\n")
        current += datetime.timedelta(minutes=1)
    print("[+] Done! UUIDs saved to uuids.txt") 
