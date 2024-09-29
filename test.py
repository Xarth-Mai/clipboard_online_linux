import hashlib
import requests
import time

AUTH_PASSWORD = "1234"
timestamp = str(int(time.time()))
md5_hash = hashlib.md5((timestamp + AUTH_PASSWORD).encode()).hexdigest()

# 发送GET请求
response = requests.get(
    'http://localhost:8777',
    headers={'Timestamp': timestamp, 'MD5': md5_hash}
)
print(timestamp)
print(md5_hash)
print(response.text)

# 发送POST请求
response = requests.post(
    'http://localhost:8777',
    headers={'Timestamp': timestamp, 'MD5': md5_hash},
    data="=Hello, Clipboard!"
)
print(response.status_code)