import hmac, hashlib
UUID = 'cbc0fec5-b992-44a3-b97c-d943c5378e08'
sub = hmac.new(UUID.encode(), b'sub', hashlib.sha256).hexdigest()[:10]
ws = hmac.new(UUID.encode(), b'ws', hashlib.sha256).hexdigest()[:10]
print(f"订阅地址: https://你的域名/{sub}")
print(f"WS路径:  /{ws}")
