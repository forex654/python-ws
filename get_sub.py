import hmac, hashlib
UUID = 'f755dc04-88ff-4348-bd5d-3f1bbad22abb'
sub = hmac.new(UUID.encode(), b'sub', hashlib.sha256).hexdigest()[:10]
ws = hmac.new(UUID.encode(), b'ws', hashlib.sha256).hexdigest()[:10]
print(f"订阅地址: https://你的域名/{sub}")
print(f"WS路径:  /{ws}")
