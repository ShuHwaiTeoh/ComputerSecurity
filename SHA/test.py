import hashlib
import sys
hasher = hashlib.sha512()
with open(sys.argv[1], 'r') as file_to_hash:
    message = file_to_hash.read()
hasher.update(message.encode('utf-8'))
with open(sys.argv[2], "w") as f:
    f.write(hasher.hexdigest())
