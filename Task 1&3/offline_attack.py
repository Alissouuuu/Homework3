import hashlib
import base64

# Target hash
target_b64 = "8yQ28QbbPQYfvpta2FBSgsZTGZlFdVYMhn7ePNbaKV8="
target_hash = base64.b64decode(target_b64)

def sha3_hash(password):
    return hashlib.sha3_256(password.encode("utf-8")).digest()

# Read dictionary file
with open("Dictionary.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        pwd = line.strip()
        if sha3_hash(pwd) == target_hash:
            print("Password found:", pwd)
            break
    else:
        print("Password not found in dictionary.")
