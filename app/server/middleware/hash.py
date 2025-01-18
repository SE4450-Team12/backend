import bcrypt
from datetime import datetime

#combine password with timestamp and then hash it, return the hashed password and the salt together
def hash_password(password: str) -> dict:
    timestamp = datetime.utcnow().isoformat()
    salted_password = f"{password}{timestamp}"
    hashed_password = bcrypt.hashpw(salted_password.encode('utf-8'), bcrypt.gensalt())

    return {"hashed_password": hashed_password.decode('utf-8'), "salt": timestamp}


#remake the salted password using the timestamp and then verify
def verify_password(password: str, salt: str, hashed_password: str) -> bool:
    salted_password = f"{password}{salt}"

    return bcrypt.checkpw(salted_password.encode('utf-8'), hashed_password.encode('utf-8'))