import base64, os, jwt, datetime
from dotenv import load_dotenv
from typing import Optional, Dict, Any


load_dotenv()

def load_secret_key() -> bytes:
    key_base = os.getenv('SECRET_KEY')
    if len(key_base) == 44 and '=' in key_base:
        try:
            key_bytes = base64.urlsafe_b64decode(key_base)
            if len(key_bytes) != 32:
                return key_base.encode('utf-8')[:32].ljust(32, b'\0')
            return key_bytes

        except:
            pass

    key_bytes = key_base.encode('utf-8')
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'\0')

    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]

    return key_bytes


SECRET_KEY = load_secret_key()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DELTA = datetime.timedelta(hours=24)


def create_jwt_token(user_data: Dict[str, Any]) -> str:
    payload = {
        'user': user_data,
        'user_id': user_data['id'],
        'exp': datetime.datetime.now() + JWT_EXPIRATION_DELTA,
        'iat': datetime.datetime.now(),
        'iss': 'aiohttp'
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM], options={"verify_exp": True}, leeway=12000)
        return payload

    except jwt.ExpiredSignatureError:
        return None

    except jwt.ExpiredSignatureError:
        return  None

    except jwt.InvalidTokenError:
        return None
