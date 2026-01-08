from passlib.context import CryptContext
import asyncio


pwd_context = CryptContext(
    schemes=['bcrypt'],
    bcrypt__rounds=12,
    deprecated='auto'
)

async def hash_password(password: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, pwd_context.hash, password)


async def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password:
        return None

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        pwd_context.verify,
        plain_password,
        hashed_password
    )