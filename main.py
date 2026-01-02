import json
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from aiohttp import web
from models import init_orm, close_orm, DbSession, User, Ads, drop_db
from cryptography import fernet
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_session import setup
import base64


def generate_secret_key():
    return fernet.Fernet.generate_key()

def setup_sessions(app: web.Application):
    secret_key = base64.urlsafe_b64decode(generate_secret_key())
    storage = EncryptedCookieStorage(secret_key)
    setup(app, storage)

def get_error(msg: str | list | dict, cls):
    msg = {"error": msg}
    msg_json = json.dumps(msg)
    return cls(
        text=msg_json,
        content_type="application/json",
    )

async def add_user(session: AsyncSession, user: User):
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        raise get_error("User already exists", web.HTTPConflict)

async def orm_context(app: web.Application):
    print('STARS')
    # await drop_db()
    await init_orm()
    yield
    await close_orm()
    print('FINISH')

@web.middleware
async def session_middleware(request: web.Request, handler):
    async with DbSession() as session:
        request.session = session
        response = await handler(request)
        return response

app = web.Application()
app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)

class UserView(web.View):
    @property
    def user_id(self) -> int:
        return int(self.request.match_info["user_id"])

    @property
    def session(self) -> AsyncSession:
        return self.request.session

    async def get_user(self) -> User:
        user = await self.session.get(User, self.user_id)
        if user is None:
            raise get_error("User not found", web.HTTPNotFound)
        return user

    async def get(self):
        user = await self.get_user()
        return web.json_response(user.dict)

    async def post(self):
        user_json = await self.request.json()
        user = User(
            first_name=user_json["first_name"],
            last_name=user_json["last_name"],
            email=user_json["email"],
        )
        user.set_password(user_json["password"])
        await add_user(self.session, user)
        return web.json_response(user.dict)

    async def delete(self):
        user = await self.get_user()
        await self.session.delete(user)
        await self.session.commit()
        return web.json_response({"status": "deleted"})

class AdsView(web.View):
    @property
    def ads_id(self) -> int:
        return int(self.request.match_info["ads_id"])

    @property
    def session(self) -> AsyncSession:
        return self.request.session

    async def get_ads(self) -> User:
        ads = await self.session.get(Ads, self.ads_id)
        if ads is None:
            raise get_error("Ads not found", web.HTTPNotFound)
        return ads

    async def get(self):
        ads = await self.get_ads()
        return web.json_response(ads.dict)

    async def post(self):
        ads_json = await self.request.json()
        ads = Ads(
            title=ads_json["title"],
            description=ads_json["description"]
        )
        self.session.add(ads)
        await self.session.commit()

    async def patch(self):
        pass

    async def delete(self):
        pass

app.add_routes(
    [
        web.get(r'/users/{user_id:\d+}', UserView),
        web.delete(r'/users/{user_id:\d+}', UserView),
        web.post(r'/users/', UserView),
        web.get(r'/ads/{ads_id:\d+}', AdsView),
        web.post(r'/ads/}', AdsView),
        web.patch(r'/ads/{ads_id:\d+}', AdsView),
        web.delete(r'/ads/{ads_id:\d+}', AdsView),
    ]
)
web.run_app(app)