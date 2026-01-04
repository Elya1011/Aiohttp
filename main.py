import json
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from aiohttp import web
from models import init_orm, close_orm, DbSession, User, Ads
from cryptography import fernet
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_session import setup, get_session
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

@web.middleware
async def auth_middleware(request: web.Request, handler):
    if request.path == '/login/' or request.path == '/users/' and request.method == 'POST':
        return await handler(request)

    if request.path.startswith('/ads/') and request.method == 'GET':
        return await handler(request)

    session = await get_session(request)
    user_id = session.get('user_id')

    if not user_id:
        raise web.HTTPUnauthorized(text=json.dumps({"error": "Unauthorized"}), content_type="application/json")

    async with DbSession() as session:
        user = await session.get(User, user_id)
        if not user:
            raise web.HTTPUnauthorized(text=json.dumps({"error": "User not found"}), content_type="application/json")
        request.user = user
    return await handler(request)

app = web.Application()
setup_sessions(app)
app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)
app.middlewares.append(auth_middleware)

class SessionView(web.View):
    async def post(self):
        data = await self.request.json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise get_error("Email and password required", web.HTTPBadRequest)

        stmt = select(User).where(User.email == email)
        result = await self.request.session.execute(stmt)
        user = result.scalar_one_or_none()

        if not user or  not user.check_password(password):
            raise get_error("Invalid credentials", web.HTTPUnauthorized)

        session = await get_session(self.request)
        session['user_id'] = user.id

        return web.json_response({"message": "Login successful", "user": user.dict})

    async def delete(self):
        session = await get_session(self.request)
        session.pop('user_id', None)
        return web.json_response({"message": "Logged out"})


class UserView(web.View):
    @property
    def user_id(self) -> int:
        return int(self.request.match_info["user_id"])

    @property
    def session(self) -> AsyncSession:
        return self.request.session

    def check_auth(self):
        if not hasattr(self.request, 'user') or not self.request.user:
            raise get_error("Authentication required", web.HTTPUnauthorized)

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
        if "password" not in user_json:
            raise get_error("Password is required", web.HTTPBadRequest)
        user = User(
            first_name=user_json["first_name"],
            last_name=user_json["last_name"],
            email=user_json["email"],
        )
        user.set_password(user_json["password"])
        await add_user(self.session, user)
        return web.json_response(user.dict, status=201)

    async def delete(self):
        self.check_auth()
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

    def check_auth(self):
        if not hasattr(self.request, 'user') or not self.request.user:
            raise get_error("Authentication required", web.HTTPUnauthorized)

    def check_ownership(self, ads):
        self.check_auth()
        if ads.user_id != self.request.user.id:
            raise get_error("You can only modify your own ads", web.HTTPForbidden)

    async def get_ads(self) -> User:
        ads = await self.session.get(Ads, self.ads_id)
        if ads is None:
            raise get_error("Ads not found", web.HTTPNotFound)
        return ads

    async def get(self):
        ads = await self.get_ads()
        return web.json_response(ads.dict)

    async def post(self):
        self.check_auth()
        ads_json = await self.request.json()
        ads = Ads(
            title=ads_json["title"],
            description=ads_json["description"],
            user_id=self.request.user.id
        )
        self.session.add(ads)
        await self.session.commit()
        return web.json_response(ads.dict, status=201)

    async def patch(self):
        ads = await self.get_ads()
        self.check_ownership(ads)

        ads_json = await self.request.json()

        if "title" in ads_json:
            ads.title = ads_json["title"]
        if "description" in ads_json:
            ads.description = ads_json["description"]

        await self.session.commit()
        return web.json_response(ads.dict)

    async def delete(self):
        ads = await self.get_ads()
        self.check_ownership(ads)

        await self.session.delete(ads)
        await self.session.commit()
        return web.json_response({"status": "deleted"})

app.add_routes(
    [
        web.get(r'/users/{user_id:\d+}', UserView),
        web.delete(r'/users/{user_id:\d+}', UserView),
        web.post(r'/users/', UserView),
        web.post('/login/', SessionView),
        web.post('/logout/', SessionView),
        web.get(r'/ads/{ads_id:\d+}', AdsView),
        web.post(r'/ads/', AdsView),
        web.patch(r'/ads/{ads_id:\d+}', AdsView),
        web.delete(r'/ads/{ads_id:\d+}', AdsView),
    ]
)
web.run_app(app)