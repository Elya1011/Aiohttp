import json
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy import select
from aiohttp import web
from jwt_auth import verify_jwt_token, create_jwt_token
from models import init_orm, close_orm, DbSession, User, Ads


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
async def jwt_auth_middleware(request: web.Request, handler):
    public_paths = [
        ('/login/', 'POST', False),
        ('/users/', 'POST', False),
        ('/ads/', 'GET', True)
    ]
    current_path = request.path
    current_method = request.method.upper()
    for path, method, allow_subpaths in public_paths:
        if current_method == method:
            if allow_subpaths and current_path.startswith(path):
                return await handler(request)
            elif not allow_subpaths and current_path == path:
                return await handler(request)

    auth_header = request.headers.get('Authorization')

    if not auth_header:
        raise web.HTTPUnauthorized(text=json.dumps({'error': 'Authorization header is missing'}), content_type='application/json')

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        raise web.HTTPUnauthorized(text=json.dumps({'error': 'Invalid Authorization header format. Expected: Bearer <token>'}), content_type='application/json')

    token = parts[1]
    payload = verify_jwt_token(token)
    if not payload:
        raise web.HTTPUnauthorized(text=json.dumps({'error': 'Invalid or expired token'}), content_type='application/json')

    payload = verify_jwt_token(token)
    user_id = payload.get('user_id') or payload.get('id') or payload.get('sub')
    if not user_id:
        raise web.HTTPUnauthorized(text=json.dumps({'error': 'Token does not contain user identifier'}), content_type='application/json')

    async with DbSession() as session:
        user = await session.get(User, user_id)
        if not user:
            raise web.HTTPUnauthorized(text=json.dumps({'error': 'User not found'}), content_type='application/json')

        if hasattr(user, 'is_active') and not user.is_active:
            raise web.HTTPUnauthorized(text=json.dumps({'error': 'User account is deactivated'}), content_type='application/json')
        request.user = user
        request.jwt_payload = payload

    return await handler(request)


app = web.Application()
app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)
app.middlewares.append(jwt_auth_middleware)


class JWTAuthView(web.View):
    async def post(self):
        try:
            data = await self.request.json()
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                raise get_error("Email and password required", web.HTTPBadRequest)

            session = self.request.session
            stmt = select(User).where(User.email == email)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()
            if not user or not await user.check_password(password):
                raise web.HTTPUnauthorized(text=json.dumps({'error': 'Invalid credentials'}), content_type='application/json')

            token = create_jwt_token({
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            })
            response_data = {
                'msg': 'Login successful',
                'token': token,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                }
            }
            response = web.json_response(response_data)
            return response

        except json.JSONDecodeError:
            raise web.HTTPBadRequest(text=json.dumps({'error': 'Invalid JSON'}), content_type='application/json')

        except Exception as e:
            return web.HTTPInternalServerError(text=json.dumps({'error': f'Server error: {str(e)}'}), content_type='application/json')


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

        if 'last_name' or 'first_name' not in user_json:
            raise get_error('name is required', web.HTTPBadRequest)

        if 'email' not in user_json:
            raise get_error('email is required', web.HTTPBadRequest)

        user = User(
            first_name=user_json["first_name"],
            last_name=user_json["last_name"],
            email=user_json["email"],
        )
        await user.set_password(user_json["password"])
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


class AdsListView(web.View):
    @property
    def session(self) -> AsyncSession:
        return self.request.session

    async def get(self):
        query = self.request.query
        stmt = select(Ads).options(selectinload(Ads.user))
        result = await self.session.execute(stmt)
        ads_list = result.scalars().all()
        ads_data = [ads.to_dict() for ads in ads_list]
        return web.json_response({
            'ads': ads_data,
            'count': len(ads_data)
        })

app.add_routes(
    [
        web.get(r'/users/{user_id:\d+}', UserView),
        web.delete(r'/users/{user_id:\d+}', UserView),
        web.post(r'/users/', UserView),
        web.post('/login/', JWTAuthView),
        web.get(r'/ads/{ads_id:\d+}', AdsView),
        web.get(r'/ads/', AdsListView),
        web.post(r'/all_ads/', AdsView),
        web.patch(r'/ads/{ads_id:\d+}', AdsView),
        web.delete(r'/ads/{ads_id:\d+}', AdsView),
    ]
)
web.run_app(app)