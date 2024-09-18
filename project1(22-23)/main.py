from datetime import datetime
from functools import lru_cache
import time
import uvicorn
from json import loads, dumps

from fastapi import Request, Response, Depends
from fastapi.staticfiles import StaticFiles

from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
import hashlib
from enum import Enum


from elasticsearch import AsyncElasticsearch

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.redis import RedisJobStore

from app import create_app
from database import Base, engine
from sqlalchemy.orm import Session
from dependencies import get_db, get_async_db, sio, sio_app  # noqa: F401, get_db and get_async_db for test client

from routers import (
    auth,
    users,
    roles,
    notifications,
    files,
    search,
    page,
    spaces,
    sprints,
    tasks,
    projects,
    chat,
    comments,
    gamification,
    integrations,
    utility,
    simple_task,
    widgets,
    survey,
    share,
)

from settings import Settings, settings

import aioredis
import logging
import sentry_sdk


# sentry_sdk.init(
#     dsn="https://2385b447e2b748cfb6f14fe77b7ae718@o4504995834626048.ingest.sentry.io/4504995835478016",

#     # Set traces_sample_rate to 1.0 to capture 100%
#     # of transactions for performance monitoring.
#     # We recommend adjusting this value in production,
#     traces_sample_rate=0.2,
#     environment=settings.environment,
#     profiles_sample_rate=1.0,
# )

es = AsyncElasticsearch("http://localhost:9200")


app = create_app()
celery = app.celery_app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.middleware("http")
def add_current_user_to_logging(request: Request, call_next):
    # start_time = time.monotonic()
    response = call_next(request)
    # end_time = time.monotonic()

    # duration = (end_time - start_time) * 1000
    ip_address = request.client.host
    auth_header = request.headers.get("Authorization")
    if auth_header is None:
        return response
    auth_header = auth_header.split(" ")[-1]
    if auth_header == "null":
        return response
    from routers.auth import get_user_from_auth_header

    user = get_user_from_auth_header(auth_header)

    logger.info(
        f"[{datetime.now().strftime('%H:%M:%S')}]-{ip_address} {user.username if user else '*'}"
    )

    return response


Base.metadata.create_all(bind=engine)


@lru_cache()
def get_settings():
    return Settings()


app.mount("/ws", sio_app)
app.mount("/static", StaticFiles(directory="./static"), name="static")


@sio.on("connected")
async def custom_connect_event(
    sid,
    data: dict,
    *args,
    **kwargs,
):
    print(f"Connection event:\n{data}\nsid: {sid}\nTime: {int(time.time())}")
    user_id = data["user_id"]
    sio.enter_room(sid, f"notify_user_{user_id}")
    sio.enter_room(sid, "system")
    room_ids: list[str] = list(
        map(
            lambda x: x,
            list(await red.smembers(f"user:{user_id}:rooms")),
        )
    )
    for room in room_ids:
        sio.enter_room(sid, f"chat_room_{room}")
    await red.sadd("online_users", user_id)
    await red.hset(f"user:{user_id}", "sid", sid)
    status = await red.get("system:maintenance")
    await sio.emit("maintenance status", loads(status), to=sid)


@sio.on("disconnected")
async def custom_disconnect_event(sid, data, *args):
    user_id = data["user_id"]
    print(f"Disconnect {user_id}\nsid: {sid}")
    sio.leave_room(sid, "system")
    sio.leave_room(sid, room=f"notify_user_{user_id}")
    room_ids: list[str] = list(
        map(
            lambda x: x,
            list(await red.smembers(f"user:{user_id}:rooms")),
        )
    )
    for room in room_ids:
        sio.leave_room(sid, f"chat_room_{room}")
    await red.srem("online_users", user_id)


@app.on_event("startup")
async def startup_event():
    print(f"Environment: {settings.environment}")
    global dash_storage
    dash_storage = {
        "weather": {
            "weather_link_l": "/static/weather/not-available-l.svg",
            "weather_link_d": "/static/weather/not-available-d.svg",
            "f1_weather_link_l": "/static/weather/not-available-l.svg",
            "f1_weather_link_d": "/static/weather/not-available-d.svg",
            "f2_weather_link_l": "/static/weather/not-available-l.svg",
            "f2_weather_link_d": "/static/weather/not-available-d.svg",
            "f3_weather_link_l": "/static/weather/not-available-l.svg",
            "f3_weather_link_d": "/static/weather/not-available-d.svg",
        },
        "usedesk": {},
        "youtube": {},
        "dtf": {},
        "tiktok": {},
        "vk-bcg": {},
        "sheet": {},
        "gp-project": {"samedi": {}, "sort": {}, "cat": {}, "eco": {}},
        "usedesk_report": {},
        "usedesk_lm_report": {},
        "usedesk_sec_report": {},
        "usedesk_lm_sec_report": {},
        "tg": {},
        "vk-stat": {},
    }
    from services.widgets import get_weather

    try:
        get_weather()
    except Exception as e:
        print(f"Unable to get weather\nError: {e}")
    global red
    red = await aioredis.from_url("redis://10.93.19.182:6379", decode_responses=True)
    red_coded = await aioredis.from_url(
        "redis://10.93.19.182:6379", decode_responses=False
    )
    global scheduler
    try:
        jobstores = {"default": RedisJobStore(db=1, host="10.93.19.182", port="6379")}
        scheduler = AsyncIOScheduler(jobstores=jobstores)
        scheduler.start()
        service_jobs()
        scheduler.print_jobs()
        print("Created Schedule Object")
    except Exception as e:
        print(f"Unable to Create Schedule Object\nError: {e}")
    FastAPICache.init(
        RedisBackend(red_coded), prefix="fastapi-cache", key_builder=api_key_builder
    )
    from routers.notifications import notification_init

    notification_init()
    # await initial_reindex_elastic()


@app.on_event("shutdown")
async def shutdown_event():
    global scheduler
    scheduler.shutdown()
    await red.close()
    await es.close()


app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(files.router, prefix="/api")
app.include_router(search.router, prefix="/api")
app.include_router(comments.router, prefix="/api")
app.include_router(page.router, prefix="/api")
app.include_router(notifications.router, prefix="/api")
app.include_router(spaces.router, prefix="/api")
app.include_router(sprints.router, prefix="/api")
app.include_router(projects.router, prefix="/api")
app.include_router(tasks.router, prefix="/api")
app.include_router(chat.router, prefix="/api")
app.include_router(gamification.router, prefix="/api")
app.include_router(utility.router, prefix="/api")
app.include_router(roles.router, prefix="/api")
app.include_router(widgets.router, prefix="/api")
app.include_router(survey.router, prefix="/api/tools")
app.include_router(share.router, prefix="/api")
app.include_router(simple_task.router, prefix="/api")
app.include_router(integrations.router, prefix="/api")


temp_storage = []


def service_jobs():
    from services.achiever import achieve_working_exp
    from services.hr import hr_user_adaptation
    from services.scheduler import (
        morning_daily_cron_trigger,
        hourly_cron_trigger,
        weekly_analytic_cron_trigger,
        night_daily_cron_trigger,
    )
    from services.widgets import get_weather
    from integrations.appsflyer import get_appsflyer_data
    from services.gamification import achievments_rarity_calculation

    scheduler.add_job(
        achieve_working_exp,
        morning_daily_cron_trigger,
        id="achieve_working_exp",
        replace_existing=True,
    )
    scheduler.add_job(
        hr_user_adaptation,
        morning_daily_cron_trigger,
        id="hr_user_adaptation",
        replace_existing=True,
    )
    scheduler.add_job(
        get_weather, hourly_cron_trigger, id="get_weather_data", replace_existing=True
    )
    scheduler.add_job(
        get_appsflyer_data,
        weekly_analytic_cron_trigger,
        id="get_appsflyer_data",
        replace_existing=True,
    )
    scheduler.add_job(
        achievments_rarity_calculation,
        hourly_cron_trigger,
        id="achievments_rarity_calculation",
        replace_existing=True,
    )


# async def initial_reindex_elastic():
#     db: Session = next(get_db())
#     await es.indices.delete(index="posts", ignore_unavailable=True)
#     await es.indices.delete(index="tasks", ignore_unavailable=True)
#     await es.indices.delete(index="comments", ignore_unavailable=True)
#     posts: list[schemas.PageIn] = db.query(Page).all()
#     for post in posts:
#         id = post.id
#         title = post.title
#         post_text_soup = BeautifulSoup(post.text, "html.parser")
#         post_text = post_text_soup.text
#         post = {
#             "title": title,
#             "text": post_text,
#         }
#         await es.index(index="posts", id=id, body=post)
#     tasks: list[schemas.TaskIn] = db.query(Tasks).all()
#     for task in tasks:
#         await es.index(index='tasks', id=task.id, body={'title': f'Задача: {task.name}', 'text': task.description})
#     comments: list[schemas.CommentIn] = db.query(Comments).all()
#     for comment in comments:
#         await es.index(index='comments', id=comment.id, body={'title': f'Комментарий: {comment.c_author.name}', 'text': BeautifulSoup(comment.text, 'html.parser').text})
#     print('Elastic (re)index done')


def api_key_builder(
    func,
    namespace: str | None = "",
    request: Request | None = None,
    response: Response | None = None,
    args: tuple | None = None,
    kwargs: dict | None = None,
):
    """
    Handle Enum and Session params properly.
    """
    prefix = f"{FastAPICache.get_prefix()}:{namespace}:"

    # Remove session and convert Enum parameters to strings
    arguments = {}
    for key, value in kwargs.items():
        if key != "db":
            arguments[key] = value.value if isinstance(value, Enum) else value

    cache_key = (
        prefix
        + hashlib.md5(
            f"{func.__module__}:{func.__name__}:{args}:{arguments}".encode()
        ).hexdigest()
    )

    return cache_key


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", reload=True, proxy_headers=True, workers=4)
