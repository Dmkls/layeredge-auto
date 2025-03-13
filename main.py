import asyncio

from utils.Console import Console
from configs import config
from core import register
from core import farm
from core import db
import tasks

async def main():
    Console().build()
    await db.create_database()
    task_list = []

    if config.REGISTER_MODE:
        task_list.append(asyncio.create_task(register.start()))

    if config.FARM_MODE:
        task_list.append(asyncio.create_task(farm.start()))

    if config.TASKS_MODE:
        task_list.append(asyncio.create_task(tasks.start()))

    if task_list:
        await asyncio.gather(*task_list)

asyncio.run(main())
