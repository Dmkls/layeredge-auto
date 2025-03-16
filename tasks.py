import asyncio
from random import randint
from fake_useragent import UserAgent
import sys

from core.reqs import (
    send_prof, submit_prof, submit_light_node,
    submit_free_pass, submit_og_pass, connect_twitter
)
from utils.file_utils import (
    read_proxies, read_wallets_to_complete_tasks, read_twitter_tokens,
    remove_wallet_to_complete_task, remove_twitter_token
)
from utils.private_key_to_wallet import private_key_to_wallet
from utils.file_utils import write_failed_tasks, write_success_tasks
from utils.log_utils import logger
from core.account import Account
from core import db
from configs import config

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

ua_faker = UserAgent()

write_failed_tasks('------------------------------------------------')
write_success_tasks('------------------------------------------------')

async def complete_tasks(private_key: str, proxy: str, twitter_data: tuple, sem: asyncio.Semaphore):
    async with sem:
        ua = await db.get_ua(private_key_to_wallet(private_key))
        if not ua:
            ua = ua_faker.random
            await db.add_account(private_key_to_wallet(private_key), ua)

        account = Account(private_key, ua)
        sleep_time = randint(config.MIN_DELAY_BEFORE_START, config.MAX_DELAY_BEFORE_START)
        logger.success(f"{account.wallet_address} | Start running tasks in {sleep_time} second")
        await asyncio.sleep(sleep_time)

        if config.DO_PROOF:
            await send_prof(account, proxy)
            await asyncio.sleep(randint(20, 30))
        if config.DO_SUBMIT_PROOF_TASK:
            await submit_prof(account, proxy)
            await asyncio.sleep(randint(10, 30))
        if config.DO_LIGHT_NODE_RUN_TASK:
            await submit_light_node(account, proxy)
            await asyncio.sleep(randint(10, 30))
        if config.DO_PLEDGE_PASS_HOLD_TASK:
            await submit_free_pass(account, proxy)
            await asyncio.sleep(randint(10, 30))
        if config.DO_OG_PLEDGE_PASS_HOLD_TASK:
            await submit_og_pass(account, proxy)
            await asyncio.sleep(randint(10, 30))
        
        twitter_success = True
        if config.DO_TWITTER_CONNECT:
            twitter_success = await connect_twitter(account, proxy, twitter_data)
            await asyncio.sleep(randint(10, 30))
        
        if twitter_success:
            remove_wallet_to_complete_task(private_key)
            token = twitter_data[0]
            remove_twitter_token(token)
        
        return

async def start():
    await db.create_database()
    rounds = config.NUMBER_OF_ROUNDS

    for r in range(rounds):
        logger.success(f"Starting round {r+1}")
        wallets = read_wallets_to_complete_tasks()
        proxies = read_proxies()
        twitter_data_list = read_twitter_tokens()

        if not wallets or not twitter_data_list:
            logger.success("Нет данных для обработки. Завершаем работу.")
            break

        tasks = []
        sem = asyncio.Semaphore(config.MAX_CONCURRENT_TASKS)
        for private_key, proxy, twitter_data in zip(wallets, proxies, twitter_data_list):
            task = asyncio.create_task(complete_tasks(private_key, proxy, twitter_data, sem))
            tasks.append(task)
            await asyncio.sleep(0.1)

        if tasks:
            await asyncio.gather(*tasks)
        logger.success(f"Round {r+1} completed.")
        await asyncio.sleep(5)

    logger.success(f"All accounts processed!")

if __name__ == '__main__':
    asyncio.run(start())
