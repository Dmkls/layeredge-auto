import asyncio
from urllib.parse import quote, parse_qs, urlparse
import time
from random import choice
from datetime import datetime, timezone
import re
import json

import aiohttp
from aiohttp import ClientHttpProxyError, ClientResponseError
from eth_account.messages import encode_defunct
from core.twitter_client import BaseAsyncSession, TwitterClient
from curl_cffi.requests.exceptions import SSLError, CurlError

from core.account import Account
from utils.file_utils import (
    write_success_account, write_failed_account, write_success_tasks, 
    write_failed_tasks, write_success_twitter, write_failed_twitter,
    remove_twitter_token
)
from utils.file_utils import read_proxies, read_proofs
from configs.config import SSL
from configs import config
from utils.log_utils import logger
from fake_useragent import UserAgent
from core import db


base_headers = {
    'Accept': "application/json, text/plain, */*",
    'Origin': "https://dashboard.layeredge.io",
}

ua = UserAgent(os=["Windows", "Linux", "Ubuntu", "Mac OS X"])
proxies = read_proxies()
proofs = read_proofs()

BAD_PROXIES = []


async def make_request(
method: str,
url: str,
proxy: str,
user_agent: str,
payload: dict = None,
wallet_address: str = "",
retries = 10,
timeout: int = 10
):
    headers = base_headers.copy()
    headers['User-Agent'] = user_agent

    method = method.upper()
    if method == 'POST':
        headers['Content-Type'] = 'application/json'

    for _ in range(retries):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(method, url, json=payload, headers=headers, proxy=proxy, timeout=timeout, ssl=SSL) as response:
                    response_json = await response.json()
                    status = response.status
                    response.raise_for_status()
                    return status, response_json
            except ClientHttpProxyError:
                logger.error(f"{wallet_address} | Bad proxy: {proxy}")
                if retries % 2 == 1:
                    proxy = choice(proxies[int(len(proxies)/1.5):])
                    logger.error(f"{wallet_address} | Changed proxy: {proxy}")
            except ClientResponseError:
                try:
                    return status, response_json
                except:
                    logger.error(f"{wallet_address} | request failed, attempt {_ + 1}/{retries}")
            except TimeoutError:
                logger.error(f"{wallet_address} | TimeoutError, attempt {_+1}/{retries}")
            except Exception as e:
                logger.error(f"{wallet_address} | Unexpected error: {e}, attempt {_+1}/{retries}")
        await asyncio.sleep(3, 10)
    return 400, {}


async def register_wallet(
private_key: str,
wallet_address: str,
proxy: str,
ref_code: str
) -> bool:
    register_data = {
        'walletAddress': wallet_address
    }

    user_agent = ua.random
    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/referral/register-wallet/{ref_code}",
        proxy,
        user_agent,
        register_data,
        wallet_address,
        retries=20
    )

    if response_status < 300:
        try:
            write_success_account(private_key)
            await db.add_account(wallet_address, user_agent)
            logger.success(f"{wallet_address} | Successfully register account")
        except:
            logger.info(f"{wallet_address} | Wallet already registered")
            return True
        return True
    else:
        write_failed_account(private_key)
        if 'message' in response_json:
            if response_json['message'] == "wallet address already registered":
                logger.success(f"{wallet_address} | Wallet already registered, starting farm..")
                return True
            elif response_json['message'] == "invalid invite code":
                logger.error(f"{wallet_address} | Invalid invite code: {ref_code}")
        else:
            logger.error(f"{wallet_address} | Unexpected error: {response_json}")
        return False

async def get_node_status(
account: Account,
proxy: str
):
    url = f"https://referralapi.layeredge.io/api/light-node/node-status/{account.wallet_address}"

    response_status, response_json = await make_request(
        'GET',
        url,
        proxy,
        account.ua,
        wallet_address=account.wallet_address
    )

    if response_status < 300:
        return response_json['data']['startTimestamp']

async def get_points(
account: Account,
proxy: str
) -> int | None:
    url = f"https://referralapi.layeredge.io/api/referral/wallet-details/{account.wallet_address}"

    response_status, response_json = await make_request(
        'GET',
        url,
        proxy,
        account.ua,
        wallet_address=account.wallet_address
    )

    if response_status < 300:
        return response_json['data']["nodePoints"]
    else:
        return None

async def get_ref_code(
account: Account,
proxy: str
) -> str | None:
    url = f"https://referralapi.layeredge.io/api/referral/wallet-details/{account.wallet_address}"

    response_status, response_json = await make_request(
        'GET',
        url,
        proxy,
        account.ua,
        wallet_address=account.wallet_address
    )

    if response_status < 300:
        return response_json['data']["referralCode"]
    else:
        return None

async def start_node(account: Account, proxy):
    timestamp = int(time.time() * 1000)
    message = f"Node activation request for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()
    data_start = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
    }

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/light-node/node-action/{account.wallet_address}/start",
        proxy,
        account.ua,
        data_start,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully start node")
        return True
    else:
        if response_status == 405:
            if 'message' in response_json:
                if 'multiple light node' in response_json['message']:
                    logger.warning(f"{account.wallet_address} | Node is already working")
            else:
                logger.error(f"{account.wallet_address} | Error when starting node")
        return False

async def stop_node(account: Account, proxy):
    timestamp = int(time.time() * 1000)
    message = f"Node deactivation request for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_stop = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
    }

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/light-node/node-action/{account.wallet_address}/stop",
        proxy,
        account.ua,
        data_stop,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully stop node")
        return True
    else:
        if response_status == 404:
            if 'message' in response_json:
                if 'no node running' in response_json['message']:
                    # node is not running
                    pass
                    # logger.warning(f"{account.wallet_address} | Node is not running")
            else:
                logger.error(f"{account.wallet_address} | Error when stopping node")
        return False

async def check_in(account: Account, proxy):
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my daily node point for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_check_in = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/light-node/claim-node-points",
        proxy,
        account.ua,
        data_check_in,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully claim daily check in")
        return True
    else:
        if response_status == 405:
            if 'message' in response_json:
                if '24 hours' in response_json['message']:
                    logger.warning(f"{account.wallet_address} | Check in is already done")
            else:
                logger.error(f"{account.wallet_address} | Failed to perform check in")
        return False

async def send_prof(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Start submitting proof..")
    now_utc = datetime.now(timezone.utc)
    current_time = now_utc.isoformat(timespec='milliseconds').replace('+00:00', 'Z')

    message = f"I am submitting a proof for LayerEdge at {current_time}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_prof = {
        'address': account.wallet_address,
        'message': message,
        'proof': choice(proofs),
        'signature': f"0x{sign}"
    }

    logger.info(f"{account.wallet_address} | Sending request for proof..")

    response_status, response_json = await make_request(
        'POST',
        f"https://dashboard.layeredge.io/api/send-proof",
        proxy,
        account.ua,
        data_prof,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully submit proof")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 429:
            if 'error' in response_json:
                if 'Proof already submitted' in response_json['error']:
                    logger.warning(f"{account.wallet_address} | Proof is already done")
            else:
                logger.error(f"{account.wallet_address} | Failed to send proof")
                write_failed_tasks(account.wallet_address)
        return False

async def submit_prof(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Start submitting proof task..")
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my proof submission node points for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    logger.info(f"{account.wallet_address} | Sending request for submit proof task..")

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/task/proof-submission",
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully complete task: submit proof")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 409:
            if 'message' in response_json:
                if 'task is already completed' in response_json['message']:
                    logger.warning(f'{account.wallet_address} | Submit proof task is already completed')
            else:
                logger.error(f"{account.wallet_address} | Failed to complete task: submit proof")
                write_failed_tasks(account.wallet_address)
        return False

async def submit_light_node(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Starting light node run task..")
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my light node run task node points for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    logger.info(f"{account.wallet_address} | Sending request for light node run task..")

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/task/node-points",
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully complete task: submit light node")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 409:
            if 'message' in response_json:
                if 'task is already completed' in response_json['message']:
                    logger.warning(f'{account.wallet_address} | Node run task is already completed')
            elif response_json == 405:
                if 'message' in response_json:
                    if 'can not complete' in response_json['message']:
                        logger.error(f'{account.wallet_address} | Can not complete node run task without running light node at 12 hours')
            else:
                logger.error(f"{account.wallet_address} | Failed to complete task: submit light node")
                write_failed_tasks(account.wallet_address)
        return False

async def submit_free_pass(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Starting free pass task..")
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my SBT verification points for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    logger.info(f"{account.wallet_address} | Sending request to verify free SBT holding..")

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/task/nft-verification/1",
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully complete task: verify free pass holding")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 404:
            if 'message' in response_json:
                if 'no nft found' in response_json['message']:
                    logger.error(f'{account.wallet_address} | Free pass holding: no nft found')
            else:
                logger.error(f"{account.wallet_address} | Failed to complete task: verify free pass holding")
                write_failed_tasks(account.wallet_address)
        return False

async def submit_og_pass(account: Account, proxy):
    logger.success(f"{account.wallet_address} | Starting OG pass task..")
    timestamp = int(time.time() * 1000)
    message = f"I am claiming my SBT verification points for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    sign = account.evm_account.sign_message(msg_hash)['signature'].hex()

    data_proof_submit = {
        'sign': f"0x{sign}",
        'timestamp': timestamp,
        'walletAddress': account.wallet_address,
    }

    logger.info(f"{account.wallet_address} | Sending request to verify OG SBT holding..")

    response_status, response_json = await make_request(
        'POST',
        f"https://referralapi.layeredge.io/api/task/nft-verification/2",
        proxy,
        account.ua,
        data_proof_submit,
        account.wallet_address
    )

    if response_status < 400:
        logger.success(f"{account.wallet_address} | Successfully complete task: verify OG pass holding")
        write_success_tasks(account.wallet_address)
        return True
    else:
        if response_status == 404:
            if 'message' in response_json:
                if 'no nft found' in response_json['message']:
                    logger.error(f'{account.wallet_address} | OG pass holding: no nft found')
            else:
                logger.error(f"{account.wallet_address} | Failed to complete task: verify OG pass holding")
                write_failed_tasks(account.wallet_address)
        return False

def sign_connect_twitter(account):
    """
    Формирует сообщение и генерирует подпись для запроса фиксации привязки Twitter.
    Сообщение можно сформировать так:
    
      "I am verifying my Twitter authentication for {walletAddress} at {timestamp}"
    
    Возвращает подпись и timestamp.
    """
    timestamp = int(time.time() * 1000)
    message = f"I am verifying my Twitter authentication for {account.wallet_address} at {timestamp}"
    msg_hash = encode_defunct(text=message)
    signature = account.evm_account.sign_message(msg_hash)['signature'].hex()
    return signature, timestamp

async def request_with_retry(session, method, url, retries=3, delay=5, **kwargs):
    for attempt in range(1, retries + 1):
        try:
            if method.lower() == "post":
                response = await session.post(url, **kwargs)
            elif method.lower() == "get":
                response = await session.get(url, **kwargs)
            else:
                raise ValueError("Unsupported method")
            return response
        except (SSLError, CurlError) as e:
            logger.warning(f"Попытка {attempt}/{retries} для {url} не удалась из-за SSL ошибки: {e}")
            if attempt < retries:
                await asyncio.sleep(delay)
            else:
                logger.error(f"Все {retries} попыток для {url} завершились неудачей из-за SSL ошибок.")
                raise e
        except Exception as e:
            logger.warning(f"Попытка {attempt}/{retries} для {url} не удалась: {e}")
            if attempt < retries:
                await asyncio.sleep(delay)
            else:
                logger.error(f"Все {retries} попыток для {url} завершились неудачей.")
                raise e
    
async def connect_twitter(account, proxy, twitter_data: tuple):
    auth_token, username = twitter_data
    if not proxy.startswith("http://") and not proxy.startswith("https://"):
        proxy = "http://" + proxy

    logger.info(f"{account.wallet_address} | Начинаем подключение Twitter...")

    def extract_browser_info(ua_str: str):
        version_match = re.search(r"Chrome/(\d+)", ua_str)
        version = version_match.group(1) if version_match else "133"
        if "Windows" in ua_str:
            platform = "Windows"
        elif "Mac" in ua_str or "Macintosh" in ua_str:
            platform = "Mac OS"
        elif "Linux" in ua_str:
            platform = "Linux"
        else:
            platform = "Unknown"
        return version, platform

    browser_version, browser_platform = extract_browser_info(account.ua)

    session = BaseAsyncSession(proxy=proxy, user_agent=account.ua)
    client = TwitterClient(auth_token, session, version=browser_version, platform=browser_platform)
    client.username = username

    login_success, login_message = await client.login()
    if not login_success:
        logger.error(f"{account.wallet_address} | Ошибка подключения Twitter: {login_message}")

        if login_message == "Плохой твиттер токен!":
            logger.warning(f"{account.wallet_address} | Удаляем плохой токен: {auth_token}")
            remove_twitter_token(auth_token)
            write_failed_twitter(auth_token)
        
        return False

    logger.success(f"{account.wallet_address} | Токен Twitter подтверждён: {login_message}")

    async with aiohttp.ClientSession() as sess:
        csrf_headers = {
            'accept': '*/*',
            'accept-language': 'ru-RU,ru;q=0.6',
            'content-type': 'application/json',
            'priority': 'u=1, i',
            'referer': 'https://dashboard.layeredge.io/tasks',
            'sec-ch-ua': f'"Not(A:Brand";v="99", "Brave";v="{browser_version}", "Chromium";v="{browser_version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{browser_platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': account.ua,
        }
        async with sess.get("https://dashboard.layeredge.io/api/auth/csrf", headers=csrf_headers, proxy=proxy, ssl=False) as resp:
            if resp.status < 300:
                csrf_response = await resp.json()
                csrf_token = csrf_response.get("csrfToken")
                if not csrf_token:
                    logger.error(f"{account.wallet_address} | Не удалось получить csrf token")
                    # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
                    return False
            else:
                error_text = await resp.text()
                logger.error(f"{account.wallet_address} | Ошибка получения csrf token: {resp.status} - {error_text}")
                # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
                return False

        logger.debug(f"{account.wallet_address} | Получен csrf token: {csrf_token}")

        callback_url = "https://dashboard.layeredge.io/tasks"
        payload = f"callbackUrl={quote(callback_url)}&csrfToken={csrf_token}&json=true"
        signin_headers = {
            'accept': '*/*',
            'accept-language': 'ru-RU,ru;q=0.6',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://dashboard.layeredge.io',
            'priority': 'u=1, i',
            'referer': 'https://dashboard.layeredge.io/tasks',
            'sec-ch-ua': f'"Not(A:Brand";v="99", "Brave";v="{browser_version}", "Chromium";v="{browser_version}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{browser_platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': account.ua,
        }
        async with sess.post("https://dashboard.layeredge.io/api/auth/signin/twitter",
                             data=payload,
                             headers=signin_headers,
                             proxy=proxy) as signin_resp:
            if signin_resp.status < 300:
                signin_json = await signin_resp.json()
                oauth_url = signin_json.get("url")
                if not oauth_url:
                    logger.error(f"{account.wallet_address} | Не получена OAuth-ссылка: {signin_json}")
                    # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
                    return False
            else:
                error_text = await signin_resp.text()
                logger.error(f"{account.wallet_address} | Ошибка signin Twitter: {error_text}")
                # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
                return False

    logger.debug(f"{account.wallet_address} | Получена OAuth-ссылка: {oauth_url}")

    parsed = urlparse(oauth_url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    oauth_start_success, auth_code_or_msg = await client.start_oauth2(oauth_url, params)
    if not oauth_start_success:
        logger.error(f"{account.wallet_address} | Ошибка start_oauth2: {auth_code_or_msg}")
        # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
        return False
    logger.debug(f"{account.wallet_address} | start_oauth2 выполнен, auth_code: {auth_code_or_msg}")

    oauth_confirm_success, redirect_uri_or_msg = await client.confirm_oauth2(oauth_url, auth_code_or_msg)
    if not oauth_confirm_success:
        logger.error(f"{account.wallet_address} | Ошибка confirm_oauth2: {redirect_uri_or_msg}")
        # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
        return False
    logger.success(f"{account.wallet_address} | Привязка Twitter выполнена успешно, начинаю верификацию")
    logger.debug(f"{account.wallet_address} | Привязка Twitter выполнена успешно, redirect: {redirect_uri_or_msg}")

    try:
        twitter_id = await client.get_twitter_id(oauth_url)
        logger.debug(f"{account.wallet_address} | Получен twitterId: {twitter_id}")
    except Exception as e:
        logger.error(f"{account.wallet_address} | Ошибка получения twitterId: {e}")
        # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
        return False

    sign, timestamp = sign_connect_twitter(account)
    connect_payload = {
        "walletAddress": account.wallet_address,
        "sign": f"0x{sign}",
        "timestamp": str(timestamp),
        "twitterId": str(twitter_id)
    }
    connect_headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'ru-RU,ru;q=0.6',
        'content-type': 'application/json',
        'origin': 'https://dashboard.layeredge.io',
        'priority': 'u=1, i',
        'referer': redirect_uri_or_msg,
        'sec-ch-ua': f'"Not(A:Brand";v="99", "Brave";v="{browser_version}", "Chromium";v="{browser_version}"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': f'"{browser_platform}"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'sec-gpc': '1',
        'user-agent': account.ua,
    }

    try:
        connect_resp = await request_with_retry(
            session,
            "post",
            "https://referralapi.layeredge.io/api/task/connect-twitter",
            retries=config.MAX_RETRIES,
            delay=config.RETRY_DELAY,
            headers=connect_headers,
            json=connect_payload,
            proxy=proxy
        )
    except Exception as e:
        logger.error(f"{account.wallet_address} | Ошибка запроса connect-twitter после нескольких попыток: {e}")
        # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
        return False

    logger.debug(f"Отправляемый payload: {json.dumps(connect_payload, indent=4, ensure_ascii=False)}")
    logger.debug(connect_resp)
    if connect_resp.status_code < 300:
        connect_json = connect_resp.json()
        logger.success(f"{account.wallet_address} | Привязка Twitter зафиксирована")
        logger.debug(f"{account.wallet_address} | Привязка Twitter зафиксирована: {connect_json}")
        write_success_twitter(account.wallet_address, account.private_key, auth_token)
    else:
        error_text = connect_resp.text
        logger.error(f"{account.wallet_address} | Ошибка фиксации привязки Twitter: {connect_resp.status_code} - {error_text}")
        # write_failed_twitter(account.wallet_address, account.private_key, auth_token)
        return False

    return True

