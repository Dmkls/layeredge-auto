import uuid
import base64
import secrets
import json
from curl_cffi import requests
from fake_useragent import UserAgent
from utils.log_utils import logger

ua_faker = UserAgent()


class BaseAsyncSession(requests.AsyncSession):
    def __init__(
            self,
            proxy: str = None,
            user_agent: str = ua_faker.random,
            *,
            impersonate: requests.BrowserType = requests.BrowserType.chrome124,
            **session_kwargs,
    ):
        proxies = {"http": proxy, "https": proxy}
        headers = session_kwargs.pop("headers", {})
        headers["user-agent"] = user_agent
        super().__init__(
            proxies=proxies,
            headers=headers,
            impersonate=impersonate,
            **session_kwargs,
        )

    @property
    def user_agent(self) -> str:
        return self.headers["user-agent"]


class TwitterClient:

    def __init__(self, auth_token: str, session: BaseAsyncSession, version: str, platform: str):
        self.auth_token = auth_token
        self.version = version
        self.platform = platform
        self.async_session = session
        self.ct0 = ""
        self.username = ""
        self.account_status = ""
        self.cookies = {
            'auth_token': self.auth_token
        }

    async def login(self):
        """ Проверяет валидность токена и получает `ct0` """
        data = {
            'debug': 'true',
            'log': '[{"_category_":"client_event","format_version":2,"triggered_on":1736641509177,"event_info":"String"}]',
        }

        response = await self.async_session.post(
            'https://x.com/i/api/1.1/jot/client_event.json',
            headers=self.base_headers(),
            cookies=self.cookies,
            data=data
        )

        if response.status_code == 200:
            self.ct0 = self.async_session.cookies.get('ct0', '')
            self.cookies['ct0'] = self.ct0
            self.account_status = 'OK'
            return True, 'OK'

        if "Could not authenticate you" in response.text:
            self.account_status = "BAD TOKEN"
            return False, 'Плохой твиттер токен!'

        self.account_status = 'UNKNOWN'
        return False, f'Ошибка авторизации: {response.text}'

    def base_headers(self):
        """ Базовые заголовки для всех запросов """
        return {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
            'content-type': 'application/json',
            'referer': 'https://x.com/',
            'sec-ch-ua': f'"Google Chrome";v="{self.version}", "Chromium";v="{self.version}", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.platform}"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': self.async_session.user_agent,
            'x-client-transaction-id': self.generate_client_transaction_id(),
            'x-client-uuid': self.generate_client_uuid(),
            'x-csrf-token': self.ct0,
            'x-twitter-active-user': 'yes',
            'x-twitter-auth-type': 'OAuth2Session',
            'x-twitter-client-language': 'en',
        }

    async def start_oauth2(self, url, params):
        """
        Начинает OAuth2 процесс авторизации для Twitter
        """
        cookies = {
            "auth_token": self.auth_token,
            "ct0": self.ct0,
        }

        headers = self.base_headers()
        headers.update({
            "referer": url,
            "x-csrf-token": self.ct0,
            "x-client-transaction-id": self.generate_client_transaction_id(),
        })

        logger.debug(f"🔹 Start OAuth2 Headers: {headers}")  # Для дебага

        response = await self.async_session.get(
            "https://twitter.com/i/api/2/oauth2/authorize",
            params=params,
            headers=headers,
            cookies=cookies
        )

        if response.status_code == 200:
            data = response.json()
            auth_code = data.get("auth_code")
            if auth_code:
                return True, auth_code

        return False, f"❌ Ошибка `start_oauth2`: {response.status_code} - {response.text}"


    async def confirm_oauth2(self, url, auth_code):
        """
        Подтверждает OAuth2 авторизацию
        """
        cookies = {
            "auth_token": self.auth_token,
            "ct0": self.ct0,
        }

        headers = self.base_headers()
        headers.update({
            "referer": url,
            "x-csrf-token": self.ct0,
            "x-client-transaction-id": self.generate_client_transaction_id(),
            "content-type": "application/json"
        })

        data = {
            "approval": "true",
            "code": auth_code
        }

        logger.debug(f"🔹 Confirm OAuth2 Headers: {headers}")  # Для дебага

        response = await self.async_session.post(
            "https://twitter.com/i/api/2/oauth2/authorize",
            headers=headers,
            cookies=cookies,
            json=data
        )

        if response.status_code == 200:
            data = response.json()
            redirect_uri = data.get("redirect_uri")
            if redirect_uri:
                return True, redirect_uri

        return False, f"❌ Ошибка `confirm_oauth2`: {response.status_code} - {response.text}"


    async def get_twitter_id(self, oauth_url):
        """
        Получает `twitterId` из Twitter API после OAuth-авторизации.
        """
        url = "https://twitter.com/i/api/2/notifications/all.json"
        params = {
            "include_profile_interstitial_type": "1",
            "include_blocking": "1",
            "include_blocked_by": "1",
            "include_followed_by": "1",
            "include_want_retweets": "1",
            "include_mute_edge": "1",
            "include_can_dm": "1",
            "include_can_media_tag": "1",
            "include_ext_is_blue_verified": "1",
            "include_ext_verified_type": "1",
            "include_ext_profile_image_shape": "1",
            "skip_status": "1",
            "cards_platform": "Web-12",
            "include_cards": "1",
            "include_ext_alt_text": "true",
            "include_ext_limited_action_results": "true",
            "include_quote_count": "true",
            "include_reply_count": "1",
            "tweet_mode": "extended",
            "include_ext_views": "true",
            "include_entities": "true",
            "include_user_entities": "true",
            "include_ext_media_color": "true",
            "include_ext_media_availability": "true",
            "include_ext_sensitive_media_warning": "true",
            "include_ext_trusted_friends_metadata": "true",
            "send_error_codes": "true",
            "simple_quoted_tweet": "true",
            "count": "20",
            "requestContext": "launch",
            "ext": "mediaStats,highlightedLabel,parodyCommentaryFanLabel,voiceInfo,birdwatchPivot,superFollowMetadata,unmentionInfo,editControl,article"
        }

        headers = self.base_headers()
        headers.update({
            "referer": oauth_url,  
            "x-csrf-token": self.ct0,
            "Cookie": f"auth_token={self.auth_token}; ct0={self.ct0};"
        })

        try:
            response = await self.async_session.get(url, headers=headers, params=params)

            logger.debug(f"🔹 [Twitter API] Статус-код: {response.status_code}")
            response_text = response.text
            logger.debug(f"🔹 [Twitter API] Ответ сервера: {response_text}")

            if response.status_code != 200:
                logger.error(f"❌ Ошибка: API вернул статус {response.status_code}")
                return None

            data = response.json()

            users_data = data.get("globalObjects", {}).get("users", {})
            
            for user_id, user_info in users_data.items():
                if "screen_name" in user_info:
                    twitter_id = user_info["id_str"]
                    logger.debug(f"✅ Найден twitterId: {twitter_id}")
                    return twitter_id

            logger.error("❌ Twitter ID не найден в ответе API")
            return None  

        except Exception as e:
            logger.error(f"❌ Ошибка при запросе Twitter API: {str(e)}")
            return None  


    @staticmethod
    def generate_client_transaction_id():
        """ Генерирует уникальный идентификатор транзакции """
        random_bytes = secrets.token_bytes(70)
        return base64.b64encode(random_bytes).decode('ascii').rstrip('=')

    @staticmethod
    def generate_client_uuid():
        """ Генерирует UUID клиента """
        return str(uuid.uuid4())
