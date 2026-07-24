import json
import requests
import re
import time
import logging
import datetime
import os
import base64
import hashlib
from hashlib import md5
from uuid import uuid1
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
import numpy as np
import cv2

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ==================== 加密与辅助工具函数 ====================

def AES_Encrypt(data):
    key = b"u2oh6Vu^HWe4_AES"
    iv = b"u2oh6Vu^HWe4_AES"
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted_data).decode("utf-8")


def resort(submit_info):
    return {key: submit_info[key] for key in sorted(submit_info.keys())}


def enc(submit_info):
    add = lambda x, y: x + y
    processed_info = resort(submit_info)
    needed = [
        add(add("[", key), "=" + value) + "]" for key, value in processed_info.items()
    ]
    pattern = "%sd`~7^/>N4!Q#){''"
    needed.append(add("[", pattern) + "]")
    seq = "".join(needed)
    return md5(seq.encode("utf-8")).hexdigest()


def generate_captcha_key(timestamp: int):
    captcha_key = md5((str(timestamp) + str(uuid1())).encode("utf-8")).hexdigest()
    encoded_timestamp = (
        md5(
            (
                str(timestamp)
                + "42sxgHoTPTKbt0uZxPJ7ssOvtXr3ZgZ1"
                + "slide"
                + captcha_key
            ).encode("utf-8")
        ).hexdigest()
        + ":"
        + str(int(timestamp) + 0x493E0)
    )
    return [captcha_key, encoded_timestamp]


def sort_dict_by_keys(dictionary):
    sorted_keys = sorted(dictionary.keys())
    return {key: dictionary[key] for key in sorted_keys}


def verify_param(params, algorithm_value):
    sorted_params = sort_dict_by_keys(params)
    hash_list = [f"[{key}={str(value)}]" for key, value in sorted_params.items()]
    hash_list.append(f"[{algorithm_value}]")
    hash_string = "".join(hash_list)
    return hashlib.md5(hash_string.encode("utf-8")).hexdigest()


def get_user_credentials(action=False):
    usernames = os.environ.get("USERNAME", "")
    passwords = os.environ.get("PASSWORD", "")
    return usernames, passwords


def get_date(day_offset: int = 0):
    today = datetime.datetime.now().date()
    offset_day = today + datetime.timedelta(days=day_offset)
    return offset_day.strftime("%Y-%m-%d")


# ==================== 核心抢座类 ====================

class reserve:
    def __init__(
        self,
        sleep_time=0.2,
        max_attempt=50,
        enable_slider=False,
        reserve_next_day=False,
    ):
        self.login_page = (
            "https://passport2.chaoxing.com/mlogin?loginType=1&newversion=true&fid="
        )
        self.url = (
            "https://office.chaoxing.com/front/third/apps/seat/code?id={}&seatNum={}"
        )
        self.submit_url = "https://office.chaoxing.com/data/apps/seat/submit"
        self.seat_url = "https://office.chaoxing.com/data/apps/seat/getusedtimes"
        self.login_url = "https://passport2.chaoxing.com/fanyalogin"
        self.token = ""
        self.success_times = 0
        self.fail_dict = []
        self.submit_msg = []
        self.requests = requests.session()
        self.token_pattern = re.compile("token = '(.*?)'")
        
        # 预加载缓存变量（用于 19:59:55 / 19:59:59 预热）
        self.pre_captcha = ""
        self.pre_token = ""
        self.pre_value = ""

        self.headers = {
            "Referer": "https://office.chaoxing.com/",
            "Host": "captcha.chaoxing.com",
            "Pragma": "no-cache",
            "Sec-Ch-Ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        }
        self.login_headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "accept-encoding": "gzip, deflate, br, zstd",
            "cache-control": "no-cache",
            "Connection": "keep-alive",
            "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.3 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1 wechatdevtools/1.05.2109131 MicroMessenger/8.0.5 Language/zh_CN webview/16364215743155638",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Host": "passport2.chaoxing.com",
        }

        self.sleep_time = sleep_time
        self.max_attempt = max_attempt
        self.enable_slider = enable_slider
        self.reserve_next_day = reserve_next_day
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    def _get_page_token(self, url, require_value=False):
        response = self.requests.get(url=url, verify=False)
        html = response.content.decode("utf-8")
        matches = re.findall(r'id="submit_enc"\s+value="(.*?)"', html)
        value_matches = None
        if require_value:
            value_matches = re.findall(r'value="(.*?)"', html)
            if not matches:
                logging.error(f"Failed to get token from {url}")
                return "", ""
            if not value_matches:
                logging.error(f"Failed to get submit value from {url}")
                return matches[0], ""
        return matches[0] if matches else "", value_matches[0] if value_matches else ""

    def get_login_status(self):
        self.requests.headers = self.login_headers
        self.requests.get(url=self.login_page, verify=False)

    def login(self, username, password):
        username_enc = AES_Encrypt(username)
        password_enc = AES_Encrypt(password)
        parm = {
            "fid": -1,
            "uname": username_enc,
            "password": password_enc,
            "refer": "http%3A%2F%2Foffice.chaoxing.com%2Ffront%2Fthird%2Fapps%2Fseat%2Fcode%3Fid%3D4219%26seatNum%3D380",
            "t": True,
        }
        jsons = self.requests.post(url=self.login_url, params=parm, verify=False)
        obj = jsons.json()
        if obj.get("status"):
            logging.info(f"User {username} login successfully")
            return (True, "")
        else:
            logging.info(f"User {username} login failed. Msg: {obj.get('msg2')}")
            return (False, obj.get("msg2", ""))

    def roomid(self, encode):
        url = f"https://office.chaoxing.com/data/apps/seat/room/list?cpage=1&pageSize=100&firstLevelName=&secondLevelName=&thirdLevelName=&deptIdEnc={encode}"
        json_data = self.requests.get(url=url).content.decode("utf-8")
        ori_data = json.loads(json_data)
        for i in ori_data["data"]["seatRoomList"]:
            info = f'{i["firstLevelName"]}-{i["secondLevelName"]}-{i["thirdLevelName"]} id为：{i["id"]}'
            print(info)

    # ==================== 预热（Pre-fetch）方法 ====================

    def pre_fetch_captcha(self):
        """19:59:55 调用的滑块预解算"""
        if not self.enable_slider:
            return
        try:
            logging.info("⏱️ [19:59:55 预热] 开始预解算滑块验证码...")
            self.pre_captcha = self.resolve_captcha()
            logging.info(f"✅ [19:59:55 预热] 滑块预解算成功 Token: {self.pre_captcha}")
        except Exception as e:
            logging.error(f"❌ [19:59:55 预热] 滑块预解算失败: {e}")
            self.pre_captcha = ""

    def pre_fetch_page_token(self, roomid, seat):
        """19:59:59 调用的页面 Token 预获取"""
        try:
            logging.info("⏱️ [19:59:59 预热] 开始提前拉取页面 Token...")
            token, value = self._get_page_token(
                self.url.format(roomid, seat), require_value=True
            )
            self.pre_token = token
            self.pre_value = value
            logging.info(f"✅ [19:59:59 预热] 页面 Token 预拉取成功: {token}")
        except Exception as e:
            logging.error(f"❌ [19:59:59 预热] 页面 Token 预拉取失败: {e}")
            self.pre_token = ""
            self.pre_value = ""

    # ==================== 验证码算法模块 ====================

    def resolve_captcha(self):
        captcha_token, bg, tp = self.get_slide_captcha_data()
        x = self.x_distance(bg, tp)

        params = {
            "callback": "jQuery33109180509737430778_1716381333117",
            "captchaId": "42sxgHoTPTKbt0uZxPJ7ssOvtXr3ZgZ1",
            "type": "slide",
            "token": captcha_token,
            "textClickArr": json.dumps([{"x": x}]),
            "coordinate": json.dumps([]),
            "runEnv": "10",
            "version": "1.1.18",
            "_": int(time.time() * 1000),
        }
        response = self.requests.get(
            "https://captcha.chaoxing.com/captcha/check/verification/result",
            params=params,
            headers=self.headers,
        )
        text = response.text.replace(
            "jQuery33109180509737430778_1716381333117(", ""
        ).replace(")", "")
        data = json.loads(text)
        try:
            validate_val = json.loads(data["extraData"])["validate"]
            return validate_val
        except KeyError:
            logging.info("Can't load validate value. Maybe server return mistake.")
            return ""

    def get_slide_captcha_data(self):
        url = "https://captcha.chaoxing.com/captcha/get/verification/image"
        timestamp = int(time.time() * 1000)
        capture_key, token = generate_captcha_key(timestamp)
        referer = "https://office.chaoxing.com/front/third/apps/seat/code?id=3993&seatNum=0199"
        params = {
            "callback": "jQuery33107685004390294206_1716461324846",
            "captchaId": "42sxgHoTPTKbt0uZxPJ7ssOvtXr3ZgZ1",
            "type": "slide",
            "version": "1.1.18",
            "captchaKey": capture_key,
            "token": token,
            "referer": referer,
            "_": timestamp,
            "d": "a",
            "b": "a",
        }
        response = self.requests.get(url=url, params=params, headers=self.headers)
        content = response.text

        data = content.replace(
            "jQuery33107685004390294206_1716461324846(", ")"
        ).replace(")", "")
        data = json.loads(data)
        captcha_token = data["token"]
        bg = data["imageVerificationVo"]["shadeImage"]
        tp = data["imageVerificationVo"]["cutoutImage"]
        return captcha_token, bg, tp

    def x_distance(self, bg, tp):
        """线程池双路并发下载 + 单通道匹配算法"""
        def cut_slide(slide):
            slider_array = np.frombuffer(slide, np.uint8)
            slider_image = cv2.imdecode(slider_array, cv2.IMREAD_UNCHANGED)
            slider_part = slider_image[:, :, :3]
            mask = slider_image[:, :, 3]
            mask[mask != 0] = 255
            x, y, w, h = cv2.boundingRect(mask)
            return slider_part[y : y + h, x : x + w]

        c_captcha_headers = {
            "Referer": "https://office.chaoxing.com/",
            "Host": "captcha-b.chaoxing.com",
            "Pragma": "no-cache",
            "Sec-Ch-Ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        }

        # 线程池并发下载两张图片
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_bg = executor.submit(self.requests.get, bg, headers=c_captcha_headers)
            future_tp = executor.submit(self.requests.get, tp, headers=c_captcha_headers)
            bgc = future_bg.result()
            tpc = future_tp.result()

        bg_img = cv2.imdecode(np.frombuffer(bgc.content, np.uint8), cv2.IMREAD_COLOR)
        tp_img = cut_slide(tpc.content)

        bg_edge = cv2.Canny(bg_img, 100, 200)
        tp_edge = cv2.Canny(tp_img, 100, 200)

        # 单通道图像模板匹配
        res = cv2.matchTemplate(bg_edge, tp_edge, cv2.TM_CCOEFF_NORMED)
        _, _, _, max_loc = cv2.minMaxLoc(res)
        return max_loc[0]

    # ==================== 提交逻辑 ====================

    def submit(self, times, roomid, seatid, action):
        for seat in seatid:
            suc = False
            # 修正了语法 Bug：用 not suc 代替 ~suc
            while not suc and self.max_attempt > 0:
                # 1. 优先使用 19:59:59 预拉取的 Token
                if self.pre_token and self.pre_value:
                    token = self.pre_token
                    value = self.pre_value
                    self.pre_token, self.pre_value = "", ""  # 消费后立即清空
                    logging.info(f"⚡ [极速发包] 使用预存 Page Token: {token}")
                else:
                    token, value = self._get_page_token(
                        self.url.format(roomid, seat), require_value=True
                    )
                    logging.info(f"Get token: {token}")

                # 2. 优先使用 19:59:55 预解算出来的 Captcha
                if self.enable_slider:
                    if self.pre_captcha:
                        captcha = self.pre_captcha
                        self.pre_captcha = ""  # 消费后立即清空
                        logging.info(f"⚡ [极速发包] 使用预存 Captcha Token: {captcha}")
                    else:
                        captcha = self.resolve_captcha()
                else:
                    captcha = ""

                suc = self.get_submit(
                    self.submit_url,
                    times=times,
                    token=token,
                    roomid=roomid,
                    seatid=seat,
                    captcha=captcha,
                    action=action,
                    value=value,
                )
                if suc:
                    return suc
                time.sleep(self.sleep_time)
                self.max_attempt -= 1
        return suc

    def get_submit(
        self, url, times, token, roomid, seatid, captcha="", action=False, value=""
    ):
        delta_day = 1 if self.reserve_next_day else 0
        day = datetime.date.today() + datetime.timedelta(days=0 + delta_day)
        if action:
            day = datetime.date.today() + datetime.timedelta(days=1 + delta_day)
            
        parm = {
            "roomId": roomid,
            "startTime": times[0],
            "endTime": times[1],
            "day": str(day),
            "seatNum": seatid,
            "captcha": captcha,
            "token": token,
            "type": "1",
            "verifyData": "1",
        }
        parm["enc"] = verify_param(parm, value)
        
        logging.info(f"submit parameter {parm}")
        html = self.requests.post(url=url, params=parm, verify=True).content.decode("utf-8")
        res_json = json.loads(html)
        self.submit_msg.append(f"{times[0]}~{times[1]}: {res_json}")
        logging.info(res_json)
        return res_json.get("success", False)
