# -*- coding: utf8 -*-
import math
import traceback
from datetime import datetime
import pytz
import uuid

import json
import random
import re
import time
import os

from util.aes_help import encrypt_data, decrypt_data
import util.zepp_helper as zeppHelper
import util.push_util as push_util

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

# 固定 device_id（可选）
# 通过环境变量 DEVICE_ID 或 CONFIG 中的 DEVICE_ID 指定。
# 留空则每次运行生成随机 device_id（会导致华米视为新设备登录，顶掉手机端登录态）
FIXED_DEVICE_ID = os.environ.get("DEVICE_ID", "").strip()

# 获取默认值转int
def get_int_value_default(_config: dict, _key, default):
    _config.setdefault(_key, default)
    return int(_config.get(_key))


# 获取当前时间对应的最大和最小步数
def get_login_fallback() -> bool:
    """Web 身份登录失败时，是否回退到手机身份登录（会顶掉手机端）。"""
    val = os.environ.get("LOGIN_FALLBACK", "").strip().lower()
    if not val:
        try:
            val = str(config.get('LOGIN_FALLBACK', '') or '').strip().lower()
        except Exception:
            val = ""
    return val in ("1", "true", "yes", "on")


def get_login_mode() -> str:
    """登录方式：web（默认，不顶掉手机端） / phone（旧的安卓手机身份）。"""
    val = os.environ.get("LOGIN_MODE", "").strip().lower()
    if not val:
        try:
            val = str(config.get('LOGIN_MODE', '') or '').strip().lower()
        except Exception:
            val = ""
    if val in ("phone", "app", "android"):
        return "phone"
    return "web"


def get_country_code() -> str:
    """国家码，默认 CN。"""
    val = os.environ.get("COUNTRY_CODE", "").strip()
    if not val:
        try:
            val = str(config.get('COUNTRY_CODE', '') or '').strip()
        except Exception:
            val = ""
    return val or "CN"


def get_min_max_by_time(hour=None, minute=None):
    if hour is None:
        hour = time_bj.hour
    if minute is None:
        minute = time_bj.minute
    time_rate = min((hour * 60 + minute) / (22 * 60), 1)
    min_step = get_int_value_default(config, 'MIN_STEP', 18000)
    max_step = get_int_value_default(config, 'MAX_STEP', 25000)
    return int(time_rate * min_step), int(time_rate * max_step)


def get_fixed_step():
    """获取固定步数（测试用）。

    微信运动在多个数据源中取【最高值】，所以若想验证刷的步数是否生效，
    必须写入一个明显大于手机真实步数的值（例如 25000），
    否则会被手机传感器的真实步数盖掉，看起来就像"没生效"。

    优先取环境变量 FIXED_STEP，其次取 CONFIG 的 FIXED_STEP；
    都没设置时返回 None（按时间区间随机）。
    """
    val = os.environ.get("FIXED_STEP", "").strip()
    if not val:
        try:
            val = str(config.get('FIXED_STEP', '') or '').strip()
        except Exception:
            val = ""
    if not val:
        return None
    try:
        n = int(val)
    except ValueError:
        print(f"FIXED_STEP 值无效（{val!r}），忽略，按时间区间随机")
        return None
    if n <= 0:
        print(f"FIXED_STEP 必须为正数（{n}），忽略")
        return None
    return n


# 虚拟ip地址
def fake_ip():
    # 随便找的国内IP段：223.64.0.0 - 223.117.255.255
    return f"{223}.{random.randint(64, 117)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


# 账号脱敏
def desensitize_user_name(user):
    if len(user) <= 8:
        ln = max(math.floor(len(user) / 3), 1)
        return f'{user[:ln]}***{user[-ln:]}'
    return f'{user[:3]}****{user[-4:]}'


# 获取北京时间
def get_beijing_time():
    target_timezone = pytz.timezone('Asia/Shanghai')
    # 获取当前时间
    return datetime.now().astimezone(target_timezone)


# 格式化时间
def format_now():
    return get_beijing_time().strftime("%Y-%m-%d %H:%M:%S")


# 获取时间戳
def get_time():
    current_time = get_beijing_time()
    return "%.0f" % (current_time.timestamp() * 1000)


# 获取登录code
def get_access_token(location):
    code_pattern = re.compile("(?<=access=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]


def get_error_code(location):
    code_pattern = re.compile("(?<=error=).*?(?=&)")
    result = code_pattern.findall(location)
    if result is None or len(result) == 0:
        return None
    return result[0]


class MiMotionRunner:
    def __init__(self, _user, _passwd):
        self.user_id = None
        self.device_id = FIXED_DEVICE_ID if FIXED_DEVICE_ID else str(uuid.uuid4())
        user = str(_user)
        password = str(_passwd)
        self.invalid = False
        self.log_str = ""
        if user == '' or password == '':
            self.error = "用户名或密码填写有误！"
            self.invalid = True
            pass
        self.password = password
        if (user.startswith("+86")) or "@" in user:
            user = user
        else:
            user = "+86" + user
        if user.startswith("+86"):
            self.is_phone = True
        else:
            self.is_phone = False
        self.user = user
        # self.fake_ip_addr = fake_ip()
        # self.log_str += f"创建虚拟ip地址：{self.fake_ip_addr}\n"

    # 登录
    def login(self):
        user_token_info = user_tokens.get(self.user)
        if user_token_info is not None:
            access_token = user_token_info.get("access_token")
            login_token = user_token_info.get("login_token")
            app_token = user_token_info.get("app_token")
            self.device_id = user_token_info.get("device_id")
            self.user_id = user_token_info.get("user_id")
            if self.device_id is None:
                self.device_id = str(uuid.uuid4())
                user_token_info["device_id"] = self.device_id
            ok, msg = zeppHelper.check_app_token(app_token)
            if ok:
                self.log_str += "使用加密保存的app_token\n"
                return app_token
            else:
                self.log_str += f"app_token失效 重新获取 last grant time: {user_token_info.get('app_token_time')}\n"
                # 检查login_token是否可用
                app_token, msg = zeppHelper.grant_app_token(login_token)
                if app_token is None:
                    # login_token 也失效了。先尝试【续期】而不是全新登录——
                    # 续期只延长现有会话，不会创建新会话，因此不会把手机端顶掉。
                    #
                    # 注意：续期要用与当初登录【相同身份】的接口。
                    # 旧存档的 login_token 是手机身份(com.xiaomi.hm.health)登录得到的，
                    # 拿它去 Web 续期接口续期无效；反过来对手机身份续期会续手机端会话，
                    # 方向不对。所以按 login_source 标记分别处理：
                    #   web   → 用 renew_login_token_web()（Web 身份续期）
                    #   phone → 不续期，直接转 Web 全新登录（顺带把身份换成 Web）
                    login_source = user_token_info.get("login_source", "phone")
                    if login_source == "web":
                        self.log_str += "login_token 失效 尝试Web身份续期（不新建会话）\n"
                        new_login_token, renew_msg = zeppHelper.renew_login_token_web(login_token)
                    else:
                        self.log_str += "login_token 失效（旧存档为手机身份），直接转Web身份登录\n"
                        new_login_token, renew_msg = None, "旧token为手机身份，跳过续期"
                    if new_login_token:
                        user_token_info["login_token"] = new_login_token
                        user_token_info["login_token_time"] = get_time()
                        login_token = new_login_token
                        app_token, msg = zeppHelper.grant_app_token(login_token)
                        if app_token:
                            user_token_info["app_token"] = app_token
                            user_token_info["app_token_time"] = get_time()
                            self.log_str += "login_token续期成功，重新获取app_token成功（未新建会话）\n"
                            return app_token
                        self.log_str += f"续期后仍无法获取app_token：{msg}\n"
                    else:
                        self.log_str += f"login_token续期失败/跳过：{renew_msg}\n"
                    # 续期不可行，走【Web 身份】全新登录（不会顶掉手机端）
                    self.log_str += "改为Web身份全新登录（不顶掉手机端登录态）\n"
                    ok_login, new_app_token = self._fresh_login()
                    if ok_login:
                        return new_app_token
                    return None

                else:
                    self.log_str += "重新获取app_token成功\n"
                    user_token_info["app_token"] = app_token
                    user_token_info["app_token_time"] = get_time()
                    return app_token

        # access_token 失效 或者没有保存加密数据
        ok_login, app_token = self._fresh_login()
        if not ok_login:
            return None
        return app_token

    def _fresh_login(self):
        """全新登录。优先用 Web 身份（不顶掉手机端 Zepp Life）。

        返回 (是否成功, app_token 或错误信息)。
        """
        mode = get_login_mode()
        self.log_str += f"全新登录方式: {mode}\n"

        if mode == "web":
            # Web 身份：华米侧视为网页端会话，与手机 App 会话互不干扰
            app_token, login_token, user_id, err = zeppHelper.login_web_tokens(
                self.user, self.password, country_code=get_country_code())
            if app_token:
                info = user_tokens.setdefault(self.user, dict())
                info["app_token"] = app_token
                info["login_token"] = login_token
                info["user_id"] = user_id
                info["app_token_time"] = get_time()
                info["login_token_time"] = get_time()
                # 记录登录身份：后续续期时选用对应身份的接口
                info["login_source"] = "web"
                if info.get("device_id") is None:
                    info["device_id"] = self.device_id
                self.user_id = user_id
                self.log_str += "Web身份登录成功（不影响手机端登录态）\n"
                return True, app_token
            self.log_str += f"Web身份登录失败：{err}\n"
            if not get_login_fallback():
                return False, None
            self.log_str += "回退到手机身份登录（可能顶掉手机端登录态）\n"

        # 原有手机身份流程（兜底）
        access_token, msg = zeppHelper.login_access_token(self.user, self.password)
        if access_token is None:
            self.log_str += "登录获取accessToken失败：%s" % msg
            return False, None
        # print(f"device_id:{self.device_id} isPhone: {self.is_phone}")
        login_token, app_token, user_id, msg = zeppHelper.grant_login_tokens(access_token, self.device_id,
                                                                             self.is_phone)
        if login_token is None:
            self.log_str += f"登录提取的 access_token 无效：{msg}"
            return False, None

        user_token_info = dict()
        user_token_info["access_token"] = access_token
        user_token_info["login_token"] = login_token
        user_token_info["app_token"] = app_token
        user_token_info["user_id"] = user_id
        # 记录登录身份：后续续期时选用对应身份的接口
        user_token_info["login_source"] = "phone"
        # 关键：必须同步赋值给 self.user_id，
        # 否则后续 get_user_device_id 会因 self.user_id 为 None 而被跳过，导致查不到设备
        self.user_id = user_id
        # 记录token获取时间
        user_token_info["access_token_time"] = get_time()
        user_token_info["login_token_time"] = get_time()
        user_token_info["app_token_time"] = get_time()
        if self.device_id is None:
            self.device_id = uuid.uuid4()
        user_token_info["device_id"] = self.device_id
        user_tokens[self.user] = user_token_info
        return True, app_token

    # 主函数
    def login_and_post_step(self, min_step, max_step):
        if self.invalid:
            return "账号或密码配置有误", False
        app_token = self.login()
        if app_token is None:
            return "登陆失败！", False

        fixed = get_fixed_step()
        if fixed is not None:
            step = str(fixed)
            self.log_str += (f"使用固定步数 FIXED_STEP={fixed}（测试用，"
                             f"忽略时间区间 {min_step}~{max_step}）\n")
        else:
            step = str(random.randint(min_step, max_step))
            self.log_str += f"已设置为随机步数范围({min_step}~{max_step}) 随机值:{step}\n"
        
        user_token_info = user_tokens.get(self.user, {})
        bound_device_id = user_token_info.get("bound_device_id")
        if not bound_device_id:
            if not self.user_id:
                # user_id 缺失时无法查询设备，明确提示，避免静默跳过
                self.log_str += "警告：未能获取 user_id，无法查询已绑定设备\n"
            else:
                bound_device_id = zeppHelper.get_user_device_id(app_token, self.user_id)
                if bound_device_id:
                    user_token_info["bound_device_id"] = bound_device_id
                    user_tokens[self.user] = user_token_info
                    self.log_str += f"查找到已绑定设备ID: {bound_device_id}\n"
                else:
                    self.log_str += "警告：未查到已绑定设备ID，请确认 Zepp Life 中已绑定手环或虚拟设备\n"

        ok, msg = zeppHelper.post_fake_brand_data(step, app_token, self.user_id,
                                                   device_id=bound_device_id, cfg=config)
        if ok:
            # 回读云端数据：脚本返回 success 不等于数据已入库，
            # 这里立刻读一次，可以马上区分"数据没写进去"和"写了但微信还没同步"
            # 华米对同一天取最大值，可能读到之前某次运行的更大值
            try:
                zeppHelper.read_back_steps(app_token, self.user_id, device_id=bound_device_id,
                                           expect_step=int(step))
            except Exception as e:
                print(f"云端回读异常（不影响提交结果）: {type(e).__name__} {str(e)[:100]}")
            # 诊断同步链路：账号维度步数 + 第三方接入（微信绑定）状态
            try:
                zeppHelper.diagnose_sync(app_token, self.user_id)
            except Exception as e:
                print(f"同步诊断异常（不影响提交结果）: {type(e).__name__} {str(e)[:100]}")
        return f"修改步数（{step}）[" + msg + "]", ok


def run_single_account(total, idx, user_mi, passwd_mi):
    idx_info = ""
    if idx is not None:
        idx_info = f"[{idx + 1}/{total}]"
    log_str = f"[{format_now()}]\n{idx_info}账号：{desensitize_user_name(user_mi)}\n"
    try:
        runner = MiMotionRunner(user_mi, passwd_mi)
        exec_msg, success = runner.login_and_post_step(min_step, max_step)
        log_str += runner.log_str
        log_str += f'{exec_msg}\n'
        exec_result = {"user": user_mi, "success": success,
                       "msg": exec_msg}
    except:
        log_str += f"执行异常:{traceback.format_exc()}\n"
        log_str += traceback.format_exc()
        exec_result = {"user": user_mi, "success": False,
                       "msg": f"执行异常:{traceback.format_exc()}"}
    print(log_str)
    return exec_result


def execute():
    user_list = users.split('#')
    passwd_list = passwords.split('#')
    exec_results = []
    if len(user_list) == len(passwd_list):
        idx, total = 0, len(user_list)
        if use_concurrent:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                exec_results = executor.map(lambda x: run_single_account(total, x[0], *x[1]),
                                            enumerate(zip(user_list, passwd_list)))
        else:
            for user_mi, passwd_mi in zip(user_list, passwd_list):
                exec_results.append(run_single_account(total, idx, user_mi, passwd_mi))
                idx += 1
                if idx < total:
                    # 每个账号之间间隔一定时间请求一次，避免接口请求过于频繁导致异常
                    time.sleep(sleep_seconds)
        if encrypt_support:
            persist_user_tokens()
        success_count = 0
        push_results = []
        for result in exec_results:
            push_results.append(result)
            if result['success'] is True:
                success_count += 1
        summary = f"\n执行账号总数{total}，成功：{success_count}，失败：{total - success_count}"
        print(summary)
        push_util.push_results(push_results, summary, push_config)
    else:
        print(f"账号数长度[{len(user_list)}]和密码数长度[{len(passwd_list)}]不匹配，跳过执行")
        exit(1)


def prepare_user_tokens() -> dict:
    data_path = r"encrypted_tokens.data"
    if os.path.exists(data_path):
        with open(data_path, 'rb') as f:
            data = f.read()
        try:
            decrypted_data = decrypt_data(data, aes_key, None)
            # 假设原始明文为 UTF-8 编码文本
            return json.loads(decrypted_data.decode('utf-8', errors='strict'))
        except:
            print("密钥不正确或者加密内容损坏 放弃token")
            return dict()
    else:
        return dict()


def persist_user_tokens():
    data_path = r"encrypted_tokens.data"
    origin_str = json.dumps(user_tokens, ensure_ascii=False)
    cipher_data = encrypt_data(origin_str.encode("utf-8"), aes_key, None)
    with open(data_path, 'wb') as f:
        f.write(cipher_data)
        f.flush()
        f.close()


if __name__ == "__main__":
    # 北京时间
    time_bj = get_beijing_time()
    encrypt_support = False
    user_tokens = dict()
    if os.environ.__contains__("AES_KEY") is True:
        aes_key = os.environ.get("AES_KEY")
        if aes_key is not None:
            aes_key = aes_key.encode('utf-8')
            if len(aes_key) == 16:
                encrypt_support = True
        if encrypt_support:
            user_tokens = prepare_user_tokens()
        else:
            print("AES_KEY未设置或者无效 无法使用加密保存功能")
    config = dict()
    if "CONFIG" in os.environ:
        try:
            config = dict(json.loads(os.environ.get("CONFIG")))
        except:
            print("CONFIG格式不正确，请检查Secret配置，请严格按照JSON格式：使用双引号包裹字段和值，逗号不能多也不能少")
            traceback.print_exc()
            exit(1)
    elif "USER" in os.environ and "PWD" in os.environ:
        config = {
            "USER": os.environ.get("USER"),
            "PWD": os.environ.get("PWD"),
            "MIN_STEP": os.environ.get("MIN_STEP", "18000"),
            "MAX_STEP": os.environ.get("MAX_STEP", "25000"),
            "PUSH_PLUS_TOKEN": os.environ.get("PUSH_PLUS_TOKEN", ""),
            "PUSH_PLUS_HOUR": os.environ.get("PUSH_PLUS_HOUR", ""),
            "PUSH_PLUS_MAX": os.environ.get("PUSH_PLUS_MAX", "30"),
            "PUSH_WECHAT_WEBHOOK_KEY": os.environ.get("PUSH_WECHAT_WEBHOOK_KEY", ""),
            "TELEGRAM_BOT_TOKEN": os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            "TELEGRAM_CHAT_ID": os.environ.get("TELEGRAM_CHAT_ID", ""),
            "SLEEP_GAP": os.environ.get("SLEEP_GAP", "5"),
            "USE_CONCURRENT": os.environ.get("USE_CONCURRENT", "False")
        }
    else:
        print("未配置CONFIG或USER/PWD环境变量，无法执行。请在本地创建.env文件或配置环境变量。")
        exit(1)

    # CONFIG 中的 DEVICE_ID 优先于环境变量
    _cfg_dev = str(config.get('DEVICE_ID', '') or '').strip()
    if _cfg_dev:
        FIXED_DEVICE_ID = _cfg_dev

    # region 初始化参数
    # 创建推送配置对象
    push_config = push_util.PushConfig(
        push_plus_token=config.get('PUSH_PLUS_TOKEN'),
        push_plus_hour=config.get('PUSH_PLUS_HOUR'),
        push_plus_max=get_int_value_default(config, 'PUSH_PLUS_MAX', 30),
        push_wechat_webhook_key=config.get('PUSH_WECHAT_WEBHOOK_KEY'),
        telegram_bot_token=config.get('TELEGRAM_BOT_TOKEN'),
        telegram_chat_id=config.get('TELEGRAM_CHAT_ID')
    )
    sleep_seconds = config.get('SLEEP_GAP')
    if sleep_seconds is None or sleep_seconds == '':
        sleep_seconds = 5
    sleep_seconds = float(sleep_seconds)
    users = config.get('USER')
    passwords = config.get('PWD')
    if users is None or passwords is None:
        print("未正确配置账号密码，无法执行")
        exit(1)
    min_step, max_step = get_min_max_by_time()
    use_concurrent = config.get('USE_CONCURRENT')
    if use_concurrent is not None and use_concurrent == 'True':
        use_concurrent = True
    else:
        print(f"多账号执行间隔：{sleep_seconds}")
        use_concurrent = False
    # endregion
    execute()
