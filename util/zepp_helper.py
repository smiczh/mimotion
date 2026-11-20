import json
import os
import re
import time
import traceback
import urllib
import uuid
import base64
from datetime import datetime

import pytz
import requests

from util.aes_help import encrypt_data, HM_AES_KEY, HM_AES_IV


# 通过账号密码获取access_token和refresh_token 但是refresh_token不知道怎么使用
def login_access_token(user, password) -> (str | None, str | None):
    headers = {
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "user-agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "app_name": "com.xiaomi.hm.health",
        "appname": "com.xiaomi.hm.health",
        "appplatform": "android_phone",
        "x-hm-ekv": "1",
        "hm-privacy-ceip": "false"
    }
    login_data = {
        'emailOrPhone': user,
        'password': password,
        'state': 'REDIRECTION',
        'client_id': 'HuaMi',
        'country_code': 'CN',
        'token': 'access',
        'redirect_uri': 'https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html',
    }
    # 等同 http_build_query，默认使用 quote_plus 将空格转为 '+'
    query = urllib.parse.urlencode(login_data)
    plaintext = query.encode('utf-8')
    # 执行请求加密
    cipher_data = encrypt_data(plaintext, HM_AES_KEY, HM_AES_IV)

    url1 = 'https://api-user.zepp.com/v2/registrations/tokens'
    r1 = requests.post(url1, data=cipher_data, headers=headers, allow_redirects=False, timeout=5)
    if r1.status_code != 303:
        return None, "登录异常，status: %d" % r1.status_code
    try:
        location = r1.headers["Location"]
        code = get_access_token(location)
        if code is None:
            return None, "获取accessToken失败 %s" % get_error_code(location)
    except:
        return None, f"获取accessToken异常:{traceback.format_exc()}"
    return code, None


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


# 获取login_token，app_token，userid
def grant_login_tokens(access_token, device_id, is_phone=False) -> (str | None, str | None, str | None, str | None):
    url = "https://account.huami.com/v2/client/login"
    headers = {
        "app_name": "com.xiaomi.hm.health",
        "x-request-id": f"{str(uuid.uuid4())}",
        "accept-language": "zh-CN",
        "appname": "com.xiaomi.hm.health",
        "cv": "50818_6.14.0",
        "v": "2.0",
        "appplatform": "android_phone",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    }
    if is_phone:
        data = {
            "app_name": "com.xiaomi.hm.health",
            "app_version": "6.14.0",
            "code": access_token,
            "country_code": "CN",
            "device_id": device_id,
            "device_model": "phone",
            "grant_type": "access_token",
            "third_name": "huami_phone",
        }
    else:
        data = {
            "allow_registration=": "false",
            "app_name": "com.xiaomi.hm.health",
            "app_version": "6.14.0",
            "code": access_token,
            "country_code": "CN",
            "device_id": device_id,
            "device_model": "android_phone",
            "dn": "account.zepp.com,api-user.zepp.com,api-mifit.zepp.com,api-watch.zepp.com,app-analytics.zepp.com,api-analytics.huami.com,auth.zepp.com",
            "grant_type": "access_token",
            "lang": "zh_CN",
            "os_version": "1.5.0",
            "source": "com.xiaomi.hm.health:6.14.0:50818",
            "third_name": "email",
        }
    resp = requests.post(url, data=data, headers=headers).json()
    # print("请求客户端登录成功：%s" % json.dumps(resp, ensure_ascii=False, indent=2))  #
    _login_token, _userid, _app_token = None, None, None
    try:
        result = resp.get("result")
        if result != "ok":
            return None, None, None, "客户端登录失败：%s" % result
        _login_token = resp["token_info"]["login_token"]
        _app_token = resp["token_info"]["app_token"]
        _userid = resp["token_info"]["user_id"]
    except:
        print("提取login_token失败：%s" % json.dumps(resp, ensure_ascii=False, indent=2))
    return _login_token, _app_token, _userid, None


# 获取app_token 用于提交数据变更
def grant_app_token(login_token: str) -> (str | None, str | None):
    url = f"https://account-cn.huami.com/v1/client/app_tokens?app_name=com.xiaomi.hm.health&dn=api-user.huami.com%2Capi-mifit.huami.com%2Capp-analytics.huami.com&login_token={login_token}"
    headers = {'User-Agent': 'MiFit/5.3.0 (iPhone; iOS 14.7.1; Scale/3.00)'}
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return None, "请求异常：%d" % resp.status_code
    resp = resp.json()
    print("grant_app_token: %s" % json.dumps(resp))

    result = resp.get("result")
    if result != "ok":
        error_code = resp.get("error_code")
        return None, "请求失败：%s" % error_code
    app_token = resp['token_info']['app_token']
    return app_token, None


# 获取用户信息 主要用于检查app_token是否有效
def check_app_token(app_token) -> (bool, str | None):
    url = "https://api-mifit-cn3.zepp.com/huami.health.getUserInfo.json"

    params = {
        "r": "00b7912b-790a-4552-81b1-3742f9dd1e76",
        "userid": "1188760659",
        "appid": "428135909242707968",
        "channel": "Normal",
        "country": "CN",
        "cv": "50818_6.14.0",
        "device": "android_31",
        "device_type": "android_phone",
        "lang": "zh_CN",
        "timezone": "Asia/Shanghai",
        "v": "2.0"
    }

    headers = {
        "User-Agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "Accept-Encoding": "gzip",
        "hm-privacy-diagnostics": "false",
        "country": "CN",
        "appplatform": "android_phone",
        "hm-privacy-ceip": "true",
        "x-request-id": str(uuid.uuid4()),
        "timezone": "Asia/Shanghai",
        "channel": "Normal",
        "cv": "50818_6.14.0",
        "appname": "com.xiaomi.hm.health",
        "v": "2.0",
        "apptoken": app_token,
        "lang": "zh_CN",
        "clientid": "428135909242707968"
    }
    response = requests.get(url, params=params, headers=headers)
    if response.status_code != 200:
        return False, "请求异常：%d" % response.status_code
    response = response.json()
    message = response["message"]
    if message == "success":
        return True, None
    else:
        return False, message


def renew_login_token(login_token) -> (str | None, str | None):
    url = "https://account-cn3.zepp.com/v1/client/renew_login_token"
    params = {
        "os_version": "v0.8.1",
        "dn": "account.zepp.com,api-user.zepp.com,api-mifit.zepp.com,api-watch.zepp.com,app-analytics.zepp.com,api-analytics.huami.com,auth.zepp.com",
        "login_token": login_token,
        "source": "com.xiaomi.hm.health:6.14.0:50818",
        "timestamp": get_time()
    }
    headers = {
        "User-Agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "Accept-Encoding": "gzip",
        "app_name": "com.xiaomi.hm.health",
        "hm-privacy-ceip": "false",
        "x-request-id": str(uuid.uuid4()),
        "accept-language": "zh-CN",
        "appname": "com.xiaomi.hm.health",
        "cv": "50818_6.14.0",
        "v": "2.0",
        "appplatform": "android_phone"
    }

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
    except Exception as e:
        return None, f"请求异常：{type(e).__name__}"
    if resp.status_code != 200:
        return None, f"请求异常：HTTP {resp.status_code}"
    try:
        body = resp.json()
    except Exception:
        return None, f"响应非JSON：{resp.text[:120]}"

    # 注意：响应结构不固定，可能是 {"result":"ok","token_info":{...}}，
    # 也可能是 {"code":0,"message":"...","token_info":{...}} 或直接是 token_info。
    # 这里做防御性解析，不能直接下标取 result（否则 KeyError 崩掉整个任务）
    result = body.get("result") if isinstance(body, dict) else None
    token_info = {}
    if isinstance(body, dict):
        token_info = body.get("token_info") or {}
        if not token_info and "login_token" in body:
            token_info = body
    if not isinstance(token_info, dict):
        token_info = {}

    login_token = token_info.get("login_token")
    if not login_token:
        if result is not None and result != "ok":
            return None, f"请求失败：{result}"
        return None, f"响应中无login_token：{str(body)[:150]}"

    if result is not None and result != "ok":
        return None, f"请求失败：{result}"

    return login_token, None


def _extract_items(resp) -> list:
    """从华米响应中提取设备/数据列表。

    华米 API 的业务数据通常在 data 字段下（如 {"code":0,"message":"success","data":{"items":[...]}}），
    但不同接口/版本层级并不一致：
      - data 可能是 dict（内含 items/list/devices/bands）
      - data 也可能直接就是 list
    这里做多层级兼容，避免永远取到空列表或类型异常。
    """
    if not isinstance(resp, dict):
        return []
    # data 可能不是 dict，先做类型防御
    data = resp.get("data")
    containers = [resp]
    if isinstance(data, dict):
        containers.append(data)
        inner = data.get("data")
        if isinstance(inner, dict):
            containers.append(inner)
    for container in containers:
        for key in ("items", "list", "devices", "bands"):
            val = container.get(key)
            if isinstance(val, list) and val:
                return val
    # data 本身就是列表的情况
    if isinstance(data, list) and data:
        return data
    return []


def _pick_device_id(item) -> str | None:
    """从单个设备条目中提取设备ID，兼容多种字段名。"""
    if not isinstance(item, dict):
        return None
    for key in ("deviceId", "device_id", "mac", "macAddress", "deviceMac", "did"):
        val = item.get(key)
        if val:
            return str(val).replace(":", "").upper()
    # 部分接口把 ID 放在 additionalInfo 里（可能是 JSON 字符串）
    info = item.get("additionalInfo")
    if isinstance(info, str):
        try:
            info = json.loads(info)
        except Exception:
            info = None
    if isinstance(info, dict):
        for key in ("mac", "deviceId", "device_id", "macAddress"):
            val = info.get(key)
            if val:
                return str(val).replace(":", "").upper()
    return None


# 查询用户在华米云端绑定的手环/手表设备ID
def get_user_device_id(app_token, userid) -> str | None:
    """查询账号绑定的设备ID。

    华米在不同版本/区域下提供了多个设备列表接口，旧接口可能已废弃
    （返回 code -50000 "Failed to process the request"），因此这里按顺序轮询，
    任一接口返回有效设备列表即返回。
    """
    ua = "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)"
    base_headers = {
        "apptoken": app_token,
        "User-Agent": ua,
        "appname": "com.xiaomi.hm.health",
        "appplatform": "android_phone",
    }
    # (说明, URL, 附加请求头)
    candidates = [
        ("binds.json(mifit-cn)",
         f"https://api-mifit-cn.huami.com/v1/device/binds.json?userid={userid}", {}),
        ("users/{id}/devices(zepp)",
         f"https://api.zepp.com/users/{userid}/devices", {}),
        ("users/{id}/devices(zepp+appid)",
         f"https://api.zepp.com/users/{userid}/devices?appid=428135909242707968"
         f"&device_type=android_phone&device=android_31&enableMultiDevice=true", {}),
        ("users/{id}/devices(mifit-cn3)",
         f"https://api-mifit-cn3.zepp.com/users/{userid}/devices", {}),
        ("binds.json(mifit-cn3)",
         f"https://api-mifit-cn3.zepp.com/v1/device/binds.json?userid={userid}", {}),
    ]

    diagnostics = []
    for label, url, extra in candidates:
        headers = dict(base_headers)
        headers.update(extra)
        try:
            r = requests.get(url, headers=headers, timeout=12)
            body = r.text[:400].replace("\n", " ")
            if r.status_code != 200:
                diagnostics.append(f"  [{label}] HTTP {r.status_code} | {body[:180]}")
                continue
            try:
                resp = r.json()
            except Exception:
                diagnostics.append(f"  [{label}] 非JSON响应 | {body[:180]}")
                continue

            items = _extract_items(resp)
            if not items:
                diagnostics.append(f"  [{label}] 响应无设备列表 | {str(resp)[:180]}")
                continue

            dev_id = _select_device_id(items)
            if dev_id:
                print(f"设备列表接口命中: {label}")
                return dev_id
            diagnostics.append(f"  [{label}] 有 {len(items)} 条但无有效设备ID")
        except Exception as e:
            diagnostics.append(f"  [{label}] 请求异常 {type(e).__name__}: {str(e)[:120]}")

    print("全部设备列表接口均未取到设备，详情：")
    for d in diagnostics:
        print(d)
    print("请确认 Zepp Life 中已绑定手环/虚拟设备，或该接口已被华米下线")
    return None


def _select_device_id(items) -> str | None:
    """从设备列表中挑出合适的设备ID（手环/手表优先，跳过体重秤）。"""
    # 1. 优先匹配 deviceType == 0 (手环/手表)
    for item in items:
        if isinstance(item, dict) and item.get("deviceType") == 0:
            dev_id = _pick_device_id(item)
            if dev_id:
                return dev_id
    # 2. 按名称匹配手环/手表（排除体重秤等非计步设备）
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("productName", item.get("name", ""))).lower()
        if any(k in name for k in ["band", "watch", "手环", "手表"]):
            dev_id = _pick_device_id(item)
            if dev_id:
                return dev_id
    # 3. 兜底：取任意一个带设备ID的条目
    for item in items:
        if isinstance(item, dict):
            name = str(item.get("productName", item.get("name", ""))).lower()
            if any(k in name for k in ["scale", "体重秤", "体脂秤"]):
                continue
            if item.get("deviceType") in (2, 3):
                continue
    dev_id = _pick_device_id(item)
    if dev_id:
        return dev_id
    return None


def _sync_summary_with_step(data_json: str, target_step: int) -> str:
    """把 summary 中的活动明细与派生指标同步到目标步数。

    data_json 形如:
        %5B%7B%22summary%22%3A%22{\\"v\\":6,...}\" ... %7D%5D
    其中 summary 的值是被 URL 编码过的 JSON 明文（含转义反斜杠）。

    处理内容：
    - stp.stage 各区间的 step 按比例缩放，使合计等于 target_step
    - stp.dis / stp.cal / stp.wk / stp.rn / runDist / runCal 按同一比例缩放
    - 保证"总步数 == 明细合计"，避免服务端判定数据异常而不推送给微信
    """
    try:
        # 定位 summary 字段：%22summary%22%3A%22 ... %22
        m = re.search(r'(%22summary%22%3A%22)(.*?)(%22(?:%2C|\"|,))', data_json, re.S)
        if not m:
            return data_json
        raw_summary = m.group(2)
        # URL 解码 -> JSON 解码（其中 \" 是转义的双引号）
        decoded = urllib.parse.unquote(raw_summary).replace('\\"', '"')
        summary = json.loads(decoded)
    except Exception as e:
        print(f"解析 summary 失败（跳过明细同步）: {e}")
        return data_json

    try:
        stp = summary.get("stp")
        if not isinstance(stp, dict):
            return data_json

        stages = stp.get("stage")
        if not isinstance(stages, list) or not stages:
            return data_json

        old_total = sum(int(s.get("step", 0) or 0) for s in stages)
        if old_total <= 0:
            return data_json

        ratio = target_step / old_total

        # 按比例缩放每个区间的步数，并把舍入误差补到最后一个区间
        acc = 0
        last_idx = len(stages) - 1
        for i, s in enumerate(stages):
            if i == last_idx:
                new_step = target_step - acc
            else:
                new_step = int(round(int(s.get("step", 0) or 0) * ratio))
                if new_step < 0:
                    new_step = 0
                acc += new_step
            s["step"] = new_step

        # 派生指标按同一比例缩放，保证整体自洽
        for key in ("dis", "cal"):
            if isinstance(stp.get(key), (int, float)):
                stp[key] = int(round(stp[key] * ratio))
        for key in ("wk", "rn"):
            if isinstance(stp.get(key), (int, float)):
                stp[key] = int(round(stp[key] * ratio))
        for key in ("runDist", "runCal"):
            if isinstance(stp.get(key), (int, float)):
                stp[key] = int(round(stp[key] * ratio))

        # 同步总步数（外层正则改的是 URL 编码后的形式，
        # 这里重新序列化整个 summary 会覆盖它，故必须再次显式赋值）
        stp["ttl"] = target_step

        # 回写：JSON 序列化 -> 转义双引号 -> URL 编码
        new_raw = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
        new_raw = new_raw.replace('"', '\\"')
        new_raw = urllib.parse.quote(new_raw, safe="")
        final_sum = sum(int(x.get("step", 0) or 0) for x in stages)
        print(f"summary 步数已同步: ttl={stp.get('ttl')} 明细合计={final_sum} "
              f"距离={stp.get('dis')}m 卡路里={stp.get('cal')}")
        return data_json[:m.start(2)] + new_raw + data_json[m.end(2):]
    except Exception as e:
        print(f"同步 summary 明细失败（保留原值）: {e}")
        return data_json


def _compat_flags(cfg=None) -> dict:
    """读取兼容模式开关。

    只认环境变量（由 GitHub Actions 的 workflow_dispatch input 注入）：
      COMPAT_STAGE_EMPTY / COMPAT_CURRENT_TS / COMPAT_NO_DEVID / COMPAT_CN2

    【重要】刻意不读 CONFIG 里的同名字段：
    1) 定时任务不传这些环境变量，若 CONFIG 里留了开关，定时任务会一直用兼容模式跑；
    2) COMPAT_NO_DEVID 会让数据写进原作者的设备 DA932FFFFE8816E7，绝不能长期开着；
    3) 改 Secret 容易漏保存/格式错（实测连续两次"兼容模式全部关闭"）。
    因此兼容模式只在手动 Run workflow 时通过输入框临时开启。
    """
    flags = {
        "stage_empty": False,
        "current_ts": False,
        "no_devid": False,
        "cn2": False,
    }
    env_map = {
        "COMPAT_STAGE_EMPTY": "stage_empty",
        "COMPAT_CURRENT_TS": "current_ts",
        "COMPAT_NO_DEVID": "no_devid",
        "COMPAT_CN2": "cn2",
    }
    for env_key, flag in env_map.items():
        val = os.environ.get(env_key, "").strip().lower()
        if val in ("1", "true", "yes", "on"):
            flags[flag] = True

    # 若 CONFIG 里还残留 COMPAT_* 字段，提示用户删除（它们已不再生效）
    if isinstance(cfg, dict):
        leftover = [k for k in cfg.keys()
                    if isinstance(k, str) and k.upper().startswith("COMPAT_")]
        if leftover:
            print(f"提示: CONFIG 中的 {leftover} 已不再生效（兼容模式只认 Actions 输入参数），"
                  f"建议从 CONFIG Secret 里删除，避免误以为已开启")
    return flags


def _clear_stage(data_json: str) -> str:
    """把 summary.stp.stage 置为空数组（对齐 Zepp-Life-Steps 的提交格式）。"""
    try:
        m = re.search(r'(%22summary%22%3A%22)(.*?)(%22(?:%2C|\"|,))', data_json, re.S)
        if not m:
            return data_json
        raw = urllib.parse.unquote(m.group(2)).replace('\\"', '"')
        summary = json.loads(raw)
        stp = summary.get("stp")
        if isinstance(stp, dict) and "stage" in stp:
            stp["stage"] = []
        new_raw = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
        new_raw = new_raw.replace('"', '\\"')
        new_raw = urllib.parse.quote(new_raw, safe="")
        return data_json[:m.start(2)] + new_raw + data_json[m.end(2):]
    except Exception as e:
        print(f"清空 stage 失败（保留原值）: {e}")
        return data_json


def post_fake_brand_data(step, app_token, userid, device_id=None, cfg=None):
    t = get_time()

    # 提交日期必须用北京时间：GitHub Actions的runner是UTC时区，跨北京时间0点执行时UTC日期还是前一天，会把步数写错天
    today = get_beijing_time().strftime("%F")

    data_json = '%5B%7B%22data_hr%22%3A%22%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9L%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FVv%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0v%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9e%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0n%5C%2Fa%5C%2F%5C%2F%5C%2FS%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0b%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F1FK%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FR%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9PTFFpaf9L%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FR%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0j%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9K%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FOv%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2Fzf%5C%2F%5C%2F%5C%2F86%5C%2Fzr%5C%2FOv88%5C%2Fzf%5C%2FPf%5C%2F%5C%2F%5C%2F0v%5C%2FS%5C%2F8%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FSf%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2Fz3%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0r%5C%2FOv%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FS%5C%2F9L%5C%2Fzb%5C%2FSf9K%5C%2F0v%5C%2FRf9H%5C%2Fzj%5C%2FSf9K%5C%2F0%5C%2F%5C%2FN%5C%2F%5C%2F%5C%2F%5C%2F0D%5C%2FSf83%5C%2Fzr%5C%2FPf9M%5C%2F0v%5C%2FOv9e%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FS%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2Fzv%5C%2F%5C%2Fz7%5C%2FO%5C%2F83%5C%2Fzv%5C%2FN%5C%2F83%5C%2Fzr%5C%2FN%5C%2F86%5C%2Fz%5C%2F%5C%2FNv83%5C%2Fzn%5C%2FXv84%5C%2Fzr%5C%2FPP84%5C%2Fzj%5C%2FN%5C%2F9e%5C%2Fzr%5C%2FN%5C%2F89%5C%2F03%5C%2FP%5C%2F89%5C%2Fz3%5C%2FQ%5C%2F9N%5C%2F0v%5C%2FTv9C%5C%2F0H%5C%2FOf9D%5C%2Fzz%5C%2FOf88%5C%2Fz%5C%2F%5C%2FPP9A%5C%2Fzr%5C%2FN%5C%2F86%5C%2Fzz%5C%2FNv87%5C%2F0D%5C%2FOv84%5C%2F0v%5C%2FO%5C%2F84%5C%2Fzf%5C%2FMP83%5C%2FzH%5C%2FNv83%5C%2Fzf%5C%2FN%5C%2F84%5C%2Fzf%5C%2FOf82%5C%2Fzf%5C%2FOP83%5C%2Fzb%5C%2FMv81%5C%2FzX%5C%2FR%5C%2F9L%5C%2F0v%5C%2FO%5C%2F9I%5C%2F0T%5C%2FS%5C%2F9A%5C%2Fzn%5C%2FPf89%5C%2Fzn%5C%2FNf9K%5C%2F07%5C%2FN%5C%2F83%5C%2Fzn%5C%2FNv83%5C%2Fzv%5C%2FO%5C%2F9A%5C%2F0H%5C%2FOf8%5C%2F%5C%2Fzj%5C%2FPP83%5C%2Fzj%5C%2FS%5C%2F87%5C%2Fzj%5C%2FNv84%5C%2Fzf%5C%2FOf83%5C%2Fzf%5C%2FOf83%5C%2Fzb%5C%2FNv9L%5C%2Fzj%5C%2FNv82%5C%2Fzb%5C%2FN%5C%2F85%5C%2Fzf%5C%2FN%5C%2F9J%5C%2Fzf%5C%2FNv83%5C%2Fzj%5C%2FNv84%5C%2F0r%5C%2FSv83%5C%2Fzf%5C%2FMP%5C%2F%5C%2F%5C%2Fzb%5C%2FMv82%5C%2Fzb%5C%2FOf85%5C%2Fz7%5C%2FNv8%5C%2F%5C%2F0r%5C%2FS%5C%2F85%5C%2F0H%5C%2FQP9B%5C%2F0D%5C%2FNf89%5C%2Fzj%5C%2FOv83%5C%2Fzv%5C%2FNv8%5C%2F%5C%2F0f%5C%2FSv9O%5C%2F0ZeXv%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F1X%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9B%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2FTP%5C%2F%5C%2F%5C%2F1b%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F0%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F9N%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2F%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%5C%2Fv7%2B%22%2C%22date%22%3A%222021-08-07%22%2C%22data%22%3A%5B%7B%22start%22%3A0%2C%22stop%22%3A1439%2C%22value%22%3A%22UA8AUBQAUAwAUBoAUAEAYCcAUBkAUB4AUBgAUCAAUAEAUBkAUAwAYAsAYB8AYB0AYBgAYCoAYBgAYB4AUCcAUBsAUB8AUBwAUBIAYBkAYB8AUBoAUBMAUCEAUCIAYBYAUBwAUCAAUBgAUCAAUBcAYBsAYCUAATIPYD0KECQAYDMAYB0AYAsAYCAAYDwAYCIAYB0AYBcAYCQAYB0AYBAAYCMAYAoAYCIAYCEAYCYAYBsAYBUAYAYAYCIAYCMAUB0AUCAAUBYAUCoAUBEAUC8AUB0AUBYAUDMAUDoAUBkAUC0AUBQAUBwAUA0AUBsAUAoAUCEAUBYAUAwAUB4AUAwAUCcAUCYAUCwKYDUAAUUlEC8IYEMAYEgAYDoAYBAAUAMAUBkAWgAAWgAAWgAAWgAAWgAAUAgAWgAAUBAAUAQAUA4AUA8AUAkAUAIAUAYAUAcAUAIAWgAAUAQAUAkAUAEAUBkAUCUAWgAAUAYAUBEAWgAAUBYAWgAAUAYAWgAAWgAAWgAAWgAAUBcAUAcAWgAAUBUAUAoAUAIAWgAAUAQAUAYAUCgAWgAAUAgAWgAAWgAAUAwAWwAAXCMAUBQAWwAAUAIAWgAAWgAAWgAAWgAAWgAAWgAAWgAAWgAAWREAWQIAUAMAWSEAUDoAUDIAUB8AUCEAUC4AXB4AUA4AWgAAUBIAUA8AUBAAUCUAUCIAUAMAUAEAUAsAUAMAUCwAUBYAWgAAWgAAWgAAWgAAWgAAWgAAUAYAWgAAWgAAWgAAUAYAWwAAWgAAUAYAXAQAUAMAUBsAUBcAUCAAWwAAWgAAWgAAWgAAWgAAUBgAUB4AWgAAUAcAUAwAWQIAWQkAUAEAUAIAWgAAUAoAWgAAUAYAUB0AWgAAWgAAUAkAWgAAWSwAUBIAWgAAUC4AWSYAWgAAUAYAUAoAUAkAUAIAUAcAWgAAUAEAUBEAUBgAUBcAWRYAUA0AWSgAUB4AUDQAUBoAXA4AUA8AUBwAUA8AUA4AUA4AWgAAUAIAUCMAWgAAUCwAUBgAUAYAUAAAUAAAUAAAUAAAUAAAUAAAUAAAUAAAUAAAWwAAUAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAeSEAeQ8AcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBcAcAAAcAAAcCYOcBUAUAAAUAAAUAAAUAAAUAUAUAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCgAeQAAcAAAcAAAcAAAcAAAcAAAcAYAcAAAcBgAeQAAcAAAcAAAegAAegAAcAAAcAcAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCkAeQAAcAcAcAAAcAAAcAwAcAAAcAAAcAIAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcCIAeQAAcAAAcAAAcAAAcAAAcAAAeRwAeQAAWgAAUAAAUAAAUAAAUAAAUAAAcAAAcAAAcBoAeScAeQAAegAAcBkAeQAAUAAAUAAAUAAAUAAAUAAAUAAAcAAAcAAAcAAAcAAAcAAAcAAAegAAegAAcAAAcAAAcBgAeQAAcAAAcAAAcAAAcAAAcAAAcAkAegAAegAAcAcAcAAAcAcAcAAAcAAAcAAAcAAAcA8AeQAAcAAAcAAAeRQAcAwAUAAAUAAAUAAAUAAAUAAAUAAAcAAAcBEAcA0AcAAAWQsAUAAAUAAAUAAAUAAAUAAAcAAAcAoAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAYAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBYAegAAcAAAcAAAegAAcAcAcAAAcAAAcAAAcAAAcAAAeRkAegAAegAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAEAcAAAcAAAcAAAcAUAcAQAcAAAcBIAeQAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBsAcAAAcAAAcBcAeQAAUAAAUAAAUAAAUAAAUAAAUBQAcBYAUAAAUAAAUAoAWRYAWTQAWQAAUAAAUAAAUAAAcAAAcAAAcAAAcAAAcAAAcAMAcAAAcAQAcAAAcAAAcAAAcDMAeSIAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcAAAcBQAeQwAcAAAcAAAcAAAcAMAcAAAeSoAcA8AcDMAcAYAeQoAcAwAcFQAcEMAeVIAaTYAbBcNYAsAYBIAYAIAYAIAYBUAYCwAYBMAYDYAYCkAYDcAUCoAUCcAUAUAUBAAWgAAYBoAYBcAYCgAUAMAUAYAUBYAUA4AUBgAUAgAUAgAUAsAUAsAUA4AUAMAUAYAUAQAUBIAASsSUDAAUDAAUBAAYAYAUBAAUAUAUCAAUBoAUCAAUBAAUAoAYAIAUAQAUAgAUCcAUAsAUCIAUCUAUAoAUA4AUB8AUBkAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAAfgAA%22%2C%22tz%22%3A32%2C%22did%22%3A%22DA932FFFFE8816E7%22%2C%22src%22%3A24%7D%5D%2C%22summary%22%3A%22%7B%5C%22v%5C%22%3A6%2C%5C%22slp%5C%22%3A%7B%5C%22st%5C%22%3A1628296479%2C%5C%22ed%5C%22%3A1628296479%2C%5C%22dp%5C%22%3A0%2C%5C%22lt%5C%22%3A0%2C%5C%22wk%5C%22%3A0%2C%5C%22usrSt%5C%22%3A-1440%2C%5C%22usrEd%5C%22%3A-1440%2C%5C%22wc%5C%22%3A0%2C%5C%22is%5C%22%3A0%2C%5C%22lb%5C%22%3A0%2C%5C%22to%5C%22%3A0%2C%5C%22dt%5C%22%3A0%2C%5C%22rhr%5C%22%3A0%2C%5C%22ss%5C%22%3A0%7D%2C%5C%22stp%5C%22%3A%7B%5C%22ttl%5C%22%3A18272%2C%5C%22dis%5C%22%3A10627%2C%5C%22cal%5C%22%3A510%2C%5C%22wk%5C%22%3A41%2C%5C%22rn%5C%22%3A50%2C%5C%22runDist%5C%22%3A7654%2C%5C%22runCal%5C%22%3A397%2C%5C%22stage%5C%22%3A%5B%7B%5C%22start%5C%22%3A327%2C%5C%22stop%5C%22%3A341%2C%5C%22mode%5C%22%3A1%2C%5C%22dis%5C%22%3A481%2C%5C%22cal%5C%22%3A13%2C%5C%22step%5C%22%3A680%7D%2C%7B%5C%22start%5C%22%3A342%2C%5C%22stop%5C%22%3A367%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A2295%2C%5C%22cal%5C%22%3A95%2C%5C%22step%5C%22%3A2874%7D%2C%7B%5C%22start%5C%22%3A368%2C%5C%22stop%5C%22%3A377%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A1592%2C%5C%22cal%5C%22%3A88%2C%5C%22step%5C%22%3A1664%7D%2C%7B%5C%22start%5C%22%3A378%2C%5C%22stop%5C%22%3A386%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A1072%2C%5C%22cal%5C%22%3A51%2C%5C%22step%5C%22%3A1245%7D%2C%7B%5C%22start%5C%22%3A387%2C%5C%22stop%5C%22%3A393%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A1036%2C%5C%22cal%5C%22%3A57%2C%5C%22step%5C%22%3A1124%7D%2C%7B%5C%22start%5C%22%3A394%2C%5C%22stop%5C%22%3A398%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A488%2C%5C%22cal%5C%22%3A19%2C%5C%22step%5C%22%3A607%7D%2C%7B%5C%22start%5C%22%3A399%2C%5C%22stop%5C%22%3A414%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A2220%2C%5C%22cal%5C%22%3A120%2C%5C%22step%5C%22%3A2371%7D%2C%7B%5C%22start%5C%22%3A415%2C%5C%22stop%5C%22%3A427%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A1268%2C%5C%22cal%5C%22%3A59%2C%5C%22step%5C%22%3A1489%7D%2C%7B%5C%22start%5C%22%3A428%2C%5C%22stop%5C%22%3A433%2C%5C%22mode%5C%22%3A1%2C%5C%22dis%5C%22%3A152%2C%5C%22cal%5C%22%3A4%2C%5C%22step%5C%22%3A238%7D%2C%7B%5C%22start%5C%22%3A434%2C%5C%22stop%5C%22%3A444%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A2295%2C%5C%22cal%5C%22%3A95%2C%5C%22step%5C%22%3A2874%7D%2C%7B%5C%22start%5C%22%3A445%2C%5C%22stop%5C%22%3A455%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A1592%2C%5C%22cal%5C%22%3A88%2C%5C%22step%5C%22%3A1664%7D%2C%7B%5C%22start%5C%22%3A456%2C%5C%22stop%5C%22%3A466%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A1072%2C%5C%22cal%5C%22%3A51%2C%5C%22step%5C%22%3A1245%7D%2C%7B%5C%22start%5C%22%3A467%2C%5C%22stop%5C%22%3A477%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A1036%2C%5C%22cal%5C%22%3A57%2C%5C%22step%5C%22%3A1124%7D%2C%7B%5C%22start%5C%22%3A478%2C%5C%22stop%5C%22%3A488%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A488%2C%5C%22cal%5C%22%3A19%2C%5C%22step%5C%22%3A607%7D%2C%7B%5C%22start%5C%22%3A489%2C%5C%22stop%5C%22%3A499%2C%5C%22mode%5C%22%3A4%2C%5C%22dis%5C%22%3A2220%2C%5C%22cal%5C%22%3A120%2C%5C%22step%5C%22%3A2371%7D%2C%7B%5C%22start%5C%22%3A500%2C%5C%22stop%5C%22%3A511%2C%5C%22mode%5C%22%3A3%2C%5C%22dis%5C%22%3A1268%2C%5C%22cal%5C%22%3A59%2C%5C%22step%5C%22%3A1489%7D%2C%7B%5C%22start%5C%22%3A512%2C%5C%22stop%5C%22%3A522%2C%5C%22mode%5C%22%3A1%2C%5C%22dis%5C%22%3A152%2C%5C%22cal%5C%22%3A4%2C%5C%22step%5C%22%3A238%7D%5D%7D%2C%5C%22goal%5C%22%3A8000%2C%5C%22tz%5C%22%3A%5C%2228800%5C%22%7D%22%2C%22source%22%3A24%2C%22type%22%3A0%7D%5D'

    find_date = re.compile(r".*?date%22%3A%22(.*?)%22%2C%22data.*?")
    find_step = re.compile(r".*?ttl%5C%22%3A(.*?)%2C%5C%22dis.*?")
    data_json = re.sub(find_date.findall(data_json)[0], today, str(data_json))
    data_json = re.sub(find_step.findall(data_json)[0], step, str(data_json))

    # 关键修复：同步修正 summary 中的活动明细与派生指标。
    # 原逻辑只改 stp.ttl，而 stage 明细/距离/卡路里仍是模板里原作者那天的数据，
    # 导致"总步数 18148"与"明细合计 23904"自相矛盾，
    # 华米侧校验判定数据异常，因而不会把数据推送给微信运动（脚本返回 success 但微信无变化）。
    data_json = _sync_summary_with_step(data_json, int(step))

    # 兼容模式：对齐 Zepp-Life-Steps（已验证可同步到微信）的提交格式。
    # 该实现与我们的差异有 4 处，逐一可开关对比，用于定位真正的阻塞点：
    #   compat_stage_empty : summary.stp.stage 置空（参考实现用 []，不带明细）
    #   compat_current_ts  : last_sync_data_time 用当前时间戳（参考实现如此，我们原为固定的 2020 年值）
    #   compat_no_devid    : 不替换 did，保持模板自带的 DA932FFFFE8816E7
    #   compat_cn2         : 提交到 api-mifit-cn2.huami.com（参考实现用的域名）
    compat = _compat_flags(cfg)
    if compat.get("stage_empty"):
        data_json = _clear_stage(data_json)
    if compat.get("no_devid"):
        # 参考实现不替换设备ID，保持模板原值
        pass
    else:
        if device_id:
            data_json = str(data_json).replace("DA932FFFFE8816E7", device_id)

    if compat.get("cn2"):
        url = f'https://api-mifit-cn2.huami.com/v1/data/band_data.json?&t={t}&r={str(uuid.uuid4())}'
    else:
        url = f'https://api-mifit-cn.huami.com/v1/data/band_data.json?&t={t}&r={str(uuid.uuid4())}'
    head = {
        "apptoken": app_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    if not device_id and not compat.get("no_devid"):
        # 没有拿到本账号真实绑定的设备ID时，绝不能写入默认设备ID
        # （那是原作者的设备，会导致"接口返回成功但自己账号步数不变"）
        print("未获取到本账号的设备ID，跳过提交（否则步数不会写入你的账号）")
        return False, "未绑定设备：请先在 Zepp Life 绑定手环或虚拟设备后重试"

    target_dev_id = "DA932FFFFE8816E7" if compat.get("no_devid") else (device_id or "DA932FFFFE8816E7")

    sync_time = int(time.time()) if compat.get("current_ts") else 1597306380
    data = f'userid={userid}&last_sync_data_time={sync_time}&device_type=0&last_deviceid={target_dev_id}&data_json={data_json}'

    if compat:
        on = [k for k, v in compat.items() if v]
        print(f"兼容模式开启: {on if on else '全部关闭'}"
              + (f" | last_sync_data_time={sync_time}" if compat.get("current_ts") else "")
              + (f" | 域名={'cn2' if compat.get('cn2') else 'cn'}"))

    # 提交尝试：依次尝试多个「域名 × 请求头」组合，任一成功即返回。
    # Web 身份登录拿到的 app_token 提交数据时可能因请求头身份不匹配而报 500，
    # 这里多试几种组合，一次运行即可定位可用组合。
    attempts = _build_submit_attempts(url, head, app_token, compat)
    last_err = None
    for idx, (label, a_url, a_head) in enumerate(attempts):
        try:
            response = requests.post(a_url, data=data, headers=a_head, timeout=20)
        except Exception as e:
            last_err = f"{label}: 请求异常 {type(e).__name__}"
            print(f"  提交尝试[{label}]: 异常 {type(e).__name__} {str(e)[:80]}")
            continue
        if response.status_code != 200:
            body = response.text[:200].replace("\n", " ")
            last_err = f"{label}: HTTP {response.status_code} {body}"
            print(f"  提交尝试[{label}]: HTTP {response.status_code} | {body[:120]}")
            continue
        try:
            j = response.json()
        except Exception:
            last_err = f"{label}: 响应非JSON"
            print(f"  提交尝试[{label}]: 响应非JSON | {response.text[:120]}")
            continue
        msg = j.get("message", "")
        if msg == "success":
            if idx > 0:
                print(f"  ✓ 提交成功于组合: {label}")
            return True, msg
        last_err = f"{label}: {msg}"
        print(f"  提交尝试[{label}]: {msg}")

    print(f"提交失败，所有组合均未成功。最后错误: {last_err}")
    print(f"  URL基准: {url}")
    print(f"  userid={userid} last_deviceid={target_dev_id} "
          f"device_type=0 sync_time={sync_time} data_json长度={len(data_json)}")
    print(f"  app_token前16位: {str(app_token)[:16]}")
    return False, "请求修改步数异常（已尝试%d种组合）：%s" % (len(attempts), str(last_err)[:100])
    try:
        response = response.json()
    except Exception:
        return False, "响应非JSON：%s" % response.text[:120]
    message = response.get("message", "")
    if message == "success":
        return True, message
    else:
        return False, message


def read_back_steps(app_token, userid, device_id=None, date=None,
                    expect_step=None, retries=3, retry_delay=5) -> dict | None:
    """回读华米云端当天步数，用于验证数据是否真的入库。

    微信运动是每天凌晨拉取云端数据后展示，脚本返回 success 不等于数据已入库，
    这里主动读一次，可以立刻区分"数据没写进去"与"写了但微信还没同步"。

    华米对同一天的数据遵循"取最大值"规则：后写入的更小步数不会覆盖已有值。
    因此传入 expect_step 时会重试若干次，直到云端值 >= 期望值（即数据确已入库）。

    expect_step: 期望的步数（用于判断是否已生效）
    """
    if date is None:
        date = get_beijing_time().strftime("%F")
    url = "https://api-mifit-cn.huami.com/v1/data/band_data.json?" + urllib.parse.urlencode({
        "query_type": "summary",
        "device_type": "android_phone",
        "userid": userid,
        "from_date": date,
        "to_date": date,
    })
    headers = {
        "apptoken": app_token,
        "User-Agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "appname": "com.xiaomi.hm.health",
        "appplatform": "android_phone",
    }

    result = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            # 多主机回读：不同区域/集群的数据可能存在同步差异，
            # api-mifit.zepp.com 是 Zepp 官方当前使用的主机
            last_err = None
            resp_json = None
            for host in ("https://api-mifit.zepp.com",
                         "https://api-mifit-cn.zepp.com",
                         "https://api-mifit-cn.huami.com"):
                u = host + "/v1/data/band_data.json?" + urllib.parse.urlencode({
                    "query_type": "summary",
                    "device_type": "android_phone",
                    "userid": userid,
                    "from_date": date,
                    "to_date": date,
                })
                try:
                    rr = requests.get(u, headers=headers, timeout=15)
                except Exception as e:
                    last_err = f"{host}: {type(e).__name__}"
                    continue
                if rr.status_code != 200:
                    last_err = f"{host}: HTTP {rr.status_code}"
                    continue
                try:
                    resp_json = rr.json()
                except Exception as e:
                    last_err = f"{host}: 非JSON"
                    continue
                if _extract_items(resp_json):
                    break
                last_err = f"{host}: 无数据项"
            if resp_json is None:
                print(f"云端回读失败（所有主机）: {last_err}")
                return None
            j = resp_json
        except Exception as e:
            print(f"云端回读异常: {type(e).__name__} {str(e)[:100]}")
            return None

        items = _extract_items(j)
        if not items:
            print(f"云端回读：{date} 无数据项（数据可能尚未入库）")
            result = None
        else:
            result = None
            for it in items:
                summary = it.get("summary")
                if isinstance(summary, str):
                    try:
                        pad = (-len(summary)) % 4
                        s = json.loads(base64.b64decode(summary + "=" * pad).decode("utf-8"))
                    except Exception:
                        # 也可能是 URL 编码的明文 JSON
                        try:
                            s = json.loads(urllib.parse.unquote(summary).replace('\\"', '"'))
                        except Exception:
                            continue
                elif isinstance(summary, dict):
                    s = summary
                else:
                    continue

                stp = s.get("stp") or {}
                ttl = stp.get("ttl")
                # 设备ID可能出现在多个位置：条目顶层、summary 内
                did = (it.get("did") or it.get("deviceId") or it.get("device_id")
                       or s.get("did") or s.get("deviceId"))
                if not did:
                    cand = [k for k in it.keys()
                            if isinstance(k, str) and ("did" in k.lower() or "device" in k.lower())]
                    if cand:
                        did = f"(字段:{cand})"
                stages = stp.get("stage") or []
                stage_sum = sum(int(x.get("step", 0) or 0) for x in stages) if stages else None
                print(f"云端回读 {date}: 设备={did} 总步数={ttl}"
                      + (f" 明细合计={stage_sum}" if stage_sum is not None else "")
                      + (f" 距离={stp.get('dis')}m" if stp.get("dis") is not None else "")
                      + (f" 卡路里={stp.get('cal')}" if stp.get("cal") is not None else ""))
                result = {"date": date, "did": did, "ttl": ttl, "stage_sum": stage_sum,
                          "dis": stp.get("dis"), "cal": stp.get("cal")}
                break

        # 期望值校验
        # 注意：华米对同一天的数据遵循"取最大值"规则 —— 后写入的更小步数不会覆盖已有值。
        # 因此只要云端值 >= 本次提交值，就说明数据已成功入库（可能是之前的某次运行写的）。
        if expect_step is None:
            break
        if result is not None and result.get("ttl") is not None:
            cur = result.get("ttl")
            if cur >= expect_step:
                if cur == expect_step:
                    print(f"云端回读校验通过：{expect_step} 步已入库")
                else:
                    print(f"云端回读校验通过：云端当前 {cur} 步 ≥ 本次提交 {expect_step} 步"
                          f"（华米当日取最大值规则，更小的值不会覆盖）")
                break
        if attempt < max(1, retries):
            print(f"云端回读暂未同步到新值（当前 {result.get('ttl') if result else '无'}，"
                  f"期望 ≥ {expect_step}），{retry_delay} 秒后重试...")
            time.sleep(retry_delay)
    return result


def _find_step_like(obj, path="", depth=0, out=None):
    """递归查找响应中所有可能是"步数"的字段。

    华米账号维度接口的字段名不固定（step / steps / todayStep / stepCount /
    totalStep / step_target 等），且可能嵌套在 defaultFields / config 里。
    """
    if out is None:
        out = []
    if depth > 4 or not isinstance(obj, (dict, list)):
        return out
    if isinstance(obj, list):
        for i, v in enumerate(obj[:5]):
            _find_step_like(v, f"{path}[{i}]", depth + 1, out)
        return out
    for k, v in obj.items():
        kl = str(k).lower()
        if any(t in kl for t in ("step", "stride", "walk", "sport")) and \
                isinstance(v, (int, float, str)) and not isinstance(v, bool):
            out.append((f"{path}.{k}" if path else str(k), v))
        elif isinstance(v, (dict, list)):
            _find_step_like(v, f"{path}.{k}" if path else str(k), depth + 1, out)
    return out


def diagnose_sync(app_token, userid) -> dict:
    """诊断微信同步链路的最后两个未知环节。

    1) 账号维度步数：getUserInfo 返回账号汇总数据，微信推送读的是这一层，
       而 band_data 写的是设备维度。若这里查不到 23714，说明数据没聚合到账号维度。
    2) 第三方接入状态：查询账号已绑定的第三方平台，确认微信绑定是否存在。
    """
    out = {}

    # ---------- 1. 账号维度步数 ----------
    try:
        url = "https://api-mifit-cn3.zepp.com/huami.health.getUserInfo.json"
        params = {
            "r": str(uuid.uuid4()),
            "userid": str(userid),
            "appid": "428135909242707968",
            "channel": "Normal",
            "country": "CN",
            "cv": "50818_6.14.0",
            "device": "android_31",
            "device_type": "android_phone",
            "lang": "zh_CN",
            "timezone": "Asia/Shanghai",
            "v": "2.0",
        }
        headers = {
            "apptoken": app_token,
            "User-Agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
            "appname": "com.xiaomi.hm.health",
            "appplatform": "android_phone",
        }
        r = requests.get(url, params=params, headers=headers, timeout=15)
        if r.status_code == 200:
            j = r.json()
            data = j.get("data") or {}
            # 账号维度常见的步数字段
            step = None
            for k in ("step", "steps", "todayStep", "stepCount", "totalStep", "currentStep"):
                if k in data:
                    step = data[k]
                    break
            # 打印完整字段名（之前只打印前12个，会漏掉 step）
            all_keys = list(data.keys())
            print(f"账号维度查询: HTTP 200, 共 {len(all_keys)} 个字段")
            print(f"  完整字段名: {all_keys}")
            # 递归查找任何像步数的字段
            found = _find_step_like(data)
            if found:
                for path, val in found:
                    print(f"  ★ 疑似步数字段: {path} = {val}")
            if step is not None:
                print(f"  ★ 账号维度步数 = {step}")
            else:
                print("  （顶层未直接包含步数字段）")
            # 顺带打印几个与步数相关的健康指标，便于判断账号维度数据
            for k in ("calories", "distance", "weight", "sleep", "heart_rate"):
                if k in data:
                    v = data[k]
                    sv = json.dumps(v, ensure_ascii=False) if not isinstance(v, (int, float, str)) else v
                    print(f"  · {k} = {str(sv)[:100]}")
            out["user_info"] = data
            out["account_step"] = step
        else:
            print(f"账号维度查询: HTTP {r.status_code} {r.text[:150]}")
    except Exception as e:
        print(f"账号维度查询异常: {type(e).__name__} {str(e)[:120]}")

    # ---------- 2. 第三方接入（微信绑定）状态 ----------
    # 该接口路径不唯一，多个候选依次尝试，任何一个返回绑定信息即可
    h2 = {
        "apptoken": app_token,
        "User-Agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "appname": "com.xiaomi.hm.health",
        "appplatform": "android_phone",
    }
    tp_candidates = [
        f"https://api-mifit-cn3.zepp.com/v1/user/thirdparty.json?userid={userid}",
        f"https://api-mifit-cn3.zepp.com/v1/user/third_party.json?userid={userid}",
        f"https://api-mifit-cn.huami.com/v1/user/thirdparty.json?userid={userid}",
        f"https://api-user.zepp.com/v1/user/thirdparty.json?userid={userid}",
        f"https://api-mifit-cn3.zepp.com/huami.health.getThirdPartyInfo.json?userid={userid}",
        f"https://api-mifit-cn3.zepp.com/v1/user/thirdparty_bind.json?userid={userid}",
    ]
    for url2 in tp_candidates:
        try:
            r2 = requests.get(url2, headers=h2, timeout=10)
        except Exception as e:
            print(f"第三方接入[{url2.split('/')[2]}{url2.split('/')[3][:28]}]: 异常 {type(e).__name__}")
            continue
        if r2.status_code != 200:
            print(f"第三方接入[{url2.split('/')[2]}{url2.split('/')[3][:28]}]: HTTP {r2.status_code}")
            continue
        j2 = r2.json()
        items = _extract_items(j2)
        if items:
            print(f"★ 第三方接入命中: {url2}")
            for it in items[:8]:
                if isinstance(it, dict):
                    print(f"  - {json.dumps(it, ensure_ascii=False)[:180]}")
                else:
                    print(f"  - {str(it)[:120]}")
            out["third_party"] = items
            out["third_party_url"] = url2
            break
        else:
            print(f"第三方接入[{url2.split('/')[2]}{url2.split('/')[3][:28]}]: HTTP 200 但无条目")
    if "third_party" not in out:
        print("  （所有候选路径均未返回绑定信息）")

    # ---------- 3. 各设备源的当日步数（多设备冲突排查） ----------
    # 账号下若绑了多个设备，微信运动取的是"最高值"数据源，
    # 未启用/未激活的设备可能仍以真实步数参与计算，从而盖掉我们写入的虚拟设备步数。
    try:
        # 同时尝试多个主机，Zepp 官方当前使用 api-mifit.zepp.com
        h3 = {
            "apptoken": app_token,
            "User-Agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
            "appname": "com.xiaomi.hm.health",
            "appplatform": "android_phone",
        }
        j3 = None
        for host in ("https://api-mifit.zepp.com",
                     "https://api-mifit-cn.zepp.com",
                     "https://api-mifit-cn.huami.com"):
            u = host + "/v1/data/band_data.json?" + urllib.parse.urlencode({
                "query_type": "summary",
                "device_type": "android_phone",
                "userid": userid,
                "from_date": get_beijing_time().strftime("%F"),
                "to_date": get_beijing_time().strftime("%F"),
            })
            try:
                rr = requests.get(u, headers=h3, timeout=15)
            except Exception:
                continue
            if rr.status_code != 200:
                continue
            try:
                jj = rr.json()
            except Exception:
                continue
            if _extract_items(jj):
                j3 = jj
                print(f"设备源查询命中主机: {host}")
                break
        if j3 is not None:
            its = _extract_items(j3)
            print(f"\n设备源步数明细（共 {len(its)} 条）：")
            for it in its:
                if not isinstance(it, dict):
                    continue
                # 真实字段名是 device_id / date_time（不是 did / date）
                did = (it.get("device_id") or it.get("did") or it.get("deviceId") or "?")
                dtime = it.get("date_time") or it.get("date")
                ttl = None
                sm = it.get("summary")
                if isinstance(sm, str):
                    try:
                        pad = (-len(sm)) % 4
                        s2 = json.loads(base64.b64decode(sm + "=" * pad).decode("utf-8"))
                        ttl = (s2.get("stp") or {}).get("ttl")
                    except Exception:
                        try:
                            s2 = json.loads(urllib.parse.unquote(sm).replace('\\"', '"'))
                            ttl = (s2.get("stp") or {}).get("ttl")
                        except Exception:
                            pass
                elif isinstance(sm, dict):
                    ttl = (sm.get("stp") or {}).get("ttl")
                src = it.get("source", it.get("src", "?"))
                # 完整打印条目，便于人工确认设备ID/日期等字段的真实名称
                brief = {k: v for k, v in it.items() if k != "summary"}
                print(f"  设备 {did}: 步数={ttl} source={src} date={dtime}")
                print(f"    条目全字段: {json.dumps(brief, ensure_ascii=False)[:300]}")
            out["device_sources"] = its
        else:
            print("设备源步数明细: 所有主机均无数据")
    except Exception as e:
        print(f"设备源步数明细异常: {type(e).__name__} {str(e)[:100]}")

    return out


# ============================================================================
# Web 身份登录（不顶掉手机端 Zepp Life）
#
# 顶号的根因：原实现以【安卓手机身份】登录
#   app_name=com.xiaomi.hm.health, device_model=android_phone
# 华米侧把同一账号的会话与手机 App 绑定，脚本每次全新登录都会把手机端挤下线。
#
# 解决方案：改用【Web 身份】登录（与 user.zepp.com 网页端同一套流程）：
#   app_name=com.huami.webapp, device_model=web, device_id=web_<uuid>
#   配合 origin/referer=https://user.zepp.com
# 这样脚本会话与手机 App 会话相互独立，不会互相顶号。
# 参考实现：amazfit-mcp / zepp-downloader 的 web-app 登录流程。
# ============================================================================

WEB_APP_NAME = "com.huami.webapp"
WEB_REDIRECT_URI = "https://s3-us-west-2.amazonaws.com/hm-registration/successsignin.html"
WEB_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
WEB_DN = "api-mifit.zepp.com,api-user.zepp.com,api-watch.zepp.com,auth.zepp.com"


def login_web_tokens(user, password, country_code="CN"):
    """以 Web 身份登录，返回 (app_token, login_token, user_id, error)。

    流程（三步）：
      1. POST api-user.huami.com/registrations/{email}/tokens  -> 拿 access code
      2. POST api-mifit.zepp.com/v2/client/login                 -> 拿 login_token + user_id
      3. GET  api-mifit.zepp.com/v1/client/app_tokens            -> 拿 app_token
    """
    try:
        # ---- 1. 注册换取 access code ----
        reg_headers = {
            "app_name": WEB_APP_NAME,
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://user.zepp.com",
            "referer": "https://user.zepp.com/",
            "x-request-id": str(uuid.uuid4()),
            "user-agent": WEB_UA,
        }
        reg_data = {
            "client_id": "HuaMi",
            "country_code": country_code,
            "json_response": "true",
            "name": user,
            "password": password,
            "redirect_uri": WEB_REDIRECT_URI,
            "state": "REDIRECTION",
            "token": "access",
        }
        r1 = requests.post(
            f"https://api-user.huami.com/registrations/{urllib.parse.quote(user, safe='')}/tokens",
            data=reg_data, headers=reg_headers, allow_redirects=False, timeout=20)

        access_code = None
        location = r1.headers.get("Location", "")
        if location:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
            access_code = (qs.get("access") or [None])[0]
        if not access_code and r1.status_code == 200:
            try:
                access_code = r1.json().get("access") or r1.json().get("code")
            except Exception:
                pass
        if not access_code:
            return None, None, None, f"Web登录失败(注册步骤) HTTP {r1.status_code}"

        # ---- 2. access code 换 login_token + user_id ----
        login_headers = {
            "app_name": WEB_APP_NAME,
            "appname": WEB_APP_NAME,
            "appplatform": "web",
            "origin": "https://user.zepp.com",
            "referer": "https://user.zepp.com/",
            "user-agent": WEB_UA,
        }
        login_data = {
            "allow_registration": "false",
            "app_name": WEB_APP_NAME,
            "app_version": "1.0.0",
            "code": access_code,
            "country_code": country_code,
            "device_id": f"web_{uuid.uuid4()}",
            "device_model": "web",
            "dn": WEB_DN,
            "grant_type": "access_token",
            "source": WEB_APP_NAME,
            "third_name": "huami",
        }
        r2 = requests.post("https://api-mifit.zepp.com/v2/client/login",
                           data=login_data, headers=login_headers, timeout=20)
        try:
            token_info = (r2.json() or {}).get("token_info") or {}
        except Exception:
            token_info = {}
        login_token = token_info.get("login_token")
        user_id = token_info.get("user_id")
        if not login_token or not user_id:
            return None, None, None, f"Web登录失败(换取token步骤) HTTP {r2.status_code}"

        # ---- 3. login_token 换 app_token ----
        r3 = requests.get(
            "https://api-mifit.zepp.com/v1/client/app_tokens",
            params={"app_name": WEB_APP_NAME, "dn": WEB_DN, "login_token": login_token},
            headers=login_headers, timeout=20)
        try:
            app_token = ((r3.json() or {}).get("token_info") or {}).get("app_token")
        except Exception:
            app_token = None
        if not app_token:
            return None, None, None, f"Web登录失败(换取app_token步骤) HTTP {r3.status_code}"

        return app_token, login_token, str(user_id), None
    except Exception as e:
        return None, None, None, f"Web登录异常: {type(e).__name__} {str(e)[:120]}"


def renew_login_token_web(login_token) -> (str | None, str | None):
    """续期【Web 身份】的 login_token。

    与 renew_login_token（手机身份）对应的 Web 版本，
    用于 Web 身份登录后 token 过期时的无感续期（不创建新会话、不顶号）。
    """
    url = "https://api-mifit.zepp.com/v1/client/renew_login_token"
    headers = {
        "app_name": WEB_APP_NAME,
        "appname": WEB_APP_NAME,
        "appplatform": "web",
        "origin": "https://user.zepp.com",
        "referer": "https://user.zepp.com/",
        "user-agent": WEB_UA,
        "x-request-id": str(uuid.uuid4()),
    }
    params = {
        "os_version": "v1.0.0",
        "dn": WEB_DN,
        "login_token": login_token,
        "source": WEB_APP_NAME,
        "timestamp": get_time(),
    }
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
    except Exception as e:
        return None, f"请求异常：{type(e).__name__}"
    if resp.status_code != 200:
        return None, f"请求异常：HTTP {resp.status_code}"
    try:
        body = resp.json()
    except Exception:
        return None, f"响应非JSON：{resp.text[:120]}"

    token_info = {}
    if isinstance(body, dict):
        token_info = body.get("token_info") or {}
        if not token_info and "login_token" in body:
            token_info = body
    if not isinstance(token_info, dict):
        token_info = {}
    login_token_new = token_info.get("login_token")
    if not login_token_new:
        result = body.get("result") if isinstance(body, dict) else None
        if result is not None and result != "ok":
            return None, f"请求失败：{result}"
        return None, f"响应中无login_token：{str(body)[:150]}"
    return login_token_new, None


def _build_submit_attempts(base_url, base_head, app_token, compat=None):
    """构造提交步数的「域名 × 请求头」组合列表。

    Web 身份登录拿到的 app_token 在提交 band_data 时可能报 500，
    原因是请求头里的身份标识（appname/appplatform）与 token 的签发身份不匹配。
    参考 amazfit-mcp 的做法：数据调用用【手机 App 的 header 身份】，
    即使 token 是 Web 签发的也能被接受。

    这里依次尝试若干组合，任一成功即可，全程打印尝试结果便于定位。
    """
    compat = compat or {}

    # 手机 App 身份的数据请求头（国内配置）
    app_data_head = {
        "hm-privacy-diagnostics": "false",
        "country": "CN",
        "appplatform": "android_phone",
        "hm-privacy-ceip": "true",
        "timezone": "Asia/Shanghai",
        "channel": "a100900101016",
        "vb": "202509151347",
        "cv": "50818_6.14.0",
        "appname": "com.xiaomi.hm.health",
        "v": "2.0",
        "lang": "zh_CN",
        "user-agent": "MiFit6.14.0 (M2007J1SC; Android 12; Density/2.75)",
        "accept-encoding": "gzip",
    }
    # 另一种 App 身份标识（部分接口认 com.huami.midong）
    midong_head = dict(app_data_head)
    midong_head["appname"] = "com.huami.midong"
    midong_head["user-agent"] = "Zepp/9.12.5 (Pixel 4; Android 12; Density/2.75)"
    # Web 身份请求头
    web_head = {
        "country": "CN",
        "appplatform": "web",
        "appname": WEB_APP_NAME,
        "app_name": WEB_APP_NAME,
        "origin": "https://user.zepp.com",
        "referer": "https://user.zepp.com/",
        "user-agent": WEB_UA,
        "accept-encoding": "gzip",
    }

    def mk(head_extra):
        h = dict(base_head)
        h.update(head_extra)
        h["apptoken"] = app_token
        return h

    t = get_time()
    hosts = [
        ("cn", "https://api-mifit-cn.huami.com"),
        ("zepp", "https://api-mifit.zepp.com"),
        ("cn3", "https://api-mifit-cn3.zepp.com"),
    ]
    if compat.get("cn2"):
        hosts.insert(0, ("cn2", "https://api-mifit-cn2.huami.com"))

    attempts = []
    # 1) 首选：cn 域名 + 完整手机 App 请求头
    #    【已实测可用】Web 签发的 app_token 必须搭配手机 App 的身份请求头，
    #    否则 band_data 接口返回 500（-50000 Failed to process the request）。
    #    参考 amazfit-mcp：数据调用用 Android-app header 身份，
    #    即使 token 是 web-app 签发的也能被接受。
    cn_host = "https://api-mifit-cn.huami.com"
    attempts.append(("cn+app头",
                     f"{cn_host}/v1/data/band_data.json?&t={t}&r={uuid.uuid4()}",
                     mk(app_data_head)))
    # 2) 原样（精简 header）+ 原域名 —— 兼容手机身份签发的 token
    attempts.append(("原样", base_url, mk({})))
    # 3) 其余域名 + 完整 App header（备用）
    for tag, host in hosts:
        if host == cn_host:
            continue
        attempts.append((f"{tag}+app头",
                         f"{host}/v1/data/band_data.json?&t={t}&r={uuid.uuid4()}",
                         mk(app_data_head)))
    # 4) midong 身份头
    attempts.append(("zepp+midong头",
                     "https://api-mifit.zepp.com/v1/data/band_data.json?&t={t}&r={uuid.uuid4()}",
                     mk(midong_head)))
    # 5) Web 身份头
    attempts.append(("zepp+web头",
                     "https://api-mifit.zepp.com/v1/data/band_data.json?&t={t}&r={uuid.uuid4()}",
                     mk(web_head)))
    return attempts
