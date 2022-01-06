#!/usr/bin/env python3

#
# SPDX-FileCopyrightText: (c) 2020-2021 CokeMine & Its repository contributors
# SPDX-FileCopyrightText: (c) 2021 A beam of light
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

"""
euserv auto-renew script

ChangeLog

v2021.09.30
- Captcha automatic recognition using TrueCaptcha API
- Email notification
- Add login failure retry mechanism
- reformat log info

v2021.11.06
- Receive renew PIN(6-digits) using mailparser parsed data download url
  workflow: auto-forward your EUserv PIN email to your mailparser inbox 
  -> parsing PIN via mailparser -> get PIN from mailparser
- Update kc2_security_password_get_token request

v2021.11.26
- Handle TrueCaptcha service exception
- Adjust TrueCaptcha constraint parameters for high availability.
  Plus, the CAPTCHA of EUserv is currently case-insensitive, so the above adjustment works.

v2021.12.15
- Implemented a simple localization system, log output localization
- Reformat code via black

"""

import os
import re
import json
import time
import base64

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP_SSL, SMTPDataError

import requests
from bs4 import BeautifulSoup

# Please use one space to separate multiple accounts
# euserv username or email
USERNAME = os.environ["USERNAME"]
# euserv password
PASSWORD = os.environ["PASSWORD"]

# default value is TrueCaptcha demo credential,
# you can use your own credential via set environment variables:
# TRUECAPTCHA_USERID and TRUECAPTCHA_APIKEY
# demo: https://apitruecaptcha.org/demo
# demo2: https://apitruecaptcha.org/demo2
# demo apikey also has a limit of 100 times per day
# {
# 'error': '101.0 above free usage limit 100 per day and no balance',
# 'requestId': '7690c065-70e0-4757-839b-5fd8381e65c7'
# }
TRUECAPTCHA_USERID = os.environ.get("TRUECAPTCHA_USERID", "arun56")
TRUECAPTCHA_APIKEY = os.environ.get("TRUECAPTCHA_APIKEY", "wMjXmBIcHcdYqO2RrsVN")

# Extract key data from your emails, automatically. https://mailparser.io
# 30 Emails/Month, 10 inboxes and unlimited downloads for free.
# Please use one space to separate multiple mailparser download link ids,
# in order to correspond to the EUserv account/email.
MAILPARSER_DOWNLOAD_URL_ID = os.environ["MAILPARSER_DOWNLOAD_URL_ID"]
# mailparser parsed data download base url
MAILPARSER_DOWNLOAD_BASE_URL = "https://files.mailparser.io/d/"

# Telegram Bot Push https://core.telegram.org/bots/api#authorizing-your-bot
# Obtained via @BotFather application, for example: 1077xxx4424:AAFjv0FcqxxxxxxgEMGfi22B4yh15R5uw
TG_BOT_TOKEN = ""
# User, group or channel ID, for example: 129xxx206
TG_USER_ID = ""
# Build your own API reverse proxy address for use when the network environment is inaccessible,
# and keep the default if the network is normal.
TG_API_HOST = "https://api.telegram.org"

# Email notification via yandex service, you can modify yourself to use other email service notifications.
RECEIVER_EMAIL = os.environ.get("RECEIVER_EMAIL", "")
YD_EMAIL = os.environ.get("YD_EMAIL", "")
# yandex mail using third party APP authorization code
YD_APP_PWD = os.environ.get("YD_APP_PWD", "")

# Server Chan(Server 酱, name in Chinese) https://sct.ftqq.com
# Free quota: up to 5 messages per day, cards show only title, maximum 1000 API requests per day, up to 5 messages per minute.
# Server Chan SENDKEY, no need to push can be ignored
SERVER_CHAN_SENDKEY = os.environ.get("SERVER_CHAN_SENDKEY", "")

# Magic internet access
PROXIES = {"http": "http://127.0.0.1:10808", "https": "http://127.0.0.1:10808"}

# Maximum number of login retry
LOGIN_MAX_RETRY_COUNT = 5

# Waiting time of receiving PIN, units are seconds.
WAITING_TIME_OF_PIN = 15

# Checking CAPTCHA API usage, options: True or False
CHECK_CAPTCHA_SOLVER_USAGE = True

user_agent = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/96.0.4664.110 Safari/537.36"
)

# Blank
desp = ""

# Simplified Chinese Translation
chs_locale = {
    ":": "：",
    ",": "，",
    ".": "。",
    "!": "！",
    "...": "......",
    "~": "~",
    "Login retried the @@@ time": "登录重试第 @@@ 次",
    "You are using the demo apikey": "你正在使用演示版 apikey",
    "There is no guarantee that demo apikey will work in the future": "无法保证演示版 apikey 在将来也能使用",
    "You are using your own apikey": " 你正在使用自己的 apikey",
    "Service Exception": "服务异常",
    "Returned JSON": "返回的 JSON",
    "Failed to find parsed results": "找不到解析结果",
    "Performing CAPTCHA recognition": "进行验证码识别",
    "The recognized CAPTCHA is": "识别的验证码是",
    "current date": "当前日期",
    "api usage count": "api 使用次数",
    "CAPTCHA Verification passed": "CAPTCHA 验证通过",
    "CAPTCHA Verification failed": "CAPTCHA 验证失败",
    "PIN": "PIN",
    "ServerID": "服务器 ID",
    "Renew Failed": "续期失败",
    "ALL Work Done": "所有工作都已完成",
    "Enjoy": "使用愉快",
    "EUserv Renewal Logs": "EUserv 续期日志",
    "push failed": "推送失败",
    "push successfully": "推送成功",
    "Server Chan": "Server 酱",
    "Checking": "正在检查",
    "You have not added any accounts": "你没有添加任何账户",
    "The number of usernames and passwords do not match": "用户名和密码的数量不匹配",
    "The number of mailparser_dl_url_ids and usernames do not match": "mailparser 下载链接 id 和用户名的数量不匹配",
    "Renewing the @@@ account": "正在续期第 @@@ 个账号",
    "The @@@ account login failed": "第 @@@ 个账号登录失败",
    "please check the login information": "请检查登录信息",
    "renewals are being attempted": "正在尝试续期",
    "The @@@ account is detected": "检测到第 @@@ 个账号",
    "with @@@ VPS": "有 @@@ 台 VPS",
    "renew Error": "续期错误",
    "has been successfully renewed": "已成功续期",
    "does not need to be renewed": "不需要续期",
}

# Traditional Chinese Translation
cht_locale = {
    ":": "：",
    ",": "，",
    ".": "。",
    "!": "！",
    "...": "......",
    "~": "~",
    "Login retried the @@@ time": "登錄重試第 @@@ 次",
    "You are using the demo apikey": "你正在使用演示版 apikey",
    "There is no guarantee that demo apikey will work in the future": "無法保證演示版 apikey 在將來也能使用",
    "You are using your own apikey": " 你正在使用你自己的 apikey",
    "Service Exception": "服務異常",
    "Returned JSON": "返回的 JSON",
    "Failed to find parsed results": "找不到解析結果",
    "Performing CAPTCHA recognition": "進行驗證碼識別",
    "The recognized CAPTCHA is": "識別的驗證碼是",
    "current date": "當前日期",
    "api usage count": "api 已使用次數",
    "CAPTCHA Verification passed": "CAPTCHA 驗證通過",
    "CAPTCHA Verification failed": "CAPTCHA 驗證失敗",
    "PIN": "PIN",
    "ServerID": "伺服器 ID",
    "Renew Failed": "續期失敗",
    "ALL Work Done": "所有工作都已完成",
    "Enjoy": "使用愉快",
    "EUserv Renewal Logs": "EUserv 續期日誌",
    "push failed": "推送失敗",
    "push successfully": "推送成功",
    "Server Chan": "Server 醬",
    "Checking": "正在檢查",
    "You have not added any accounts": "你沒有新增任何賬戶",
    "The number of usernames and passwords do not match": "使用者名稱和密碼的數量不匹配",
    "The number of mailparser_dl_url_ids and usernames do not match": "mailparser 下載連結 id 和使用者名稱的數量不匹配",
    "Renewing the @@@ account": "正在續期第 @@@ 個賬號",
    "The @@@ account login failed": "第 @@@ 個賬號登入失敗",
    "please check the login information": "請檢查登入資訊",
    "renewals are being attempted": "正在嘗試續期",
    "The @@@ account is detected": "檢測到第 @@@ 個賬號",
    "with @@@ VPS": "有 @@@ 臺 VPS",
    "renew Error": "續期錯誤",
    "has been successfully renewed": "已成功續期",
    "does not need to be renewed": "不需要續期",
}

# Localization
log_lang_options = {
    "en": lambda x: x,
    "chs": lambda x: chs_locale.get(x, x),
    "cht": lambda x: cht_locale.get(x, x),
}

# Language Options: en/chs/cht, or leave it blank
log_lang = "chs"

ordinal = lambda n: "{}{}".format(
    n,
    "tsnrhtdd"[(n / 10 % 10 != 1) * (n % 10 < 4) * n % 10 :: 4],
)


def log(info: str):
    print(info)
    global desp
    desp = desp + info + "\n\n"


def login_retry(*args, **kwargs):
    def wrapper(func):
        def inner(username, password):
            ret, ret_session = func(username, password)
            max_retry = kwargs.get("max_retry")
            # default retry 3 times
            if not max_retry:
                max_retry = 3
            number = 0
            if ret == "-1":
                while number < max_retry:
                    number += 1
                    if number > 1:
                        log(
                            "[EUserv] {} {}".format(
                                log_lang_options.get(log_lang, lambda x: x)(
                                    "Login retried the @@@ time"
                                ).replace("@@@", ordinal(number)),
                                log_lang_options.get(log_lang, lambda x: x)("."),
                            )
                        )
                    sess_id, session = func(username, password)
                    if sess_id != "-1":
                        return sess_id, session
                    else:
                        if number == max_retry:
                            return sess_id, session
            else:
                return ret, ret_session

        return inner

    return wrapper


def captcha_solver(captcha_image_url: str, session: requests.session) -> dict:
    """
    TrueCaptcha API doc: https://apitruecaptcha.org/api
    Free to use 100 requests per day.
    -- response::
    {
        "result": "", ==> Or "result": 0
        "conf": 0.85,
        "usage": 0,
        "requestId": "ed0006e5-69f0-4617-b698-97dc054f9022",
        "version": "dev2"
    }
    """
    response = session.get(captcha_image_url)
    encoded_string = base64.b64encode(response.content)
    url = "https://api.apitruecaptcha.org/one/gettext"

    # Since "case": "mixed", "mode": "human"
    # can sometimes cause internal errors in the truecaptcha server.
    # So a more relaxed constraint(lower/upper & default) is used here.
    # Plus, the CAPTCHA of EUserv is currently case-insensitive, so the below adjustment works.
    data = {
        "userid": TRUECAPTCHA_USERID,
        "apikey": TRUECAPTCHA_APIKEY,
        # case sensitivity of text (upper | lower| mixed)
        "case": "lower",
        # use human or AI (human | default)
        "mode": "default",
        "data": str(encoded_string)[2:-1],
    }
    r = requests.post(url=url, json=data)
    j = json.loads(r.text)
    return j


def handle_captcha_solved_result(solved: dict) -> str:
    """Since CAPTCHA sometimes appears as a very simple binary arithmetic expression.
    But since recognition sometimes doesn't show the result of the calculation directly,
    that's what this function is for.
    """
    if "result" in solved:
        solved_result = solved["result"]
        if isinstance(solved_result, str):
            if "RESULT  IS" in solved_result:
                log(
                    "[Captcha Solver] {}{}".format(
                        log_lang_options.get(log_lang, lambda x: x)(
                            "You are using the demo apikey"
                        ),
                        log_lang_options.get(log_lang, lambda x: x)("."),
                    )
                )
                print(
                    "{}{}".format(
                        log_lang_options.get(log_lang, lambda x: x)(
                            "There is no guarantee that demo apikey will work in the future"
                        ),
                        log_lang_options.get(log_lang, lambda x: x)("!"),
                    )
                )
                # because using demo apikey
                text = re.findall(r"RESULT  IS . (.*) .", solved_result)[0]
            else:
                # using your own apikey
                log(
                    "[Captcha Solver] {}{}".format(
                        log_lang_options.get(log_lang, lambda x: x)(
                            "You are using your own apikey"
                        ),
                        log_lang_options.get(log_lang, lambda x: x)("."),
                    )
                )
                text = solved_result
            operators = ["X", "x", "+", "-"]
            if any(x in text for x in operators):
                for operator in operators:
                    operator_pos = text.find(operator)
                    if operator == "x" or operator == "X":
                        operator = "*"
                    if operator_pos != -1:
                        left_part = text[:operator_pos]
                        right_part = text[operator_pos + 1 :]
                        if left_part.isdigit() and right_part.isdigit():
                            return eval(
                                "{left} {operator} {right}".format(
                                    left=left_part, operator=operator, right=right_part
                                )
                            )
                        else:
                            # Because these symbols("X", "x", "+", "-") do not appear at the same time,
                            # it just contains an arithmetic symbol.
                            return text
            else:
                return text
        else:
            print(
                "[Captcha Solver] {}{} {}".format(
                    log_lang_options.get(log_lang, lambda x: x)("Returned JSON"),
                    log_lang_options.get(log_lang, lambda x: x)(":"),
                    solved,
                )
            )
            log(
                "[Captcha Solver] {}{}".format(
                    log_lang_options.get(log_lang, lambda x: x)("Service Exception"),
                    log_lang_options.get(log_lang, lambda x: x)("!"),
                )
            )
            raise ValueError("[Captcha Solver] Service Exception!")
    else:
        print(
            "[Captcha Solver] {}{} {}".format(
                log_lang_options.get(log_lang, lambda x: x)("Returned JSON"),
                log_lang_options.get(log_lang, lambda x: x)(":"),
                solved,
            )
        )
        log(
            "[Captcha Solver] {}{}".format(
                log_lang_options.get(log_lang, lambda x: x)(
                    "Failed to find parsed results"
                ),
                log_lang_options.get(log_lang, lambda x: x)("!"),
            )
        )
        raise KeyError("[Captcha Solver] Failed to find parsed results!")


def get_captcha_solver_usage() -> dict:
    url = "https://api.apitruecaptcha.org/one/getusage"

    params = {
        "username": TRUECAPTCHA_USERID,
        "apikey": TRUECAPTCHA_APIKEY,
    }
    r = requests.get(url=url, params=params)
    j = json.loads(r.text)
    return j


def get_pin_from_mailparser(url_id: str) -> str:
    """
    response format:
    [
      {
        "id": "83b95f50f6202fb03950afbe00975eab",
        "received_at": "2021-11-06 02:30:07",  ==> up to mailparser account timezone setting, here is UTC 0000.
        "processed_at": "2021-11-06 02:30:07",
        "pin": "123456"
      }
    ]
    """
    response = requests.get(
        f"{MAILPARSER_DOWNLOAD_BASE_URL}{url_id}",
        # Mailparser parsed data download using Basic Authentication.
        # auth=("<your mailparser username>", "<your mailparser password>")
    )
    pin = response.json()[0]["pin"]
    return pin


@login_retry(max_retry=LOGIN_MAX_RETRY_COUNT)
def login(username: str, password: str) -> (str, requests.session):
    headers = {"user-agent": user_agent, "origin": "https://www.euserv.com"}
    url = "https://support.euserv.com/index.iphp"
    captcha_image_url = "https://support.euserv.com/securimage_show.php"
    session = requests.Session()

    sess = session.get(url, headers=headers)
    sess_id = re.findall("PHPSESSID=(\\w{10,100});", str(sess.headers))[0]
    # visit png
    logo_png_url = "https://support.euserv.com/pic/logo_small.png"
    session.get(logo_png_url, headers=headers)

    login_data = {
        "email": username,
        "password": password,
        "form_selected_language": "en",
        "Submit": "Login",
        "subaction": "login",
        "sess_id": sess_id,
    }
    f = session.post(url, headers=headers, data=login_data)
    f.raise_for_status()

    if (
        f.text.find("Hello") == -1
        and f.text.find("Confirm or change your customer data here") == -1
    ):
        if (
            f.text.find(
                "To finish the login process please solve the following captcha."
            )
            == -1
        ):
            return "-1", session
        else:
            log(
                "[Captcha Solver] {}{}".format(
                    log_lang_options.get(log_lang, lambda x: x)(
                        "Performing CAPTCHA recognition"
                    ),
                    log_lang_options.get(log_lang, lambda x: x)("..."),
                )
            )
            solved_result = captcha_solver(captcha_image_url, session)
            try:
                captcha_code = handle_captcha_solved_result(solved_result)
                log(
                    "[Captcha Solver] {}{} {}".format(
                        log_lang_options.get(log_lang, lambda x: x)(
                            "The recognized CAPTCHA is"
                        ),
                        log_lang_options.get(log_lang, lambda x: x)(":"),
                        captcha_code,
                    )
                )

                if CHECK_CAPTCHA_SOLVER_USAGE:
                    usage = get_captcha_solver_usage()
                    log(
                        "[Captcha Solver] {} {} {}{} {}".format(
                            log_lang_options.get(log_lang, lambda x: x)("current date"),
                            usage[0]["date"],
                            log_lang_options.get(log_lang, lambda x: x)(
                                "api usage count"
                            ),
                            log_lang_options.get(log_lang, lambda x: x)(":"),
                            usage[0]["count"],
                        )
                    )

                f2 = session.post(
                    url,
                    headers=headers,
                    data={
                        "subaction": "login",
                        "sess_id": sess_id,
                        "captcha_code": captcha_code,
                    },
                )
                if (
                    f2.text.find(
                        "To finish the login process please solve the following captcha."
                    )
                    == -1
                ):
                    log(
                        "[Captcha Solver] {}".format(
                            log_lang_options.get(log_lang, lambda x: x)(
                                "CAPTCHA Verification passed"
                            )
                        )
                    )
                    return sess_id, session
                else:
                    log(
                        "[Captcha Solver] {}".format(
                            log_lang_options.get(log_lang, lambda x: x)(
                                "CAPTCHA Verification failed"
                            )
                        )
                    )
                    return "-1", session
            except (KeyError, ValueError):
                return "-1", session
    else:
        return sess_id, session


def get_servers(sess_id: str, session: requests.session) -> {}:
    d = {}
    url = "https://support.euserv.com/index.iphp?sess_id=" + sess_id
    headers = {"user-agent": user_agent, "origin": "https://www.euserv.com"}
    f = session.get(url=url, headers=headers)
    f.raise_for_status()
    soup = BeautifulSoup(f.text, "html.parser")
    for tr in soup.select(
        "#kc2_order_customer_orders_tab_content_1 .kc2_order_table.kc2_content_table tr"
    ):
        server_id = tr.select(".td-z1-sp1-kc")
        if not len(server_id) == 1:
            continue
        flag = (
            True
            if tr.select(".td-z1-sp2-kc .kc2_order_action_container")[0]
            .get_text()
            .find("Contract extension possible from")
            == -1
            else False
        )
        d[server_id[0].get_text()] = flag
    return d


def renew(
    sess_id: str,
    session: requests.session,
    password: str,
    order_id: str,
    mailparser_dl_url_id: str,
) -> bool:
    url = "https://support.euserv.com/index.iphp"
    headers = {
        "user-agent": user_agent,
        "Host": "support.euserv.com",
        "origin": "https://support.euserv.com",
        "Referer": "https://support.euserv.com/index.iphp",
    }
    data = {
        "Submit": "Extend contract",
        "sess_id": sess_id,
        "ord_no": order_id,
        "subaction": "choose_order",
        "choose_order_subaction": "show_contract_details",
    }
    session.post(url, headers=headers, data=data)

    # pop up 'Security Check' window, it will trigger 'send PIN' automatically.
    session.post(
        url,
        headers=headers,
        data={
            "sess_id": sess_id,
            "subaction": "show_kc2_security_password_dialog",
            "prefix": "kc2_customer_contract_details_extend_contract_",
            "type": "1",
        },
    )

    # # trigger 'Send new PIN to your Email-Address' (optional),
    # new_pin = session.post(url, headers=headers, data={
    #     "sess_id": sess_id,
    #     "subaction": "kc2_security_password_send_pin",
    #     "ident": f"kc2_customer_contract_details_extend_contract_{order_id}"
    # })
    # if not json.loads(new_pin.text)["rc"] == "100":
    #     print("new PIN Not Sended")
    #     return False

    # sleep WAITING_TIME_OF_PIN seconds waiting for mailparser email parsed PIN
    time.sleep(WAITING_TIME_OF_PIN)
    pin = get_pin_from_mailparser(mailparser_dl_url_id)
    log(
        "[MailParser] {}{} {}".format(
            log_lang_options.get(log_lang, lambda x: x)("PIN"),
            log_lang_options.get(log_lang, lambda x: x)(":"),
            pin,
        )
    )

    # using PIN instead of password to get token
    data = {
        "auth": pin,
        "sess_id": sess_id,
        "subaction": "kc2_security_password_get_token",
        "prefix": "kc2_customer_contract_details_extend_contract_",
        "type": 1,
        "ident": f"kc2_customer_contract_details_extend_contract_{order_id}",
    }
    f = session.post(url, headers=headers, data=data)
    f.raise_for_status()
    if not json.loads(f.text)["rs"] == "success":
        return False
    token = json.loads(f.text)["token"]["value"]
    data = {
        "sess_id": sess_id,
        "ord_id": order_id,
        "subaction": "kc2_customer_contract_details_extend_contract_term",
        "token": token,
    }
    session.post(url, headers=headers, data=data)
    time.sleep(5)
    return True


def check(sess_id: str, session: requests.session):
    print(
        "{}{}".format(
            log_lang_options.get(log_lang, lambda x: x)("Checking"),
            log_lang_options.get(log_lang, lambda x: x)("..."),
        )
    )
    d = get_servers(sess_id, session)
    flag = True
    for key, val in d.items():
        if val:
            flag = False
            log(
                "[EUserv] {}{} {} {}{}".format(
                    log_lang_options.get(log_lang, lambda x: x)("ServerID"),
                    log_lang_options.get(log_lang, lambda x: x)(":"),
                    key,
                    log_lang_options.get(log_lang, lambda x: x)("Renew Failed"),
                    log_lang_options.get(log_lang, lambda x: x)("!"),
                )
            )

    if flag:
        log(
            "[EUserv] {}{} {}{}".format(
                log_lang_options.get(log_lang, lambda x: x)("ALL Work Done"),
                log_lang_options.get(log_lang, lambda x: x)("!"),
                log_lang_options.get(log_lang, lambda x: x)("Enjoy"),
                log_lang_options.get(log_lang, lambda x: x)("~"),
            )
        )


# Telegram Bot Push https://core.telegram.org/bots/api#authorizing-your-bot
def telegram():
    data = (
        ("chat_id", TG_USER_ID),
        (
            "text",
            "{}\n\n".format(
                log_lang_options.get(log_lang, lambda x: x)("EUserv Renewal Logs")
            )
            + desp,
        ),
    )
    response = requests.post(
        TG_API_HOST + "/bot" + TG_BOT_TOKEN + "/sendMessage", data=data
    )
    if response.status_code != 200:
        print(
            "Telegram Bot {}".format(
                log_lang_options.get(log_lang, lambda x: x)("push failed")
            )
        )
    else:
        print(
            "Telegram Bot {}".format(
                log_lang_options.get(log_lang, lambda x: x)("push successfully")
            )
        )


# Yandex mail notification
def send_mail_by_yandex(
    to_email, from_email, subject, text, files, sender_email, sender_password
):
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.attach(MIMEText(text, _charset="utf-8"))
    if files is not None:
        for file in files:
            file_name, file_content = file
            # print(file_name)
            part = MIMEApplication(file_content)
            part.add_header(
                "Content-Disposition", "attachment", filename=("gb18030", "", file_name)
            )
            msg.attach(part)
    s = SMTP_SSL("smtp.yandex.ru", 465)
    s.login(sender_email, sender_password)
    try:
        s.sendmail(msg["From"], msg["To"], msg.as_string())
    except SMTPDataError as e:
        raise e
    finally:
        s.close()


# eMail push
def email():
    msg = (
        "{}\n\n".format(
            log_lang_options.get(log_lang, lambda x: x)("EUserv Renewal Logs")
        )
        + desp
    )
    try:
        send_mail_by_yandex(
            RECEIVER_EMAIL,
            YD_EMAIL,
            log_lang_options.get(log_lang, lambda x: x)("EUserv Renewal Logs"),
            msg,
            None,
            YD_EMAIL,
            YD_APP_PWD,
        )
        print(
            "eMail {}".format(
                log_lang_options.get(log_lang, lambda x: x)("push successfully")
            )
        )
    except requests.exceptions.RequestException as e:
        print(str(e))
        print(
            "eMail {}".format(
                log_lang_options.get(log_lang, lambda x: x)("push failed")
            )
        )
    except SMTPDataError as e1:
        print(str(e1))
        print(
            "eMail {}".format(
                log_lang_options.get(log_lang, lambda x: x)("push failed")
            )
        )


# Server Chan https://sct.ftqq.com
def server_chan():
    data = {
        "title": log_lang_options.get(log_lang, lambda x: x)("EUserv Renewal Logs"),
        "desp": desp,
    }
    response = requests.post(
        f"https://sctapi.ftqq.com/{SERVER_CHAN_SENDKEY}.send", data=data
    )
    if response.status_code != 200:
        print(
            "{} {}".format(
                log_lang_options.get(log_lang, lambda x: x)("Server Chan"),
                log_lang_options.get(log_lang, lambda x: x)("push failed"),
            )
        )
    else:
        print(
            "{} {}".format(
                log_lang_options.get(log_lang, lambda x: x)("Server Chan"),
                log_lang_options.get(log_lang, lambda x: x)("push successfully"),
            )
        )


if __name__ == "__main__":
    if not USERNAME or not PASSWORD:
        log(
            "[EUserv] {}{}".format(
                log_lang_options.get(log_lang, lambda x: x)(
                    "You have not added any accounts"
                ),
                log_lang_options.get(log_lang, lambda x: x)("."),
            )
        )
        exit(1)
    user_list = USERNAME.strip().split()
    passwd_list = PASSWORD.strip().split()
    mailparser_dl_url_id_list = MAILPARSER_DOWNLOAD_URL_ID.strip().split()
    if len(user_list) != len(passwd_list):
        log(
            "[EUserv] {}{}".format(
                log_lang_options.get(log_lang, lambda x: x)(
                    "The number of usernames and passwords do not match"
                ),
                log_lang_options.get(log_lang, lambda x: x)("!"),
            )
        )
        exit(1)
    if len(mailparser_dl_url_id_list) != len(user_list):
        log(
            "[Mailparser] {}{}".format(
                log_lang_options.get(log_lang, lambda x: x)(
                    "The number of mailparser_dl_url_ids and usernames do not match"
                ),
                log_lang_options.get(log_lang, lambda x: x)("!"),
            )
        )
        exit(1)
    for i in range(len(user_list)):
        print("*" * 30)
        log(
            "[EUserv] {}{}".format(
                log_lang_options.get(log_lang, lambda x: x)(
                    "Renewing the @@@ account"
                ).replace("@@@", ordinal(i + 1)),
                log_lang_options.get(log_lang, lambda x: x)("..."),
            )
        )
        sessid, s = login(user_list[i], passwd_list[i])
        if sessid == "-1":
            log(
                "[EUserv] {}{} {}{}".format(
                    log_lang_options.get(log_lang, lambda x: x)(
                        "The @@@ account login failed"
                    ).replace("@@@", ordinal(i + 1)),
                    log_lang_options.get(log_lang, lambda x: x)(","),
                    log_lang_options.get(log_lang, lambda x: x)(
                        "please check the login information"
                    ),
                    log_lang_options.get(log_lang, lambda x: x)("."),
                )
            )
            continue
        SERVERS = get_servers(sessid, s)
        log(
            "[EUserv] {} {}{} {}{}".format(
                log_lang_options.get(log_lang, lambda x: x)(
                    "The @@@ account is detected"
                ).replace("@@@", ordinal(i + 1)),
                log_lang_options.get(log_lang, lambda x: x)("with @@@ VPS").replace(
                    "@@@", str(len(SERVERS))
                ),
                log_lang_options.get(log_lang, lambda x: x)(","),
                log_lang_options.get(log_lang, lambda x: x)(
                    "renewals are being attempted"
                ),
                log_lang_options.get(log_lang, lambda x: x)("..."),
            )
        )
        for k, v in SERVERS.items():
            if v:
                if not renew(
                    sessid, s, passwd_list[i], k, mailparser_dl_url_id_list[i]
                ):
                    log(
                        "[EUserv] {}{} {} {}{}".format(
                            log_lang_options.get(log_lang, lambda x: x)("ServerID"),
                            log_lang_options.get(log_lang, lambda x: x)(":"),
                            k,
                            log_lang_options.get(log_lang, lambda x: x)("renew Error"),
                            log_lang_options.get(log_lang, lambda x: x)("!"),
                        )
                    )
                else:
                    log(
                        "[EUserv] {}{} {} {}{}".format(
                            log_lang_options.get(log_lang, lambda x: x)("ServerID"),
                            log_lang_options.get(log_lang, lambda x: x)(":"),
                            k,
                            log_lang_options.get(log_lang, lambda x: x)(
                                "has been successfully renewed"
                            ),
                            log_lang_options.get(log_lang, lambda x: x)("!"),
                        )
                    )
            else:
                log(
                    "[EUserv] {}{} {} {}{}".format(
                        log_lang_options.get(log_lang, lambda x: x)("ServerID"),
                        log_lang_options.get(log_lang, lambda x: x)(":"),
                        k,
                        log_lang_options.get(log_lang, lambda x: x)(
                            "does not need to be renewed"
                        ),
                        log_lang_options.get(log_lang, lambda x: x)("."),
                    )
                )
        time.sleep(15)
        check(sessid, s)
        time.sleep(5)

    TG_BOT_TOKEN and TG_USER_ID and TG_API_HOST and telegram()
    RECEIVER_EMAIL and YD_EMAIL and YD_APP_PWD and email()
    SERVER_CHAN_SENDKEY and server_chan()

    print("*" * 30)
