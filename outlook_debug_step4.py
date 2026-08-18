import json
import re
import uuid
import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup


# ============================================================
# Outlook Signup Diagnostic Client
#
# Step 1
#   GET /signup?lic=1
#
# Step 2
#   POST /API/CheckAvailableSigninNames?lic=1
#
# Step 3
#   POST /API/CreateAccount?lic=1
#   302 -> error.aspx -> HTML -> var t0={...}
#
# Step 4.1
#   POST https://login.microsoftonline.com/{tenant}/api/v1.0/risk/initialize
#   读取 continuationToken / riskInitializationData
#
# 当前版本是协议/响应调试版本：
#   - 不自动求解 CAPTCHA
#   - 不提交 challenge solution
#   - 不自动完成账号注册
# ============================================================


SIGNUP_URL = "https://signup.live.com/signup"
SIGNUP_API = "https://signup.live.com"

CLIENT_ID = "9199bf20-a13f-4107-85dc-02114787ef48"
COBRAND_ID = "ab0455a0-8d03-46b9-b18b-df2f57b9e44c"

ARKOSE_PK_DEFAULT = (
    "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"
)

# 从你前面真实抓包中确认的 Microsoft Consumer tenant。
DEFAULT_TENANT_ID = (
    "9188040d-6c67-4c5b-b112-36a304b66dad"
)

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36"
)

DEBUG_DIR = Path("debug")
DEBUG_DIR.mkdir(exist_ok=True)


# ============================================================
# Utility
# ============================================================

def save_text(filename, text):
    path = DEBUG_DIR / filename
    path.write_text(text, encoding="utf-8")
    print(f"[DEBUG] Saved: {path}")


def save_json(filename, data):
    path = DEBUG_DIR / filename
    path.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )
    print(f"[DEBUG] Saved: {path}")


def find_value(obj, key):
    """递归查找 JSON 中指定字段。"""

    if isinstance(obj, dict):
        if key in obj:
            return obj[key]

        for value in obj.values():
            result = find_value(value, key)
            if result is not None:
                return result

    elif isinstance(obj, list):
        for value in obj:
            result = find_value(value, key)
            if result is not None:
                return result

    return None


def extract_server_data(html):
    """从 signup 页面提取 ServerData。"""

    patterns = [
        r'window\.ServerData\s*=\s*(\{.*?\});',
        r'var\s+ServerData\s*=\s*(\{.*?\});',
        r'ServerData\s*=\s*(\{.*?\});',
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.S)

        if not match:
            continue

        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    soup = BeautifulSoup(html, "html.parser")

    for script in soup.find_all("script"):
        text = script.string or script.get_text()

        if "ServerData" not in text:
            continue

        match = re.search(
            r'ServerData\s*=\s*(\{.*?\});',
            text,
            re.S
        )

        if not match:
            continue

        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            continue

    return None


def extract_t0(html):
    """
    从 CreateAccount/error.aspx 返回 HTML 中提取：

        var t0={...};
    """

    patterns = [
        r'var\s+t0\s*=\s*(\{.*?\});',
        r'window\.t0\s*=\s*(\{.*?\});',
        r't0\s*=\s*(\{.*?\});',
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.S)

        if not match:
            continue

        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    return None


def utc_timestamp():
    now = datetime.datetime.now(datetime.timezone.utc)

    return (
        now.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{now.microsecond // 1000:03d}Z"
    )


# ============================================================
# Client
# ============================================================

class OutlookSignupClient:

    def __init__(
        self,
        proxy=None,
        email_suffix="@outlook.com",
        tenant_id=DEFAULT_TENANT_ID
    ):
        self.proxy = proxy
        self.email_suffix = email_suffix

        self.session = None

        # 动态注册状态
        self.uaid = ""
        self.api_canary = ""

        self.hpgid = 200225
        self.scid = 100118
        self.uiflvr = 1001

        self.opid = ""
        self.contextid = ""

        # telemetry
        self.telemetry_context = ""

        # Step 3 / t0
        self.tenant_id = tenant_id or ""

        # Step 4.1
        self.continuation_token = ""
        self.risk_session_id = ""
        self.risk_provider = ""
        self.human_sensor_url = ""

        self.arkose_pk = ARKOSE_PK_DEFAULT

    # ========================================================
    # Session
    # ========================================================

    def create_session(self):
        session = requests.Session()

        session.headers.update({
            "User-Agent": CHROME_UA,
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

        if self.proxy:
            session.proxies.update({
                "http": self.proxy,
                "https": self.proxy,
            })

        return session

    # ========================================================
    # Signup URL parameters
    # ========================================================

    def build_params(self):
        sru = (
            "https://login.live.com/"
            "oauth20_authorize.srf"
            "?lc=2052"
            f"&client_id={CLIENT_ID}"
            f"&cobrandid={COBRAND_ID}"
            "&mkt=ZH-CN"
            f"&opid={self.opid}"
            "&opidt=0"
            f"&uaid={self.uaid}"
            f"&contextid={self.contextid}"
        )

        return {
            "sru": sru,
            "mkt": "ZH-CN",
            "uiflavor": "web",
            "fl": "dob,flname,wld",
            "cobrandid": COBRAND_ID,
            "client_id": CLIENT_ID,
            "uaid": self.uaid,
            "suc": CLIENT_ID,
            "fluent": "2",
            "lic": "1",
        }

    # ========================================================
    # Common signup headers
    # ========================================================

    def common_headers(self):
        return {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "client-request-id": self.uaid,
            "hpgid": str(self.hpgid),
            "hpgact": "0",
            "canary": self.api_canary,
        }

    # ========================================================
    # Update state
    # ========================================================

    def update_canary(self, data):
        if not isinstance(data, dict):
            return

        value = (
            data.get("apiCanary")
            or find_value(data, "apiCanary")
        )

        if value:
            self.api_canary = value

    def update_from_t0(self, t0):
        if not isinstance(t0, dict):
            return

        api_canary = (
            t0.get("apiCanary")
            or find_value(t0, "apiCanary")
        )
        if api_canary:
            self.api_canary = api_canary

        hpgid = (
            t0.get("hpgid")
            or find_value(t0, "hpgid")
        )
        if hpgid is not None:
            try:
                self.hpgid = int(hpgid)
            except (TypeError, ValueError):
                pass

        scid = (
            t0.get("scid")
            or find_value(t0, "scid")
        )
        if scid is not None:
            try:
                self.scid = int(scid)
            except (TypeError, ValueError):
                pass

        uaid = (
            t0.get("uaid")
            or find_value(t0, "uaid")
        )
        if uaid:
            self.uaid = uaid

        uiflvr = (
            t0.get("uiflvr")
            or find_value(t0, "uiflvr")
        )
        if uiflvr is not None:
            try:
                self.uiflvr = int(uiflvr)
            except (TypeError, ValueError):
                pass

        # t0 中如果存在 telemetry
        client_telemetry = t0.get("clientTelemetry")
        if isinstance(client_telemetry, dict):
            tcxt = client_telemetry.get("tcxt")
            if tcxt:
                self.telemetry_context = tcxt

        # 尝试从 t0 提取 tenant
        tenant = (
            t0.get("sTenantId")
            or t0.get("tenantId")
            or find_value(t0, "sTenantId")
        )
        if tenant:
            self.tenant_id = tenant

    # ========================================================
    # Step 1
    # ========================================================

    def step1_init(self):
        print()
        print("=" * 70)
        print("STEP 1: Init session")
        print("=" * 70)

        self.opid = uuid.uuid4().hex[:8].upper()
        self.contextid = uuid.uuid4().hex[:16].upper()
        self.uaid = uuid.uuid4().hex

        self.session = self.create_session()

        try:
            response = self.session.get(
                SIGNUP_URL,
                params=self.build_params(),
                timeout=30,
                allow_redirects=True
            )
        except requests.RequestException as e:
            print("[ERROR] Step1:", e)
            return False

        print("HTTP:", response.status_code)
        print("Final URL:", response.url)

        save_text(
            "step1_signup.html",
            response.text
        )

        if response.status_code != 200:
            print("[ERROR] Step1 HTTP failure")
            return False

        server_data = extract_server_data(
            response.text
        )

        if not server_data:
            print("[ERROR] ServerData not found")
            return False

        save_json(
            "step1_serverdata.json",
            server_data
        )

        self.uaid = (
            find_value(server_data, "uaid")
            or self.uaid
        )

        self.api_canary = (
            find_value(server_data, "apiCanary")
            or ""
        )

        hpgid = find_value(
            server_data,
            "hpgid"
        )
        if hpgid:
            self.hpgid = int(hpgid)

        scid = find_value(
            server_data,
            "scid"
        )
        if scid:
            self.scid = int(scid)

        uiflvr = find_value(
            server_data,
            "uiflvr"
        )
        if uiflvr:
            self.uiflvr = int(uiflvr)

        self.arkose_pk = (
            find_value(
                server_data,
                "sArkoseEnforcementPid"
            )
            or ARKOSE_PK_DEFAULT
        )

        # Consumer tenant 常见情况下固定，
        # 但若页面显式提供则优先使用页面值。
        tenant = (
            find_value(
                server_data,
                "sTenantId"
            )
            or find_value(
                server_data,
                "tenantId"
            )
        )
        if tenant:
            self.tenant_id = tenant

        print()
        print("uaid:", self.uaid)
        print(
            "apiCanary:",
            "OK" if self.api_canary else "MISSING"
        )
        print("hpgid:", self.hpgid)
        print("scid:", self.scid)
        print("uiflvr:", self.uiflvr)
        print("tenant_id:", self.tenant_id)
        print("arkose_pk:", self.arkose_pk)

        print()
        print("Cookies:")
        for cookie in self.session.cookies:
            print(
                f"  {cookie.name}="
                f"{cookie.value}"
            )

        return bool(self.api_canary)

    # ========================================================
    # Step 2
    # ========================================================

    def step2_check_available(self, username):
        print()
        print("=" * 70)
        print("STEP 2: CheckAvailableSigninNames")
        print("=" * 70)

        endpoint = (
            f"{SIGNUP_API}/"
            "API/CheckAvailableSigninNames"
        )

        full_email = (
            f"{username}"
            f"{self.email_suffix}"
        )

        payload = {
            "includeSuggestions": True,
            "signInName": full_email,
            "uiflvr": self.uiflvr,
            "scid": self.scid,
            "hpgid": self.hpgid,
            "uaid": self.uaid,
        }

        headers = self.common_headers()

        safe_headers = dict(headers)
        safe_headers["canary"] = "<redacted>"

        save_json(
            "step2_request.json",
            {
                "url": endpoint,
                "params": self.build_params(),
                "headers": safe_headers,
                "payload": payload,
            }
        )

        try:
            response = self.session.post(
                endpoint,
                params=self.build_params(),
                headers=headers,
                json=payload,
                timeout=30
            )
        except requests.RequestException as e:
            print("[ERROR] Step2:", e)
            return None

        print("HTTP:", response.status_code)

        save_text(
            "step2_response_raw.txt",
            response.text
        )

        try:
            data = response.json()
        except ValueError:
            print(
                "[ERROR] Step2 response "
                "is not JSON"
            )
            print(response.text[:3000])
            return None

        save_json(
            "step2_response.json",
            data
        )

        self.update_canary(data)

        print(
            json.dumps(
                data,
                indent=2,
                ensure_ascii=False
            )
        )

        return data

    # ========================================================
    # Step 3
    # ========================================================

    def step3_create_account(
        self,
        username,
        password,
        firstname="Alex",
        lastname="Smith",
        country="US",
        birth_year=1995,
        birth_month=5,
        birth_day=15
    ):
        print()
        print("=" * 70)
        print("STEP 3: CreateAccount")
        print("=" * 70)

        endpoint = (
            f"{SIGNUP_API}/"
            "API/CreateAccount"
        )

        full_email = (
            f"{username}"
            f"{self.email_suffix}"
        )

        country_birthdate = (
            f"{country}:"
            f"{birth_year}:"
            f"{birth_month}:"
            f"{birth_day}"
        )

        payload = {
            "Country": country,
            "CountryBirthdate": country_birthdate,
            "EncExtra": None,
            "FirstName": firstname,
            "LastName": lastname,
            "Password": password,
            "SignInName": full_email,
            "TokenFlow": None,
            "VerificationCode": None,
            "anid": None,
            "canary": self.api_canary,
            "confirmMemberName": None,
            "encAttemptToken": None,
            "hpgid": self.hpgid,
            "isChildAccountCreation": False,
            "isFamily": False,
            "scid": self.scid,
            "uaid": self.uaid,
            "uiflvr": self.uiflvr,
        }

        safe_payload = dict(payload)
        safe_payload["Password"] = "<redacted>"

        safe_headers = self.common_headers()
        safe_headers["canary"] = "<redacted>"

        save_json(
            "step3_request.json",
            {
                "url": endpoint,
                "params": {"lic": "1"},
                "headers": safe_headers,
                "payload": safe_payload,
            }
        )

        try:
            response = self.session.post(
                endpoint,
                params={"lic": "1"},
                headers=self.common_headers(),
                json=payload,
                timeout=30,
                allow_redirects=True
            )
        except requests.RequestException as e:
            print("[ERROR] Step3:", e)
            return None

        print()
        print("HTTP:", response.status_code)
        print(
            "Content-Type:",
            response.headers.get("Content-Type")
        )
        print(
            "Final URL:",
            response.url
        )

        if response.history:
            print("Redirect history:")
            for item in response.history:
                print(
                    f"  {item.status_code} -> "
                    f"{item.headers.get('Location')}"
                )

        save_json(
            "step3_response_headers.json",
            dict(response.headers)
        )

        save_text(
            "step3_response_raw.txt",
            response.text
        )

        t0 = extract_t0(
            response.text
        )

        if not t0:
            print(
                "[WARN] t0 not found in HTML."
            )
            return None

        save_json(
            "step3_t0.json",
            t0
        )

        print()
        print("[OK] Parsed var t0")

        self.update_from_t0(t0)

        print()
        print("=" * 70)
        print("UPDATED STATE FROM t0")
        print("=" * 70)
        print("hpgid:", self.hpgid)
        print("scid:", self.scid)
        print("uiflvr:", self.uiflvr)
        print("uaid:", self.uaid)
        print("tenant_id:", self.tenant_id)
        print(
            "apiCanary:",
            (
                self.api_canary[:60] + "..."
                if self.api_canary
                else "<none>"
            )
        )
        print(
            "telemetry_context:",
            (
                "OK"
                if self.telemetry_context
                else "MISSING"
            )
        )

        return t0

    # ========================================================
    # Step 4.1
    # Risk initialization
    # ========================================================

    def step4_risk_initialize(self):
        """
        请求 Microsoft Risk Initialization。

        这里只完成：
          risk/initialize
            -> 保存 response
            -> 保存 continuationToken
            -> 保存 riskInitializationData

        不处理 challenge solution。
        """

        print()
        print("=" * 70)
        print("STEP 4.1: Risk Initialize")
        print("=" * 70)

        if not self.tenant_id:
            print(
                "[ERROR] Missing tenant_id."
            )
            return None

        endpoint = (
            "https://login.microsoftonline.com/"
            f"{self.tenant_id}/"
            "api/v1.0/risk/initialize"
        )

        # 已通过 test_risk_init.py 实测成功：
        # risk/initialize 的请求体为 continuationToken=""。
        payload = {
            "continuationToken": ""
        }

        headers = {
            "Accept":
                "application/json",

            "Content-Type":
                "application/json; charset=utf-8",

            "client-request-id":
                self.uaid,

            "canary":
                self.api_canary,

            "hpgid":
                str(self.hpgid),

            "hpgact":
                "0",
        }

        safe_headers = dict(headers)
        safe_headers["canary"] = "<redacted>"

        save_json(
            "step4_risk_initialize_request.json",
            {
                "url": endpoint,
                "headers": safe_headers,
                "payload": payload,
            }
        )

        try:
            response = self.session.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=30,
                allow_redirects=True
            )
        except requests.RequestException as e:
            print(
                "[ERROR] "
                "risk/initialize:",
                e
            )
            return None

        print(
            "HTTP:",
            response.status_code
        )

        print(
            "Content-Type:",
            response.headers.get(
                "Content-Type"
            )
        )

        save_json(
            "step4_risk_initialize_headers.json",
            dict(response.headers)
        )

        save_text(
            "step4_risk_initialize_response_raw.txt",
            response.text
        )

        try:
            data = response.json()
        except ValueError:
            print(
                "[ERROR] risk/initialize "
                "response is not JSON"
            )
            print(
                response.text[:5000]
            )
            return None

        save_json(
            "step4_risk_initialize_response.json",
            data
        )

        # HTTP 200 才表示初始化成功。
        if response.status_code != 200:
            print()
            print(
                "[FAIL] risk/initialize "
                f"HTTP {response.status_code}"
            )

            error = (
                data.get("error")
                if isinstance(data, dict)
                else None
            )

            if error:
                print(
                    "[FAIL] code:",
                    error.get("code")
                )
                print(
                    "[FAIL] message:",
                    error.get("message")
                )

            return None

        # 更新可能的 apiCanary
        self.update_canary(data)

        # continuationToken
        token = (
            data.get("continuationToken")
            or find_value(
                data,
                "continuationToken"
            )
        )

        if token:
            self.continuation_token = token

        # riskInitializationData
        risk_data = (
            data.get("riskInitializationData")
            or find_value(
                data,
                "riskInitializationData"
            )
        )

        if isinstance(risk_data, list) and risk_data:
            first = risk_data[0]

            if isinstance(first, dict):
                self.risk_provider = (
                    first.get(
                        "riskProvider",
                        ""
                    )
                )

                self.human_sensor_url = (
                    first.get(
                        "humanSensorUrl",
                        ""
                    )
                )

        elif isinstance(risk_data, dict):
            self.risk_provider = (
                risk_data.get(
                    "riskProvider",
                    ""
                )
            )

            self.human_sensor_url = (
                risk_data.get(
                    "humanSensorUrl",
                    ""
                )
            )

        print()
        print(
            json.dumps(
                data,
                indent=2,
                ensure_ascii=False
            )
        )

        print()
        print("=" * 70)
        print("RISK INITIALIZATION STATE")
        print("=" * 70)

        print(
            "state:",
            data.get("state")
        )

        print(
            "riskProvider:",
            self.risk_provider or "<none>"
        )

        print(
            "humanSensorUrl:",
            self.human_sensor_url or "<none>"
        )

        print(
            "continuationToken:",
            (
                f"OK (len={len(self.continuation_token)})"
                if self.continuation_token
                else "MISSING"
            )
        )

        print(
            "apiCanary:",
            (
                "UPDATED"
                if data.get("apiCanary")
                else "UNCHANGED"
            )
        )

        return data

    # ========================================================
    # State
    # ========================================================

    def print_state(self):
        print()
        print("=" * 70)
        print("CURRENT SESSION STATE")
        print("=" * 70)

        print("uaid:", self.uaid)
        print("hpgid:", self.hpgid)
        print("scid:", self.scid)
        print("uiflvr:", self.uiflvr)
        print("tenant_id:", self.tenant_id)

        print(
            "apiCanary:",
            (
                self.api_canary[:80] + "..."
                if self.api_canary
                else "<none>"
            )
        )

        print(
            "telemetry_context:",
            (
                "OK"
                if self.telemetry_context
                else "<none>"
            )
        )

        print(
            "continuation_token:",
            (
                "OK"
                if self.continuation_token
                else "<none>"
            )
        )

        print(
            "risk_provider:",
            self.risk_provider or "<none>"
        )

        print(
            "human_sensor_url:",
            self.human_sensor_url or "<none>"
        )

        print()
        print("Cookies:")

        for cookie in self.session.cookies:
            print(
                f"  {cookie.name}="
                f"{cookie.value}"
            )


# ============================================================
# Main
# ============================================================

def main():

    TEST_USERNAME = (
        "t5es2txyz98l765"
    )

    TEST_PASSWORD = (
        "T3stPass!2025"
    )

    PROXY = None

    EMAIL_SUFFIX = (
        "@outlook.com"
    )


    full_email = (
        TEST_USERNAME
        + EMAIL_SUFFIX
    )


    print(
        "Target:",
        full_email
    )


    client = OutlookSignupClient(
        proxy=PROXY,
        email_suffix=EMAIL_SUFFIX
    )


    # ========================================================
    # Step 1
    # ========================================================

    if not client.step1_init():

        print(
            "[ABORT] Step1 failed"
        )

        return


    # ========================================================
    # Step 2
    # ========================================================

    result2 = (
        client.step2_check_available(
            TEST_USERNAME
        )
    )


    if not result2:

        print(
            "[ABORT] Step2 failed"
        )

        return


    if not result2.get(
        "isAvailable",
        False
    ):

        print()
        print(
            f"[ABORT] "
            f"{full_email} "
            "is NOT available"
        )

        suggestions = (
            result2.get(
                "suggestions",
                []
            )
        )

        if suggestions:
            print()
            print("Suggestions:")
            for item in suggestions:
                print("  ", item)

        return


    print()
    print(
        f"[OK] {full_email} "
        "is AVAILABLE"
    )


    # ========================================================
    # Step 3
    # ========================================================

    result3 = (
        client.step3_create_account(

            username=
                TEST_USERNAME,

            password=
                TEST_PASSWORD,

            firstname=
                "Alex",

            lastname=
                "Smith",

            country=
                "US",

            birth_year=
                1995,

            birth_month=
                5,

            birth_day=
                15
        )
    )


    if not result3:

        print(
            "[ABORT] "
            "Step3/t0 failed"
        )

        client.print_state()
        return


    # ========================================================
    # Step 4.1
    # ========================================================

    result4 = (
        client.step4_risk_initialize()
    )


    if not result4:

        print()
        print(
            "[ABORT] "
            "Step4 risk/initialize failed"
        )

        client.print_state()
        return


    # ========================================================
    # Final state
    # ========================================================

    client.print_state()


    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)

    print(
        "[OK] Step 4.1 risk initialization "
        "completed with HTTP 200."
    )

    print()
    print(
        "Saved:"
    )

    print(
        "  debug/step4_risk_initialize_request.json"
    )

    print(
        "  debug/step4_risk_initialize_response.json"
    )

    print(
        "  debug/step4_risk_initialize_response_raw.txt"
    )

    print()
    print(
        "continuationToken:",
        (
            "RECEIVED"
            if client.continuation_token
            else "MISSING"
        )
    )

    print(
        "riskProvider:",
        client.risk_provider or "<none>"
    )

    print(
        "humanSensorUrl:",
        client.human_sensor_url or "<none>"
    )


if __name__ == "__main__":
    main()
