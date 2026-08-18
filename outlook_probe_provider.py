"""
Client-profile scanner for the Outlook signup risk provider.

Reuses extract_server_data() from outlook_debug_step4.py and requests the
signup ServerData across several (mkt x User-Agent) combinations, then reports
which combination flips the risk provider from Human to Arkose.

Read-only: does NOT create accounts, only fetches the signup landing page.
"""

import uuid
import time
import requests

from outlook_debug_step4 import (
    extract_server_data,
    find_value,
    SIGNUP_URL,
    CLIENT_ID,
    COBRAND_ID,
)

# ---- profiles to scan ----------------------------------------------------

USER_AGENTS = {
    "chrome-win": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
    ),
    "safari-ios": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    ),
    "firefox-win": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) "
        "Gecko/20100101 Firefox/130.0"
    ),
}

MARKETS = ["ZH-CN", "EN-US", "JA-JP", "DE-DE", "PT-BR"]

# fields we care about when deciding provider routing
WATCH_KEYS = [
    "fEnableHumanSensorOnSignup",
    "fIsRiskInitializationRequired",
    "fIsRiskBlockUXEnabled",
    "sHumanAppId",
    "sArkoseEnforcementPid",
    "urlArkoseEnforcement",
    "sRingId",
]


def build_params(mkt, uaid, opid, ctxid):
    sru = (
        "https://login.live.com/oauth20_authorize.srf"
        "?lc=2052"
        f"&client_id={CLIENT_ID}"
        f"&cobrandid={COBRAND_ID}"
        f"&mkt={mkt}"
        f"&opid={opid}"
        "&opidt=0"
        f"&uaid={uaid}"
        f"&contextid={ctxid}"
    )
    return {
        "sru": sru,
        "mkt": mkt,
        "uiflavor": "web",
        "fl": "dob,flname,wld",
        "cobrandid": COBRAND_ID,
        "client_id": CLIENT_ID,
        "uaid": uaid,
        "suc": CLIENT_ID,
        "fluent": "2",
        "lic": "1",
    }


def accept_language(mkt):
    lang = mkt.lower()
    primary = lang.split("-")[0]
    return f"{lang},{primary};q=0.9,en;q=0.8"


def probe(ua_name, ua, mkt):
    uaid = uuid.uuid4().hex
    opid = uuid.uuid4().hex[:8].upper()
    ctxid = uuid.uuid4().hex[:16].upper()

    s = requests.Session()
    s.headers.update({
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": accept_language(mkt),
    })

    try:
        r = s.get(SIGNUP_URL, params=build_params(mkt, uaid, opid, ctxid),
                  timeout=30, allow_redirects=True)
    except requests.RequestException as e:
        return {"ok": False, "err": str(e)}

    if r.status_code != 200:
        return {"ok": False, "err": f"HTTP {r.status_code}"}

    sd = extract_server_data(r.text)
    if not sd:
        return {"ok": False, "err": "no ServerData", "final": r.url[:80]}

    out = {"ok": True, "final": r.url.split("?")[0]}
    for k in WATCH_KEYS:
        v = find_value(sd, k)
        if k.startswith("url") and v:
            v = str(v)[:38] + "..."
        out[k] = v
    return out


def classify(row):
    if not row.get("ok"):
        return "ERR"
    human = row.get("fEnableHumanSensorOnSignup")
    riskreq = row.get("fIsRiskInitializationRequired")
    has_arkose = bool(row.get("sArkoseEnforcementPid"))
    if str(human) in ("1", "True", "true"):
        return "HUMAN"
    if has_arkose and str(riskreq) not in ("1", "True", "true"):
        return "ARKOSE?"
    return "OTHER"


def main():
    print("=" * 92)
    print("Outlook signup risk-provider profile scan")
    print("=" * 92)
    header = f"{'UA':<12} {'mkt':<7} {'verdict':<8} {'humanOn':<8} {'riskReq':<8} {'ring':<5} {'arkosePid'}"
    print(header)
    print("-" * 92)

    results = []
    for ua_name, ua in USER_AGENTS.items():
        for mkt in MARKETS:
            row = probe(ua_name, ua, mkt)
            verdict = classify(row)
            results.append((ua_name, mkt, verdict, row))
            if row.get("ok"):
                print(f"{ua_name:<12} {mkt:<7} {verdict:<8} "
                      f"{str(row.get('fEnableHumanSensorOnSignup')):<8} "
                      f"{str(row.get('fIsRiskInitializationRequired')):<8} "
                      f"{str(row.get('sRingId')):<5} "
                      f"{str(row.get('sArkoseEnforcementPid'))[:12]}")
            else:
                print(f"{ua_name:<12} {mkt:<7} {verdict:<8} err={row.get('err')}")
            time.sleep(1.5)

    print("-" * 92)
    arkose = [r for r in results if r[2] == "ARKOSE?"]
    human = [r for r in results if r[2] == "HUMAN"]
    print(f"HUMAN combos : {len(human)}   ARKOSE? combos : {len(arkose)}   "
          f"errors : {sum(1 for r in results if r[2]=='ERR')}")
    if arkose:
        print("Arkose-leaning profiles:")
        for ua_name, mkt, _, _ in arkose:
            print(f"   - UA={ua_name}  mkt={mkt}")
    else:
        print("No combo dropped Human sensor; all scanned profiles route to Human.")


if __name__ == "__main__":
    main()
