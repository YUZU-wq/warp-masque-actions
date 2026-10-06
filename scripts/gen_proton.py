#!/usr/bin/env python3
"""登录 Proton，产出一段可粘贴进 Worker 的凭据文本。

Worker 不碰 Proton 登录（那会触发风控），只消费这段文本。
证书最长 7 天，过期重跑本流水线换新的。

用法:
  PROTON_USER=x PROTON_PASS=y [PROTON_TOTP_SECRET=z] python3 gen_proton.py <输出目录>

PROTON_TOTP_SECRET 只在账号开了 2FA 时才需要。没开就完全不用管，
行为跟以前一样。开了又没配，本脚本会明确告诉你"是 2FA 拦住了"，
而不是一句含混的"密码不对"。
"""
import asyncio, base64, hashlib, hmac, json, os, struct, sys, time
from proton.session import Session
from proton.session.exceptions import (
    ProtonAPIError, ProtonAPI2FANeeded, ProtonAPIHumanVerificationNeeded,
    ProtonAPIAuthenticationNeeded, ProtonAPINotReachable, ProtonCryptoError)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# 只挑这些国家的落地，够用且不会让配置爆炸
WANT = {"JP": "日本", "SG": "新加坡", "US": "美国", "NL": "荷兰",
        "CH": "瑞士", "CA": "加拿大", "PL": "波兰", "RO": "罗马尼亚",
        "NO": "挪威", "MX": "墨西哥"}
PER_COUNTRY = 3     # 每国取几台


def ed25519_to_wg(raw_sk: bytes) -> str:
    """Proton 的 wg 私钥是从 Ed25519 私钥推的：SHA512 前 32 字节 + clamp。"""
    h = bytearray(hashlib.sha512(raw_sk).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return base64.b64encode(bytes(h)).decode()


def totp_code(secret_b32: str, at: float = None, step: int = 30, digits: int = 6) -> str:
    """RFC 6238 TOTP，纯标准库，不为这个再多拉一个依赖。

    Proton 导出密钥时长这样：'proton:totp/label: <BASE32>'，
    冒号后面那段才是真密钥，先剥掉前缀。
    """
    s = secret_b32.strip()
    if ":" in s:
        s = s.rsplit(":", 1)[-1].strip()
    s = s.replace(" ", "").upper().rstrip("=")
    key = base64.b32decode(s + "=" * (-len(s) % 8), casefold=True)
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


async def login(s: Session, user: str, pw: str):
    """登录 + 必要时过 2FA。失败一律 sys.exit 带一句人话，不抛裸 traceback。"""
    try:
        ok = await s.async_authenticate(user, pw)
    except ProtonCryptoError as e:
        sys.exit(f"SRP 算完了但校验没过（{e}）。多半是 python-proton-core 跟 "
                 f"Proton 服务端的 auth version 对不上，不是密码问题。")
    except ProtonAPIHumanVerificationNeeded as e:
        sys.exit(f"Proton 要人机验证（风控），非官方客户端过不去：{e}\n"
                 f"换个时间段重跑，或从浏览器登录一次该账号把风控解除。")
    except ProtonAPINotReachable as e:
        sys.exit(f"连不上 Proton API：{e}")
    except ProtonAPIError as e:
        sys.exit(f"API 返回错误 [http {e.http_code} / body {e.body_code}]：{e.error}")
    if not ok:
        # 库里只有 body_code 8002（密码错/会话失效）会返回 False
        sys.exit("登录失败：密码不对，或这个 SRP 会话已过期。先手动去 "
                 "Proton 网页登一次确认密码没问题。")

    # 关键：async_authenticate 在"密码对但还需要 2FA"时也返回 True，
    # 它只是把 2FA 状态存起来。不在这儿处理的话，会拖到后面调 /vpn/v2
    # 才炸出一个 403，看日志根本猜不到是 2FA。
    if s.needs_twofa:
        totp = os.environ.get("PROTON_TOTP_SECRET", "").strip()
        if not totp:
            sys.exit("账号开了 2FA。二选一：\n"
                     "  a) Settings > Secrets 加 PROTON_TOTP_SECRET"
                     "（Proton 里导出的一串 base32，形如 'XXXX...=='）\n"
                     "  b) 或者 Proton 账户设置里把 2FA 关掉，只用密码登录")
        if s.supports_fido2:
            sys.exit("账号用的是 FIDO2 硬件密钥做 2FA，Actions 里没法插密钥。"
                     "请在 Proton 后台加一个验证器 App（TOTP）并配 "
                     "PROTON_TOTP_SECRET。")
        try:
            code = totp_code(totp)
        except Exception as e:
            sys.exit(f"PROTON_TOTP_SECRET 不是一串合法的 base32：{e}")
        try:
            if not await s.async_validate_2fa_code(code):
                sys.exit(f"2FA 验证码 {code} 被拒。检查密钥对不对、"
                         f"runner 时钟准不准（TOTP 靠时间，差 30 秒就废）")
        except ProtonAPIAuthenticationNeeded as e:
            # 8002 = 2FA jail，服务端要求整个会话重来
            sys.exit(f"2FA 也被服务端限流了（{e}）。等十几分钟再重跑，"
                     f"别连着试——连着错会把账号登进 jail。")
        except ProtonAPIError as e:
            sys.exit(f"过 2FA 时 API 报错 [http {e.http_code} / body {e.body_code}]：{e.error}")
        print("2FA 通过")
    return True


async def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "dist"
    user = os.environ.get("PROTON_USER", "").strip()
    pw = os.environ.get("PROTON_PASS", "")
    if not user or not pw:
        sys.exit("PROTON_USER / PROTON_PASS 是空的，压根没到登录这一步。")

    s = Session(appversion="linux-vpn@4.8.2",
                user_agent="ProtonVPN/4.8.2 (Linux; Ubuntu/24.04)")

    await login(s, user, pw)
    print("登录成功")

    try:
        vpn = (await s.async_api_request("/vpn/v2")).get("VPN", {})
    except ProtonAPI2FANeeded as e:
        sys.exit(f"过了密码这关但 API 仍要 2FA（{e}）——理论不该到这，"
                 f"把这段日志留着，重跑一次看看是不是偶发")
    except ProtonAPIHumanVerificationNeeded as e:
        sys.exit(f"登录成功了，但取套餐时触发人机验证：{e}")
    except ProtonAPIError as e:
        sys.exit(f"取 /vpn/v2 失败 [http {e.http_code} / body {e.body_code}]：{e.error}")
    print(f"套餐 {vpn.get('PlanName')} / Tier {vpn.get('MaxTier')} / 最大连接 {vpn.get('MaxConnect')}")

    # 申请证书。Duration 写多久都封顶 7 天，实测过
    sk = ed25519.Ed25519PrivateKey.generate()
    pem = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    raw = sk.private_bytes(serialization.Encoding.Raw,
                           serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    try:
        cert = await s.async_api_request("/vpn/v1/certificate", jsondata={
            "ClientPublicKey": pem, "Mode": "session",
            "Duration": "10080 min", "DeviceName": "worker",
        })
    except ProtonAPI2FANeeded as e:
        # 必须排在 ProtonAPIError 前面：它是个子类，否则会被下面的 403 兜底
        # 捕获，报成"套餐不含该权限"，把人往完全错的方向带。
        sys.exit(f"证书接口仍认为 2FA 没过（{e}）。密码和 2FA 都过了却卡在这，"
                 f"通常是服务端要求重新登录，重跑一次。")
    except ProtonAPIHumanVerificationNeeded as e:
        sys.exit(f"申请证书时触发人机验证：{e}")
    except ProtonAPIError as e:
        sys.exit(f"申请证书失败 [http {e.http_code} / body {e.body_code}]：{e.error}\n"
                 f"403 一般是套餐不含该权限；免费版要确认 Proton 后台里 "
                 f"这个设备位没被占满。")
    if "ExpirationTime" not in cert:
        sys.exit(f"证书接口没返回 ExpirationTime，字段变了？返回体键："
                 f"{sorted(cert)}")
    exp = cert["ExpirationTime"]
    wg_sk = ed25519_to_wg(raw)
    print(f"证书到期 {time.strftime('%F %T', time.gmtime(exp))} UTC "
          f"（{(exp - time.time()) / 86400:.1f} 天）")

    # 服务器列表，只要免费的
    lg = await s.async_api_request("/vpn/logicals")
    free = [x for x in lg["LogicalServers"] if x.get("Tier") == 0]

    picked, by_cc = [], {}
    for srv in sorted(free, key=lambda x: x.get("Score", 99)):
        cc = srv["ExitCountry"]
        if cc not in WANT or by_cc.get(cc, 0) >= PER_COUNTRY:
            continue
        phys = (srv.get("Servers") or [{}])[0]
        pub = phys.get("X25519PublicKey")
        ip = phys.get("EntryIP")
        if not (pub and ip):
            continue
        by_cc[cc] = by_cc.get(cc, 0) + 1
        picked.append({
            "name": f"{WANT[cc]}{by_cc[cc]}",
            "cc": cc, "ip": ip, "port": 51820, "pub": pub,
        })

    print(f"选中 {len(picked)} 台，覆盖 {len(by_cc)} 国: "
          + " ".join(f"{c}x{n}" for c, n in sorted(by_cc.items())))
    if not picked:
        # 证书已经花了，但没服务器等于凭据没用。宁可失败也别推一段空配置
        sys.exit(f"免费线路一台都没挑中（共 {len(free)} 台 tier0，"
                 f"国家白名单 {sorted(WANT)}）。服务端列表变了，改 WANT。")

    payload = {
        "v": 1,
        "privateKey": wg_sk,
        "expiresAt": exp,
        "generatedAt": int(time.time()),
        "servers": picked,
    }

    os.makedirs(outdir, exist_ok=True)
    # 压成一行 base64，方便整段复制粘贴，不会被换行搞乱
    blob = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).decode()

    with open(os.path.join(outdir, "proton-blob.txt"), "w") as f:
        f.write(blob + "\n")
    with open(os.path.join(outdir, "proton.json"), "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"\n已生成 {outdir}/proton-blob.txt（{len(blob)} 字符）")
    print("把这段整个复制，粘贴到 Worker 管理页的 Proton 凭据框即可。")


asyncio.run(main())
