#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HideWizard (无忧隐藏 9.3.8) 注册机 / 激活码生成器

依据对 HideWizard.exe (x64, 9.3.8.0) 的静态逆向结果：

  1. 客户端注册码格式（sub_14003B3B4）：
       17 位十进制数字，分为 A(5) + B(4) + C(4) + D(4)
       x = (98*A - 234) % 10000;  x % 100 == 0 时 x += 23;  x < 1000 时反复 *10
       y = (x + 198*C) % 10000;   y % 100 == 0 时 y += 23;  y < 1000 时反复 *10
       合法条件: B == x 且 D == y

  2. 在线激活（sub_14003B9C0）：
       MCODE = 26 * atoi(serial[0:4])；为 0 取 12128；>99999 时 /10
       GET http://www.seapsoft.com/HideAll.asp?SNID=<serial>&MCODE=<MCODE>
           &EMAIL=<email>&FLAG=1&VER=9.38
       服务器返回 "status[,其它]"；status >= 30 时必须等于 13*MCODE - 5678
       成功后 HW_CODE = normalize5((11*MCODE) ^ 0x607) 写入注册表

  3. 启动离线校验（sub_140027BFC）：
       读取 HKCU\\Software\\U_HIDE\\All\\HideSN
       以同样方式计算 HW_CODE，与
       HKCU\\SOFTWARE\\ODBC\\HW_Update\\HW_CODE 比较，相等即视为已注册。

因此本脚本生成的注册码可以通过客户端本地校验，并可选择把
HideSN / E_Mail / HW_CODE 直接写入注册表完成离线激活。

注意：
  * 程序启动约 6 秒后会以 FLAG=10 再次联网校验；若服务器返回 10 或 20，
    会清除注册标志（置 NEEDRE=1）。离线使用或屏蔽 seapsoft.com 可避免。
  * --apply 会修改当前用户的注册表，请确认后再使用。

用法示例：
    python keygen.py                     # 生成 1 个注册码并显示激活信息
    python keygen.py -n 5                # 生成 5 个
    python keygen.py --email a@b.com --reg hw.reg
    python keygen.py --apply             # 写入注册表（离线激活）
    python keygen.py --check 12345...    # 校验已有注册码
"""

import argparse
import json
import random
import sys

REG_PATH_SN = r"Software\U_HIDE\All"
REG_PATH_HW = r"SOFTWARE\ODBC\HW_Update"


# ---------------------------------------------------------------------------
# 客户端算法（与 sub_14003B3B4 / sub_14003B9C0 / sub_140027BFC 保持一致）
# ---------------------------------------------------------------------------

def _normalize4(value: int) -> int:
    """复现 x = (...)%10000; 若为 100 的倍数 +23; 不足 4 位则 *10。"""
    value %= 10000
    if value == 100 * (value // 100):
        value += 23
    while value < 1000:
        value *= 10
    return value


def build_serial(a: int, c: int) -> str:
    """由 A(5 位) 与 C(4 位) 生成 17 位注册码。"""
    if not (0 <= a <= 99999):
        raise ValueError("A 必须在 0..99999 之间")
    if not (0 <= c <= 9999):
        raise ValueError("C 必须在 0..9999 之间")
    b = _normalize4(98 * a - 234)
    d = _normalize4(b + 198 * c)
    serial = f"{a:05d}{b:04d}{c:04d}{d:04d}"
    if not validate_serial(serial):
        raise AssertionError("内部错误：生成的注册码未通过本地校验")
    return serial


def validate_serial(serial: str) -> bool:
    """复现 sub_14003B3B4 的客户端校验。"""
    if len(serial) != 17 or not serial.isdigit():
        return False
    a = int(serial[0:5])
    b = int(serial[5:9])
    c = int(serial[9:13])
    d = int(serial[13:17])
    x = _normalize4(98 * a - 234)
    y = _normalize4(x + 198 * c)
    return b == x and d == y


def compute_mcode(serial: str) -> int:
    """MCODE = 26 * atoi(serial[0:4])，0→12128，>99999→/10。"""
    mcode = 26 * int(serial[0:4])
    if mcode == 0:
        mcode = 12128
    if mcode > 99999:
        mcode //= 10
    return mcode


def compute_hw_code(mcode: int) -> int:
    """HW_CODE = normalize5((11*MCODE) ^ 0x607)。"""
    value = (11 * mcode) ^ 0x607
    while value < 10000:
        value *= 10
    while value >= 100000:
        value //= 10
    return value


def expected_server_status(mcode: int) -> int:
    """服务器对合法注册码应返回的状态字：13*MCODE - 5678。"""
    return 13 * mcode - 5678


def activation_info(serial: str, email: str = "user@example.com") -> dict:
    mcode = compute_mcode(serial)
    return {
        "serial": serial,
        "email": email,
        "mcode": mcode,
        "expected_server_status": expected_server_status(mcode),
        "hw_code": compute_hw_code(mcode),
        "request_url": (
            "http://www.seapsoft.com/HideAll.asp"
            f"?SNID={serial}&MCODE={mcode}&EMAIL={email}&FLAG=1&VER=9.38"
        ),
    }


# ---------------------------------------------------------------------------
# 注册表写入 / .reg 文件生成
# ---------------------------------------------------------------------------

def apply_to_registry(serial: str, email: str) -> None:
    import winreg

    info = activation_info(serial, email)

    key = winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, REG_PATH_SN, 0, winreg.KEY_SET_VALUE
    )
    try:
        winreg.SetValueEx(key, "HideSN", 0, winreg.REG_SZ, serial)
        winreg.SetValueEx(key, "E_Mail", 0, winreg.REG_SZ, email)
        winreg.SetValueEx(key, "UT", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "NEEDRE", 0, winreg.REG_DWORD, 0)
    finally:
        winreg.CloseKey(key)

    key = winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, REG_PATH_HW, 0, winreg.KEY_SET_VALUE
    )
    try:
        winreg.SetValueEx(key, "HW_CODE", 0, winreg.REG_DWORD, info["hw_code"])
    finally:
        winreg.CloseKey(key)


def write_reg_file(path: str, serial: str, email: str) -> None:
    info = activation_info(serial, email)
    content = (
        "Windows Registry Editor Version 5.00\r\n"
        "\r\n"
        f"[HKEY_CURRENT_USER\\{REG_PATH_SN}]\r\n"
        f"\"HideSN\"=\"{serial}\"\r\n"
        f"\"E_Mail\"=\"{email}\"\r\n"
        "\"UT\"=dword:00000000\r\n"
        "\"NEEDRE\"=dword:00000000\r\n"
        "\r\n"
        f"[HKEY_CURRENT_USER\\{REG_PATH_HW}]\r\n"
        f"\"HW_CODE\"=dword:{info['hw_code']:08x}\r\n"
    )
    with open(path, "wb") as f:
        f.write(b"\xff\xfe")  # UTF-16LE BOM
        f.write(content.encode("utf-16-le"))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="HideWizard 9.3.8 注册机（本地算法 + 离线激活）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-n", "--count", type=int, default=1, help="生成数量，默认 1")
    parser.add_argument("--email", default="user@example.com", help="注册邮箱")
    parser.add_argument("--a", type=int, help="手动指定 A 字段（5 位）")
    parser.add_argument("--c", type=int, help="手动指定 C 字段（4 位）")
    parser.add_argument("--seed", type=int, help="随机种子")
    parser.add_argument("--apply", action="store_true", help="写入当前用户注册表")
    parser.add_argument("--reg", metavar="FILE", help="生成 .reg 注册表文件")
    parser.add_argument("--check", metavar="SERIAL", help="校验已有注册码")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = parser.parse_args(argv)

    if args.check:
        ok = validate_serial(args.check)
        info = activation_info(args.check, args.email) if ok else None
        if args.json:
            print(json.dumps({"valid": ok, "info": info}, ensure_ascii=False, indent=2))
        else:
            print(f"注册码: {args.check}")
            print(f"客户端校验: {'通过' if ok else '失败'}")
            if info:
                print(f"MCODE: {info['mcode']}")
                print(f"服务器应返回状态: {info['expected_server_status']}")
                print(f"HW_CODE: {info['hw_code']}")
        return 0 if ok else 1

    if args.seed is not None:
        random.seed(args.seed)

    if args.count < 1:
        parser.error("--count 必须 >= 1")

    results = []
    for i in range(args.count):
        a = args.a if args.a is not None else random.randint(10000, 99999)
        c = args.c if args.c is not None else random.randint(0, 9999)
        serial = build_serial(a, c)
        results.append(activation_info(serial, args.email))

    if args.apply:
        if len(results) > 1:
            parser.error("--apply 只能与单个注册码一起使用")
        if sys.platform != "win32":
            parser.error("--apply 仅支持 Windows")
        apply_to_registry(results[0]["serial"], args.email)
        print(f"已写入注册表: {REG_PATH_SN} / {REG_PATH_HW}", file=sys.stderr)

    if args.reg:
        if len(results) > 1:
            parser.error("--reg 只能与单个注册码一起使用")
        write_reg_file(args.reg, results[0]["serial"], args.email)
        print(f"已生成注册表文件: {args.reg}", file=sys.stderr)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for info in results:
            print("=" * 60)
            print(f"注册码 (17 位) : {info['serial']}")
            print(f"电子邮箱       : {info['email']}")
            print(f"MCODE          : {info['mcode']}")
            print(f"服务器应返回   : {info['expected_server_status']}")
            print(f"HW_CODE        : {info['hw_code']}")
            print(f"激活请求       : {info['request_url']}")
        if not args.apply:
            print("=" * 60)
            print("提示：GUI 中的“激活注册码”仍需服务器返回上述状态字；")
            print("      离线激活可使用 --apply 或 --reg 直接写入 HideSN 与 HW_CODE。")

    return 0


if __name__ == "__main__":
    sys.exit(main())
