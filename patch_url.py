#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HideWizard 激活 URL 重定向补丁

程序运行时用「基址 + "/" + 路径 + 参数」拼接激活 URL：

    base = "http://www.seapsoft.com"          # 文件偏移 0x99A18（UTF-16LE，槽位 48 字节）
    path = "HideAll.asp?SNID"                 # 文件偏移 0x999B8（UTF-16LE，槽位 40 字节）
    url  = base + "/" + path + "=" + SNID + "&MCODE=..." +
           "&EMAIL=..." + "&FLAG=1" + "&VER=9.38"

同一组 base/path 也被启动后的 FLAG=10 在线复查使用。
本脚本把 base（和可选的 path）改成新值，并重算 PE 头校验和，
否则 imagehlp!MapFileAndCheckSumW 的校验会失败（HeaderSum != CheckSum），
程序不会进入正常工作流程。

默认只生成副本，不修改原文件。

用法：
    python patch_url.py --host http://127.0.0.1:8080
    python patch_url.py --host http://127.0.0.1 --out hw_patched.exe
    python patch_url.py --path activate --host http://127.0.0.1:8080
    python patch_url.py --host http://127.0.0.1:8080 --in-place   # 谨慎

槽位限制：
    host <= 23 个字符（48 字节，含结尾 NUL）
    path <= 19 个字符（40 字节，含结尾 NUL）
若需要更长的主机名，需要把字符串搬到别处并修改两条 lea 指令的 RIP 相对位移，
本脚本不处理这种情况。
"""

import argparse
import os
import struct
import sys

IMAGE_BASE = 0x140000000

HOST_OFF = 0x99A18          # VA 0x14009B018
HOST_SLOT = 48              # 23 个 WCHAR + NUL

PATH_OFF = 0x999B8          # VA 0x14009AFB8
PATH_SLOT = 40              # 19 个 WCHAR + NUL

CHECKSUM_FIELD = 0x158      # PE 可选头 CheckSum 字段的文件偏移（本样本）


def pe_checksum(data: bytes) -> int:
    """复现 imagehlp!CheckSumMappedFile：CheckSum 字段按 0 计算。"""
    buf = bytearray(data)
    struct.pack_into("<I", buf, CHECKSUM_FIELD, 0)

    checksum = 0
    dwords = len(buf) // 4
    for i in range(dwords):
        checksum += struct.unpack_from("<I", buf, i * 4)[0]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    rem = len(buf) % 4
    if rem:
        tail = bytes(buf[dwords * 4:]) + b"\x00" * (4 - rem)
        checksum += struct.unpack("<I", tail)[0]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += len(buf)
    return checksum & 0xFFFFFFFF


def patch_string(data: bytearray, offset: int, slot: int, text: str, label: str) -> None:
    raw = text.encode("utf-16-le") + b"\x00\x00"
    if len(raw) > slot:
        raise SystemExit(
            f"{label} 过长：{text!r} 需要 {len(raw)} 字节，槽位只有 {slot} 字节"
        )
    data[offset:offset + slot] = raw + b"\x00" * (slot - len(raw))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="重定向 HideWizard 激活 URL 并修复 PE 校验和")
    ap.add_argument("--input", default=os.path.join("software", "HideWizard.exe"))
    ap.add_argument("--out", default=os.path.join("software", "HideWizard_patched.exe"))
    ap.add_argument("--host", help='新基址，例如 "http://127.0.0.1:8080"')
    ap.add_argument("--path", help='新路径，例如 "HideAll.asp?SNID"（不含开头的 "/"）')
    ap.add_argument("--in-place", action="store_true", help="直接修改 --input 文件")
    args = ap.parse_args(argv)

    if not args.host and not args.path:
        ap.error("至少指定 --host 或 --path")

    with open(args.input, "rb") as f:
        data = bytearray(f.read())

    old_checksum = struct.unpack_from("<I", data, CHECKSUM_FIELD)[0]
    if pe_checksum(data) != old_checksum:
        print("警告：原文件 PE 校验和与实算值不一致，继续处理", file=sys.stderr)

    if args.host:
        patch_string(data, HOST_OFF, HOST_SLOT, args.host, "host")
        print(f"host -> {args.host!r} @ 文件偏移 0x{HOST_OFF:X}")
    if args.path:
        patch_string(data, PATH_OFF, PATH_SLOT, args.path, "path")
        print(f"path -> {args.path!r} @ 文件偏移 0x{PATH_OFF:X}")

    new_checksum = pe_checksum(data)
    struct.pack_into("<I", data, CHECKSUM_FIELD, new_checksum)
    print(f"PE 校验和: 0x{old_checksum:08X} -> 0x{new_checksum:08X}")

    out = args.input if args.in_place else args.out
    if args.in_place:
        print("警告：正在覆盖原文件", file=sys.stderr)
    with open(out, "wb") as f:
        f.write(data)
    print(f"已写出: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
