# Fuck HideWizard 9.3.8

## 项目文件说明

| 文件 | 作用 |
|---|---|
| `keygen.py` | 注册机 |
| `patch_url.py` | 替换域名补丁脚本 |
| `HideAll.asp` | 在线校验逻辑复现 |
| `HideAllCrack.asp` | 删掉校验的逻辑 |

## 0. 样本信息

| 项目 | 值 |
|---|---|
| 文件 | `software/HideWizard.exe` |
| 产品 | 无忧隐藏（HideWizard）9.3.8.0，Seapsoft.com Inc. |
| 架构 | PE32+，x86-64，静态链接 MFC |
| 加壳 | 无（各节熵值正常） |
| 相关模块 | `vism.dll`（启动/皮肤接口）、`HW32DLL.dll`、`VD.dll`、`vd_32.dll` |

本报告中的地址均为 IDA 中的虚拟地址（ImageBase = `0x140000000`）。

---

## 1. 激活界面

资源 `IDD = 142`，标题「激活无忧隐藏」，
控件与类成员的对应关系来自 `CUHelp::DoDataExchange`（`sub_14003AF10`）：

| 控件 ID | 类型 | 文本/用途 | 成员偏移 |
|---|---|---|---|
| 1035 | Edit | 注册码输入框（DDX 限长 20） | `this+2000` |
| 1041 | Edit | 电子邮箱输入框（DDX 限长 50） | `this+2008` |
| 1034 | Button | 「激活注册码」 | `this+1832` |
| 1050 | Button | 「购买注册码激活」（打开 `buy.htm`） | — |
| 1053 | Button | 「确定并关闭激活窗口」 | `this+232` |
| 1158 | CheckBox | 「使用免费协议」（2345 浏览器推广） | `this+2488` |
| 1079/1040/1043/1152 | Static | 状态提示、购买链接、免费协议说明 | — |

`CUHelp::OnInitDialog`（`sub_14003B618`）会从注册表读取已保存的
`HideSN / E_Mail / NEEDRE / YESFREE`；若已注册（全局标志 `dword_1400C5460 != 0`）、
序列号长度为 17 且 `NEEDRE == 0`，则把输入框中的序列号显示为
「前 8 位 + `*********`」。

---

## 2. 客户端注册码校验

### 2.1 触发路径

`CUHelp` 的消息映射表位于 `0x14009D460`，其中与激活相关的两项为：

| 消息 | 通知码 | 控件 ID | 处理函数 |
|---|---|---|---|
| `WM_COMMAND (0x111)` | `BN_CLICKED (0)` | 1034「激活注册码」 | `sub_14003B3B4` |
| `WM_USER + 0x4CA` | — | — | `sub_14003B9C0` |

即：点击「激活注册码」按钮 → `sub_14003B3B4` 先做本地校验；
校验通过后向对话框发送 `SendMessageW(hWnd, WM_USER+0x4CA, 1, 10)`，
该消息由 `sub_14003B9C0` 处理，进入在线激活。

`sub_14003B3B4` 开头还会：

1. 调用 `sub_140041318(this, 1)`（`UpdateData(TRUE)`），把编辑框内容同步到成员变量；
2. 用 `GetTickCount` 做 300ms 防重复点击；
3. 校验失败时把注册码成员变量置为全局空串 `psz`（相当于清空输入）。

### 2.2 注册码格式

注册码必须是 **17 位十进制数字**，分为四段：

```
+--------+--------+--------+--------+
|   A    |   B    |   C    |   D    |
| 5 位   | 4 位   | 4 位   | 4 位   |
+--------+--------+--------+--------+
```

### 2.3 校验公式

```c
A = atoi(serial[0:5]);
B = atoi(serial[5:9]);
C = atoi(serial[9:13]);
D = atoi(serial[13:17]);

x = (98 * A - 234) % 10000;
if (x % 100 == 0) x += 23;      // 避免尾数为 00
while (x < 1000) x *= 10;       // 补足为 4 位

y = (x + 198 * C) % 10000;
if (y % 100 == 0) y += 23;
while (y < 1000) y *= 10;

合法 ⇔ (B == x) && (D == y)
```

对应反汇编中的常量：`0x62 = 98`、`0xEA = 234`、`0xC6 = 198`、`0x2710 = 10000`、
`0x17 = 23`、`0x3E8 = 1000`。

> 说明：`A` 取 `10000..99999` 时结果稳定；若 `A < 3`，`98*A-234` 为负数，
> 取模与补位会进入有符号溢出路径，注册机因此从 `A >= 10000` 取值。

### 2.4 校验通过后的动作

`sub_14003B3B4` 只负责本地格式校验并发出 `WM_USER+0x4CA`；
真正的在线激活在 `sub_14003B9C0` 中完成。

---

## 3. 在线激活协议

### 3.1 请求构造（`sub_14003B9C0`）

1. 检查邮箱长度：`*(int *)(*(_QWORD *)(this + 2008) - 16) >= 3`，否则提示错误。
2. 计算 MCODE：

```c
MCODE = 26 * atoi(serial[0:4]);   // 注意是前 4 位，不是 5 位
if (MCODE == 0)     MCODE = 12128;   // 0x2F60
if (MCODE > 99999)  MCODE /= 10;
```

3. 拼接 URL 并发送：

```
GET http://www.seapsoft.com/HideAll.asp
    ?SNID=<17位注册码>
    &MCODE=<MCODE>
    &EMAIL=<邮箱>
    &FLAG=1
    &VER=9.38
```

其中 `VER=9.38` 来自常量 `0x4022B851EB851EB8`（double 9.38）。

HTTP 实现位于 `sub_1400393C4`：

```c
hInternet = InternetOpenW(L"MSClient", 0, NULL, NULL, 0);
hFile = InternetOpenUrlW(hInternet, url, NULL, 0, 0x80000, 1);
HttpQueryInfoW(hFile, HTTP_QUERY_STATUS_CODE, ...);
// 要求状态码 200..299
InternetReadFile(hFile, buf, 1000, &read);
// 多字节 → 宽字符，返回响应文本
```

### 3.2 响应格式与状态字

响应为 ASCII 文本，长度必须在 `1..20` 字节之间，逗号分隔：

```
status[,extra]
```

`status = atoi(第一段)`。处理逻辑：

| 条件 | 行为 |
|---|---|
| `status < 30` 且 `status == 2` | 显示提示 A |
| `status < 30` 且 `status == 1` 或 `20` | 显示提示 B（序列号无效类） |
| `status < 30` 且 `status == 3` | 显示提示 C |
| `status < 30` 且其它 | 显示默认提示 D |
| `status >= 30` 且 `status != 13*MCODE - 5678` | 显示默认提示 D（无效） |
| `status >= 30` 且 `status == 13*MCODE - 5678` | **激活成功** |

激活成功后：

```c
HW_CODE = (11 * MCODE) ^ 0x607;
while (HW_CODE <  10000) HW_CODE *= 10;
while (HW_CODE >= 100000) HW_CODE /= 10;

// HKCU\Software\U_HIDE\All
RegSetValueExW(..., L"HideSN", REG_SZ,    serial);
RegSetValueExW(..., L"E_Mail", REG_SZ,    email);
RegSetValueExW(..., L"UT",     REG_DWORD, 0);
RegSetValueExW(..., L"NEEDRE", REG_DWORD, 0);

// HKCU\SOFTWARE\ODBC\HW_Update
RegSetValueExW(..., L"HW_CODE", REG_DWORD, HW_CODE);
```

同时置全局注册标志 `dword_1400C5460 = 1`。

> 旧版「服务器返回 1/2 等状态字」的说法在新版中仍成立，
> 但新版额外加入了 `status == 13*MCODE - 5678` 这一客户端-服务器约定校验。

---

## 4. 启动校验与在线复查

### 4.1 启动读取（`sub_140027F48`）

`InitInstance` 阶段从 `HKCU\Software\U_HIDE\All` 读取：

- `LUT` → 使用计数 `dword_1400C49F8`
- `UDATA`（80 字节）→ 全局数据
- `HideSN`（50 字节）→ 全局已存序列号 `qword_1400C5150`

随后调用 `sub_140027BFC` 做离线注册判定。

### 4.2 离线注册判定（`sub_140027BFC`）

```c
if (HideSN.Length < 10) return;          // 视为未注册

MCODE = 26 * atoi(HideSN[0:4]);
if (MCODE == 0)     MCODE = 12128;
if (MCODE > 99999)  MCODE /= 10;

i = (11 * MCODE) ^ 0x607;
while (i <  10000) i *= 10;
while (i >= 100000) i /= 10;

RegQueryValueExW(HKCU\SOFTWARE\ODBC\HW_Update, L"HW_CODE", ...);
if (HW_CODE == i)
    dword_1400C5460 = 1;                 // 已注册
```

**结论：注册状态只取决于 `HideSN` 与 `HW_CODE` 两个注册表值，
不需要服务器参与即可通过启动校验。**

### 4.3 在线复查（`sub_14002D72C`）

启动约 6 秒后（`sub_14002EA3C` 中 `WaitForSingleObject(..., 0x1770)`）：

- 若 `dword_1400C5460 == 0` → 走未注册统计 `sub_14002DE28`（`hideall_unreg36.asp`）；
- 若已注册 → 启动 `sub_14002D72C`，用已存 `HideSN` / `E_Mail` 发送：

```
GET http://www.seapsoft.com/HideAll.asp
    ?SNID=<HideSN>&MCODE=<MCODE>&EMAIL=<E_Mail>&FLAG=10&VER=9.38
```

响应状态字：

- `10` → 提示序列号问题，`NEEDRE = 1`，`dword_1400C5460 = 0`（清除注册）；
- `20` → 提示问题，`dword_1400C5460 = 0`；
- 其它值 → 不做处理，保持已注册状态。

网络不通时会等待/重试最多 5 次（每次 3 分钟）。

> 因此离线激活后若保持联网，服务器仍可能把状态改为未注册；
> 离线使用或屏蔽 `seapsoft.com` 可避免该复查生效。

---

## 5. 完整性校验

`sub_14003547C`（主窗口初始化流程）调用：

```c
MapFileAndCheckSumW(&Filename, &HeaderSum, &CheckSum);
```

`sub_140030A9C` 中比较：

```c
if (HeaderSum == CheckSum) {
    // 正常创建托盘图标、启动后续逻辑
}
// 否则直接返回，程序不进入正常工作流程
```

`HeaderSum` 是 PE 可选头中保存的校验和，`CheckSum` 是 `imagehlp` 实算值。
若修改了二进制，需要同步重算并写回 PE 头校验和，否则程序不启动。
该检查与注册码校验相互独立。

---

## 6. 注册机可行性

### 6.1 客户端算法可完全离线复现

17 位注册码的本地校验只依赖 `A`、`C` 两段，`B`、`D` 可由公式导出，
因此可以无限生成通过客户端校验的注册码。

### 6.2 在线激活仍需服务器

GUI 中点击「激活注册码」后，程序会请求 `HideAll.asp`，服务器必须返回
`13*MCODE - 5678` 才会置为已注册。该状态字可由 MCODE 推算，但服务器是否
认可某个序列号（是否为售出的正版序列号）无法离线判断。

### 6.3 离线激活路径

由于启动校验（4.2 节）只比较 `HideSN` 与 `HW_CODE`，因此直接写入：

```
HKCU\Software\U_HIDE\All
    HideSN = <17 位注册码>
    E_Mail = <邮箱>
    UT     = 0
    NEEDRE = 0
HKCU\SOFTWARE\ODBC\HW_Update
    HW_CODE = normalize5((11*MCODE) ^ 0x607)
```

即可让程序在启动时判定为已注册，无需服务器。

---

## 7. 注册机脚本

`keygen.py` 实现：

- `build_serial(a, c)`：按 2.3 节公式生成 17 位注册码；
- `validate_serial(s)`：复现客户端校验；
- `compute_mcode / compute_hw_code / expected_server_status`：复现 3.1、3.2 节；
- `--apply`：写入上述两个注册表位置（离线激活）；
- `--reg FILE`：生成 `.reg` 文件；
- `--check SERIAL`：校验任意注册码并给出激活参数。

示例：

```
$ python keygen.py --seed 1
注册码 (17 位) : 27611564493251994
电子邮箱       : user@example.com
MCODE          : 71786
服务器应返回   : 927540
HW_CODE        : 78912
```

离线激活：

```
python keygen.py --email me@example.com --apply
```

或生成注册表文件后双击导入：

```
python keygen.py --email me@example.com --reg hidewizard.reg
```

### 7.2 服务端模拟：`HideAll.asp`

经典 ASP（VBScript）实现，可直接放在 IIS 站点根目录作为 `HideAll.asp`。
它与客户端保持完全一致：

- 17 位注册码的 A/B/C/D 校验公式；
- C `atoi` 语义（跳过前导空白、可选正负号、遇到非数字停止）；
- 32 位有符号乘法溢出回绕（覆盖 A 较小时产生的负数中间值）；
- `MCODE = 26 * atoi(SNID[0:4])`，0 → 12128，>99999 → /10；
- `FLAG=1` 合法时返回 `13*MCODE - 5678`（仅当该值 >= 30），否则返回 `1`；
- `FLAG=10` 合法时返回 `0`，否则返回 `1`（客户端只把 10/20 视为失效）；
- 若请求携带 `MCODE` 且与服务端重算值不一致，返回 `1`。

验证方式：用 `cscript` 直接执行从 ASP 中抽取的函数，
446 组注册码校验向量 + 99 组响应分支向量全部通过（0 失败）。

部署时配合 `patch_url.py` 把客户端基址改为本地服务器即可，例如：

```
python patch_url.py --host http://127.0.0.1:8080
```

注意：该模拟器不维护售出序列号数据库，任何通过公式的序列号都会被接受；
`2`（序列号已存在）、`3`、`20` 等业务错误码未实现。

---

## 8. 与旧版参考的对应关系

| 旧版（32 位） | 新版（9.3.8 x64） |
|---|---|
| `0042AB9B` 检查注册码 17 位 | `sub_14003B3B4` 检查 `Length == 17` |
| 注册码通过后 `SendMessageA` 进入下一步 | `SendMessageW(hWnd, 0x4CA, 1, 10)` → `sub_14003B9C0` |
| `CHttpFile` / `CInternetFile::Read` | `InternetOpenUrlW` / `InternetReadFile`（`sub_1400393C4`） |
| 服务器返回 1/2 等状态字 | 逗号分隔响应，`status < 30` 为错误码，`>= 30` 时校验 `13*MCODE-5678` |
| `MapFileAndCheckSumA` | `MapFileAndCheckSumW`（`sub_14003547C` / `sub_140030A9C`） |
| 无离线注册表校验记录 | 新增 `HW_CODE` 离线校验（`sub_140027BFC`） |

---

## 9. 附录：关键函数索引

| 地址 | 作用 |
|---|---|
| `0x14003AF10` | `CUHelp::DoDataExchange`（控件映射） |
| `0x14003B618` | `CUHelp::OnInitDialog`（读取注册表、掩码显示） |
| `0x14003B3B4` | 17 位注册码本地校验 |
| `0x14003B9C0` | 激活请求与响应处理 |
| `0x1400393C4` | HTTP GET 封装 |
| `0x140027F48` | `InitInstance`，读取 HideSN 等 |
| `0x140027BFC` | 启动时 HW_CODE 离线校验 |
| `0x14002D72C` | FLAG=10 在线复查 |
| `0x14002EA3C` | 启动 6 秒后选择复查/统计线程 |
| `0x14002DE28` | 未注册统计（`hideall_unreg36.asp`） |
| `0x14003547C` | 主窗口初始化，调用 `MapFileAndCheckSumW` |
| `0x140030A9C` | PE 校验和比较 |
