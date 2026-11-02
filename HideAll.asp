<%@ Language=VBScript %>
<%
'==========================================================================
' HideAll.asp —— HideWizard 9.3.8 激活接口（服务端模拟）
'
' 与客户端 sub_14003B9C0 / sub_14003B3B4 / sub_140027BFC 的校验逻辑一致：
'
'   注册码 17 位，A(5)+B(4)+C(4)+D(4)
'   x = (98*A - 234) % 10000;  x % 100 == 0 -> x += 23;  x < 1000 -> x *= 10
'   y = (x + 198*C) % 10000;   y % 100 == 0 -> y += 23;  y < 1000 -> y *= 10
'   合法: B == x 且 D == y
'
'   MCODE = 26 * atoi(SNID[0:4]); 0 -> 12128; > 99999 -> /10
'
' 请求：
'   GET /HideAll.asp?SNID=<17位码>&MCODE=<mcode>&EMAIL=<邮箱>&FLAG=1&VER=9.38
'   GET /HideAll.asp?SNID=<HideSN>&MCODE=<mcode>&EMAIL=<邮箱>&FLAG=10&VER=9.38
'
' 响应（纯文本，无换行）：
'   FLAG=1  合法序列号 -> 13*MCODE - 5678（客户端要求 status >= 30 且等于该值）
'           非法/参数不符 -> 1（客户端按“序列号无效”处理）
'   FLAG=10 合法序列号 -> 0（只要不是 10 或 20，客户端就保持注册状态）
'           非法 -> 1
'
' 说明：
'   * 本模拟器不维护售出序列号数据库，任何通过上述公式的序列号都会被接受。
'   * 客户端对 B/C/D 使用 atoi，因此这里也按 C atoi 语义解析（非数字即停止），
'     不额外要求全为数字，以保持与客户端完全一致。
'   * 32 位有符号乘法溢出按 MSVC 行为（二进制补码回绕）模拟，
'     用于覆盖 A 较小时产生的负数中间值。
'==========================================================================

Option Explicit
Response.ContentType = "text/plain"
Response.Charset = "utf-8"
Response.Expires = -1
Response.CacheControl = "no-cache"

Dim snid, mcodeParam, email, flag, ver

snid       = QS("SNID")
mcodeParam = QS("MCODE")
email      = QS("EMAIL")
flag       = QS("FLAG")
ver        = QS("VER")

Response.Write Handle(flag, snid, mcodeParam)
Response.End

'==========================================================================
' 函数定义
'==========================================================================

' 根据 FLAG 返回响应文本（与客户端 sub_14003B9C0 / sub_14002D72C 对齐）
Function Handle(flag, snid, mcodeParam)
    Dim mcode, status

    ' FLAG=1：在线激活
    If flag = "1" Then
        If Not IsValidSerial(snid) Then
            Handle = "1"
            Exit Function
        End If

        mcode = ComputeMcode(snid)

        ' 客户端会同时发送 MCODE；若存在则必须与服务端重算值一致
        If mcodeParam <> "" Then
            If Atoi(mcodeParam) <> mcode Then
                Handle = "1"
                Exit Function
            End If
        End If

        ' 与客户端 sub_14003B9C0 的约定：status == 13*MCODE - 5678
        ' 客户端先判断 status < 30（错误码区间），所以这里也只在 >= 30 时返回成功值
        status = 13 * mcode - 5678
        If status < 30 Then
            Handle = "1"
        Else
            Handle = CStr(CLng(status))
        End If
        Exit Function
    End If

    ' FLAG=10：启动后的在线复查
    ' 客户端只把 10 / 20 当作“失效”，其它值保持注册状态。
    If flag = "10" Then
        If IsValidSerial(snid) Then
            Handle = "0"
        Else
            Handle = "1"
        End If
        Exit Function
    End If

    ' 未知 FLAG
    Handle = "1"
End Function

' 读取 QueryString，兼容重复参数/空值
Function QS(name)
    Dim v
    v = Request.QueryString(name)
    If IsArray(v) Then
        If UBound(v) >= 0 Then
            QS = Trim(CStr(v(0)))
        Else
            QS = ""
        End If
    ElseIf IsNull(v) Or IsEmpty(v) Then
        QS = ""
    Else
        QS = Trim(CStr(v))
    End If
End Function

' C atoi：跳过前导空白，可选正负号，读到非数字停止
Function Atoi(s)
    Dim i, c, sign, n
    i = 1
    n = 0
    sign = 1

    Do While i <= Len(s)
        c = Mid(s, i, 1)
        If c = " " Or c = vbTab Or c = vbLf Or c = vbCr _
           Or c = Chr(11) Or c = Chr(12) Then
            i = i + 1
        Else
            Exit Do
        End If
    Loop

    If i <= Len(s) Then
        c = Mid(s, i, 1)
        If c = "-" Then
            sign = -1
            i = i + 1
        ElseIf c = "+" Then
            i = i + 1
        End If
    End If

    Do While i <= Len(s)
        c = Mid(s, i, 1)
        If c >= "0" And c <= "9" Then
            n = n * 10 + (Asc(c) - 48)
            i = i + 1
        Else
            Exit Do
        End If
    Loop

    Atoi = sign * n
End Function

' C 的 % 语义：余数符号与被除数相同
Function ModC(a, b)
    Dim q
    q = Fix(a / b)          ' Fix 向零截断
    ModC = a - q * b
End Function

' 32 位有符号整数乘法（二进制补码回绕），对应 MSVC 的 imul 行为
Function Mul32(a, b)
    Dim p, q, r
    p = a * b
    q = Fix(p / 4294967296)
    r = p - q * 4294967296
    If r < 0 Then r = r + 4294967296
    If r >= 2147483648 Then r = r - 4294967296
    Mul32 = r
End Function

' MCODE = 26 * atoi(SNID[0:4]); 0 -> 12128; > 99999 -> /10
Function ComputeMcode(s)
    Dim m
    m = 26 * Atoi(Mid(s, 1, 4))
    If m = 0 Then m = 12128
    If m > 99999 Then m = Fix(m / 10)
    ComputeMcode = m
End Function

' 与 sub_14003B3B4 一致的 17 位注册码校验
Function IsValidSerial(s)
    Dim A, B, C, D, x, y

    If Len(s) <> 17 Then
        IsValidSerial = False
        Exit Function
    End If

    A = Atoi(Mid(s, 1, 5))
    B = Atoi(Mid(s, 6, 4))
    C = Atoi(Mid(s, 10, 4))
    D = Atoi(Mid(s, 14, 4))

    x = ModC(98 * A - 234, 10000)
    If ModC(x, 100) = 0 Then x = x + 23
    Do While x < 1000
        x = Mul32(x, 10)
    Loop

    y = ModC(x + 198 * C, 10000)
    If ModC(y, 100) = 0 Then y = y + 23
    Do While y < 1000
        y = Mul32(y, 10)
    Loop

    IsValidSerial = (B = x) And (D = y)
End Function
%>
