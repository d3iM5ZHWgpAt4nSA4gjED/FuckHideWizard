<%@ Language=VBScript %>
<%
'==========================================================================
' HideAllCrack.asp —— HideWizard 激活接口（无校验版）
'
' 与 tools/HideAll.asp 的区别：不做任何注册码/MCODE 校验，
' 对任何请求都返回能让客户端通过的值。
'
'   FLAG=1   -> 13 * MCODE - 5678（按请求里的 MCODE 计算；缺失或非法时用 12128）
'               客户端判定条件：status >= 30 且 status == 13*MCODE - 5678
'   FLAG=10  -> 0（客户端只把 10 / 20 视为失效，其它值保持注册）
'   其它 FLAG -> 1
'
' 注意：FLAG=1 的返回值依赖客户端发来的 MCODE。为保证与客户端重算值一致，
'       需要客户端按该序列号算出的 MCODE 发送正确（客户端总是会发它自己算的值），
'       因此这里直接原样使用请求中的 MCODE 即可通过。
'
' 部署：需同时把客户端基址/路径改到本文件，例如
'       python tools/patch_url.py --host http://127.0.0.1:8080 --path HideAllCrack.asp
'==========================================================================

Option Explicit
Response.ContentType = "text/plain"
Response.Charset = "utf-8"
Response.Expires = -1
Response.CacheControl = "no-cache"

Dim flag, mcode, status

flag  = Param("FLAG")
mcode = Atoi(Param("MCODE"))

If flag = "1" Then
    If mcode <= 0 Then mcode = 12128

    status = 13 * mcode - 5678
    If status < 30 Then
        ' 客户端把 < 30 当作错误码；这种情况下无论返回什么都无法通过，
        ' 但仍尽量返回一个数值（合理序列号的 MCODE 正常都不会走到这里）
        Response.Write "1"
    Else
        Response.Write CStr(CLng(status))
    End If
ElseIf flag = "10" Then
    Response.Write "0"
Else
    Response.Write "1"
End If
Response.End

Function Param(name)
    Dim v
    v = Request.QueryString(name)
    If IsArray(v) Then
        If UBound(v) >= 0 Then
            Param = Trim(CStr(v(0)))
        Else
            Param = ""
        End If
    ElseIf IsNull(v) Or IsEmpty(v) Then
        Param = ""
    Else
        Param = Trim(CStr(v))
    End If
End Function

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
%>
