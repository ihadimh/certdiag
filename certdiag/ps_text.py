"""ps_text.py — PowerShell 片段（唯一来源，避免两份脚本漂移）

timestamp.py 与 psworker.py 都从这里取：
    TS_SETUP     公共设置（错误处理、输出编码、加载 System.Security）
    TS_FUNCTION  Get-TsRecord 函数体
    TS_SCRIPT    一次性脚本（param + setup + function + 入口）
"""
from __future__ import annotations

TS_SETUP = r"""$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
"""

TS_FUNCTION = r"""function Get-TsRecord {
  param([string]$Path)
  $out = [ordered]@{
    path = $Path; has_signature = $false; signature_ok = $false
    has_token = $false; token_ok = $false; token_oid = $null
    has_legacy_countersignature = $false; has_nested_signature = $false
    tsa_subject = $null; tsa_not_before = $null; tsa_not_after = $null
    error = $null
  }
  try {
    # 只读 PE 头和证书表：以前对整个文件 ReadAllBytes，1MB 的 DLL 要 400~600ms
    $fs = [System.IO.File]::OpenRead($Path)
    try {
      $size = $fs.Length
      if ($size -lt 0x40) { throw "不是 PE 文件" }
      $head = New-Object byte[] 0x40
      [void]$fs.Read($head, 0, 0x40)
      if ($head[0] -ne 0x4D -or $head[1] -ne 0x5A) { throw "不是 PE 文件" }
      $pe = [System.BitConverter]::ToInt32($head, 0x3C)
      if ($pe -le 0 -or ($pe + 24 + 128) -gt $size) { throw "PE 头偏移越界" }

      $fs.Position = $pe
      $nh = New-Object byte[] (4 + 20 + 256)
      [void]$fs.Read($nh, 0, $nh.Length)
      if ($nh[0] -ne 0x50 -or $nh[1] -ne 0x45) { throw "缺少 PE 签名" }   # 'PE'
      $magic = [System.BitConverter]::ToUInt16($nh, 4 + 20)
      if ($magic -eq 0x20B) { $dd = 4 + 20 + 112 + 4 * 8 }
      elseif ($magic -eq 0x10B) { $dd = 4 + 20 + 96 + 4 * 8 }
      else { throw "未知的 PE 格式" }

      $certOff = [System.BitConverter]::ToUInt32($nh, $dd)
      $certSize = [System.BitConverter]::ToUInt32($nh, $dd + 4)
      if ($certOff -eq 0 -or $certSize -eq 0) { throw "没有嵌入式签名" }

      # 不可信输入：所有偏移都对着文件长度核对
      if ($certSize -lt 8) { throw "签名目录长度非法" }
      if (($certOff + $certSize) -gt $size) { throw "签名目录长度越界" }

      $fs.Position = $certOff
      $raw = New-Object byte[] $certSize
      $got = 0
      while ($got -lt $certSize) {
        $n = $fs.Read($raw, $got, $certSize - $got)
        if ($n -le 0) { break }
        $got += $n
      }
      if ($got -lt 8) { throw "签名目录读取不完整" }
    } finally { $fs.Dispose() }

    $len = [System.BitConverter]::ToUInt32($raw, 0)
    if ($len -lt 8) { throw "WIN_CERTIFICATE 长度非法" }
    if ($len -gt $certSize) { throw "WIN_CERTIFICATE 长度超过签名目录声明的大小" }
    $out.has_signature = $true

    $p7 = New-Object byte[] ($len - 8)
    [Array]::Copy($raw, 8, $p7, 0, $len - 8)
    $raw = $null

    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $cms.Decode($p7)
    try { $cms.CheckSignature($true); $out.signature_ok = $true }
    catch { $out.error = "签名校验失败：$($_.Exception.Message)" }

    # OID：311.3.3.1 = RFC3161 时间戳；1.2.840.113549.1.9.6 = 旧式 countersignature；
    #      311.2.4.1 = 嵌套签名（不是时间戳）
    foreach ($ua in $cms.SignerInfos[0].UnsignedAttributes) {
      if ($ua.Oid.Value -eq '1.2.840.113549.1.9.6') {
        $out.has_legacy_countersignature = $true
        continue
      }
      if ($ua.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1') {
        $out.has_nested_signature = $true
        continue
      }
      if ($ua.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1') {
        $out.has_token = $true
        $out.token_oid = $ua.Oid.Value
        $ts = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $ts.Decode($ua.Values[0].RawData)
        try { $ts.CheckSignature($true); $out.token_ok = $true }
        catch { $out.error = "时间戳令牌校验失败：$($_.Exception.Message)" }
        $tsa = $ts.SignerInfos[0].Certificate
        if ($tsa) {
          $out.tsa_subject = $tsa.Subject
          $out.tsa_not_before = $tsa.NotBefore.ToString('yyyy-MM-ddTHH:mm:ss')
          $out.tsa_not_after = $tsa.NotAfter.ToString('yyyy-MM-ddTHH:mm:ss')
        }
        break
      }
    }
  }
  catch { $out.error = $_.Exception.Message }
  return $out
}
"""

TS_SCRIPT = r"""param([string]$Path)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

function Get-TsRecord {
  param([string]$Path)
  $out = [ordered]@{
      path = $Path; has_signature = $false; signature_ok = $false
      has_token = $false; token_ok = $false; token_oid = $null
      has_legacy_countersignature = $false; has_nested_signature = $false
      tsa_subject = $null; tsa_not_before = $null; tsa_not_after = $null
      error = $null
  }

  try {
      $b = [System.IO.File]::ReadAllBytes($Path)
      if ($b.Length -lt 0x40 -or $b[0] -ne 0x4D -or $b[1] -ne 0x5A) { throw "不是 PE 文件" }
      $pe = [System.BitConverter]::ToInt32($b, 0x3C)
      $magic = [System.BitConverter]::ToUInt16($b, $pe + 24)
      if ($magic -eq 0x20B) { $dd = $pe + 24 + 112 + 4 * 8 }
      elseif ($magic -eq 0x10B) { $dd = $pe + 24 + 96 + 4 * 8 }
      else { throw "未知的 PE 格式" }

      $certOff = [System.BitConverter]::ToUInt32($b, $dd)
      $certSize = [System.BitConverter]::ToUInt32($b, $dd + 4)
      if ($certOff -eq 0 -or $certSize -eq 0) { throw "没有嵌入式签名" }

      # 不可信输入，所有偏移都要对着文件长度核对一遍，避免越界读取
      if ($certOff + 8 -gt $b.Length) { throw "签名目录偏移越界" }
      if ($certSize -lt 8 -or $certOff + $certSize -gt $b.Length) { throw "签名目录长度越界" }

      $len = [System.BitConverter]::ToUInt32($b, $certOff)
      if ($len -lt 8) { throw "WIN_CERTIFICATE 长度非法" }
      if ($len -gt $certSize) { throw "WIN_CERTIFICATE 长度超过签名目录声明的大小" }
      if ($len -gt $b.Length) { throw "WIN_CERTIFICATE 长度超过文件大小" }
      $out.has_signature = $true

      $p7 = New-Object byte[] ($len - 8)
      [Array]::Copy($b, $certOff + 8, $p7, 0, $len - 8)

      $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
      $cms.Decode($p7)
      try { $cms.CheckSignature($true); $out.signature_ok = $true }
      catch { $out.error = "签名校验失败：$($_.Exception.Message)" }

      # OID 说明（别搞混）：
      #   1.3.6.1.4.1.311.3.3.1   RFC3161 时间戳令牌（本函数处理的对象）
      #   1.2.840.113549.1.9.6   传统 PKCS#9 countersignature（另一种时间戳机制）
      #   1.3.6.1.4.1.311.2.4.1  嵌套签名 szOID_NESTED_SIGNATURE —— 不是时间戳！
      foreach ($ua in $cms.SignerInfos[0].UnsignedAttributes) {
          if ($ua.Oid.Value -eq '1.2.840.113549.1.9.6') {
              $out.has_legacy_countersignature = $true
              continue
          }
          if ($ua.Oid.Value -eq '1.3.6.1.4.1.311.2.4.1') {
              $out.has_nested_signature = $true
              continue
          }
          if ($ua.Oid.Value -eq '1.3.6.1.4.1.311.3.3.1') {
              $out.has_token = $true
              $out.token_oid = $ua.Oid.Value
              $ts = New-Object System.Security.Cryptography.Pkcs.SignedCms
              $ts.Decode($ua.Values[0].RawData)
              try { $ts.CheckSignature($true); $out.token_ok = $true }
              catch { $out.error = "时间戳令牌校验失败：$($_.Exception.Message)" }
              $tsa = $ts.SignerInfos[0].Certificate
              if ($tsa) {
                  $out.tsa_subject = $tsa.Subject
                  $out.tsa_not_before = $tsa.NotBefore.ToString('yyyy-MM-ddTHH:mm:ss')
                  $out.tsa_not_after = $tsa.NotAfter.ToString('yyyy-MM-ddTHH:mm:ss')
              }
              break
          }
      }
  }
  catch { $out.error = $_.Exception.Message }
  return $out
}

$r = Get-TsRecord -Path $Path
$r | ConvertTo-Json -Compress
"""
