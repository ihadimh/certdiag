
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

function Get-Sha256Safe {
  # Get-FileHash 在精简版 PowerShell 或受限模块路径下可能不存在。
  # SHA256 只是附加信息，不能因为它让整个诊断失败。
  param([string]$Path)
  try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($fs)) -replace '-', '') }
    finally { $fs.Dispose(); $sha.Dispose() }
  } catch { }
  return $null
}

function Get-SigRecord {
  param([string]$Path, [string]$Revoke = 'NoCheck', [bool]$Offline = $false)

  $rec = [ordered]@{
    path = $Path; exists = $false; size = 0; sha256 = $null; error_kind = $null
    status = $null; status_message = $null
    signer = $null; signer_expired = $false; timestamper = $null
    chain = $null; crl_ocsp_urls = @(); error = $null
  }

  try {
    if (-not (Test-Path -LiteralPath $Path)) {
      $rec.error = "文件不存在"; $rec.error_kind = "not_found"; return $rec
    }
    if ((Get-Item -LiteralPath $Path) -is [System.IO.DirectoryInfo]) {
      $rec.error = "这是目录，请对单个文件诊断"; $rec.error_kind = "is_directory"; return $rec
    }
    $item = Get-Item -LiteralPath $Path
    $rec.path = $item.FullName
    $rec.exists = $true
    $rec.size = $item.Length
    $rec.sha256 = Get-Sha256Safe $item.FullName

    $sig = Get-AuthenticodeSignature -LiteralPath $item.FullName
    $rec.status = $sig.Status.ToString()
    $rec.status_message = $sig.StatusMessage

    $cert = $sig.SignerCertificate
    if ($cert) {
      $rec.signer = [ordered]@{
        subject = $cert.Subject; issuer = $cert.Issuer; thumbprint = $cert.Thumbprint
        serial = $cert.SerialNumber
        not_before = $cert.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssK')
        not_after = $cert.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
        version = $cert.Version
      }
      $rec.signer_expired = ($cert.NotAfter -lt (Get-Date))

      if ($sig.TimeStamperCertificate) {
        $ts = $sig.TimeStamperCertificate
        $rec.timestamper = [ordered]@{
          subject = $ts.Subject; thumbprint = $ts.Thumbprint
          not_after = $ts.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
        }
      }

      $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
      $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::$Revoke
    # 离线模式：连中间证书（AIA）都不许下载，否则离线就是假的
    if ($Offline -and ($chain.ChainPolicy.PSObject.Properties.Name -contains 'DisableCertificateDownloads')) {
      $chain.ChainPolicy.DisableCertificateDownloads = $true
      $rec.aia_downloads_disabled = $true
    } else {
      $rec.aia_downloads_disabled = $false
    }
      $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
      $built = $chain.Build($cert)

      $elements = @(); $urls = New-Object System.Collections.ArrayList
      foreach ($el in $chain.ChainElements) {
        $st = @()
        foreach ($s in $el.ChainElementStatus) {
          $st += [ordered]@{ status = $s.Status.ToString(); info = $s.StatusInformation }
        }
        $elements += [ordered]@{
          subject = $el.Certificate.Subject; issuer = $el.Certificate.Issuer
          thumbprint = $el.Certificate.Thumbprint
          not_before = $el.Certificate.NotBefore.ToString('yyyy-MM-ddTHH:mm:ssK')
          not_after = $el.Certificate.NotAfter.ToString('yyyy-MM-ddTHH:mm:ssK')
          status = $st
        }
        foreach ($ext in $el.Certificate.Extensions) {
          try {
            $txt = $ext.Format($false)
            if ($txt -match 'https?://') {
              foreach ($m in [regex]::Matches($txt, 'https?://[^\s",;<>\)\]]+')) {
                if (-not $urls.Contains($m.Value)) { [void]$urls.Add($m.Value) }
              }
            }
          } catch { }
        }
      }
      $cs = @()
      foreach ($s in $chain.ChainStatus) {
        $cs += [ordered]@{ status = $s.Status.ToString(); info = $s.StatusInformation }
      }
      $rec.chain = [ordered]@{ built = [bool]$built; elements = $elements; chain_status = $cs }
      $rec.crl_ocsp_urls = @($urls)
    }
  }
  catch {
    $rec.error = $_.Exception.Message
  }
  return $rec
}

while ($true) {
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


$line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  if ($line.Trim() -eq '') { continue }
  $out = $null
  try {
    $job = $line | ConvertFrom-Json
    if ($job.op -eq 'timestamp') {
      try { $r = Get-TsRecord -Path $job.path }
      catch { $r = [ordered]@{ path = $job.path; error = $_.Exception.Message } }
      $r | ConvertTo-Json -Compress
      continue
    }
    $rev = if ($job.revoke) { $job.revoke } else { 'NoCheck' }
    $off = if ($job.offline) { $true } else { $false }
    $out = Get-SigRecord -Path $job.path -Revoke $rev -Offline $off
  }
  catch {
    $out = [ordered]@{ path = $job.path; error = $_.Exception.Message; error_kind = 'internal' }
  }
  $json = $out | ConvertTo-Json -Depth 10 -Compress
  [Console]::Out.WriteLine($json)
  [Console]::Out.Flush()
}
