<# 
Send-LTE-SMS.ps1  (PowerShell 5.1 compatible)

For each router:
- Open SSH via interactive ShellStream (Cisco-friendly)
- Detect Cellular interface(s)
- Read ICCID
- Send SMS to primary + secondary numbers:
    Primary   : 0400252637
    Secondary : 0401255433
  Message: "From <RouterIP> ICCID <ICCID>"
- Log per-router results with per-number success

Usage examples:
  .\Send-LTE-SMS.ps1 -Routers 192.168.200.1 -Username admin -PasswordPlain 'Bryan2011'
  .\Send-LTE-SMS.ps1 -RouterList .\routers.txt -Username admin -PasswordPlain 'Bryan2011'
  .\Send-LTE-SMS.ps1 -Routers 192.168.200.1 -Username admin -PasswordPlain 'Bryan2011' -Number +61400252637 -SecondaryNumber +61401255433
#>

[CmdletBinding()]
param(
  [Parameter(ParameterSetName='Inline', Mandatory=$true)]
  [string[]]$Routers,

  [Parameter(ParameterSetName='File', Mandatory=$true)]
  [string]$RouterList,

  [Parameter(Mandatory=$true)]
  [string]$Username,

  [Parameter(Mandatory=$false)]
  [securestring]$Password,

  [Parameter(Mandatory=$false)]
  [string]$PasswordPlain,

  # Primary + Secondary destination numbers (can override on CLI)
  [string]$Number = '0400252637',
  [string]$SecondaryNumber = '0401255433',

  [switch]$NoSend,

  [int]$Port = 22,
  [int]$TimeoutSec = 25
)

# ------------- helpers -------------

function ConvertTo-Plain {
  param([securestring]$Secure)
  if (-not $Secure) { return $null }
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Ensure-PoshSsh {
  if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    throw "Posh-SSH not found. Install it once with: Install-Module Posh-SSH -Scope CurrentUser"
  }
  Import-Module Posh-SSH -ErrorAction Stop
}

function Read-UntilPrompt {
  param(
    [Parameter(Mandatory=$true)] $Shell,
    [int]$TimeoutSec = 20,
    [string]$PromptRegex = '(?m)[\r\n].*[>#]\s*$'   # matches IOS user/priv prompt
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $buf = New-Object System.Text.StringBuilder

  while ((Get-Date) -lt $deadline) {
    $chunk = $Shell.Read()
    if ($chunk) {
      [void]$buf.Append($chunk)

      # Handle --More-- pagination if it ever appears
      if ($buf.ToString() -match '--More--') {
        [void]$Shell.Write(" ")   # send space to continue
        Start-Sleep -Milliseconds 120
      }

      if ($buf.ToString() -match $PromptRegex) {
        break
      }
    } else {
      Start-Sleep -Milliseconds 100
    }
  }
  return $buf.ToString()
}

function Send-Cmd {
  param(
    [Parameter(Mandatory=$true)] $Shell,
    [Parameter(Mandatory=$true)] [string]$Command,
    [int]$TimeoutSec = 20
  )
  [void]$Shell.Write("$Command`r")
  Start-Sleep -Milliseconds 150
  $out = Read-UntilPrompt -Shell $Shell -TimeoutSec $TimeoutSec
  return $out
}

function Open-CiscoShell {
  param(
    [string]$Ip, [string]$User, [securestring]$Pass, [int]$Port, [int]$TimeoutSec
  )
  $cred = [PSCredential]::new($User, $Pass)
  $session = New-SSHSession -ComputerName $Ip -Port $Port -Credential $cred -AcceptKey -ConnectionTimeout $TimeoutSec -ErrorAction Stop

  $shell = $null
  try {
    # Newer Posh-SSH (supports TerminalWidth/TerminalHeight/MaxLines)
    $shell = New-SSHShellStream -SSHSession $session -TerminalName "vt100" -TerminalWidth 140 -TerminalHeight 4000 -MaxLines 10000
  } catch {
    try {
      # Older Posh-SSH (uses Columns/Rows/BufferSize)
      $shell = New-SSHShellStream -SSHSession $session -TerminalName "vt100" -Columns 140 -Rows 4000 -BufferSize 10000
    } catch {
      # Last resort: no sizing params
      $shell = New-SSHShellStream -SSHSession $session -TerminalName "vt100"
    }
  }

  Start-Sleep -Milliseconds 200
  [void]$Shell.Write("`r")
  Start-Sleep -Milliseconds 200
  $null = Read-UntilPrompt -Shell $Shell -TimeoutSec $TimeoutSec

  # disable paging
  Send-Cmd -Shell $Shell -Command "terminal length 0" -TimeoutSec $TimeoutSec | Out-Null

  return @{ Session=$session; Shell=$shell }
}

function Close-CiscoShell {
  param($Session, $Shell)
  try { if ($Shell) { $Shell.Dispose() } } catch {}
  try { if ($Session) { Remove-SSHSession -SSHSession $Session | Out-Null } } catch {}
}

function Run-CiscoCommands {
  param(
    [string]$Ip, [string]$User, [securestring]$Pass, [int]$Port, [int]$TimeoutSec, [string[]]$Commands
  )
  $sess = $null; $sh = $null
  try {
    $opened = Open-CiscoShell -Ip $Ip -User $User -Pass $Pass -Port $Port -TimeoutSec $TimeoutSec
    $sess = $opened.Session; $sh = $opened.Shell

    $outs = @()
    foreach ($c in $Commands) {
      $o = Send-Cmd -Shell $sh -Command $c -TimeoutSec $TimeoutSec
      $outs += [pscustomobject]@{ Command=$c; Output=$o }
    }
    return $outs
  }
  finally {
    Close-CiscoShell -Session $sess -Shell $sh
  }
}

function Get-CellularInterfacesFromText {
  param([string]$Text)
  $ifaces = @()
  foreach ($m in [regex]::Matches($Text, '(?im)\b(Cellular\d+(?:/\d+/\d+)?)\b')) {
    $ifaces += $m.Groups[1].Value
  }
  $ifaces | Sort-Object -Unique
}

function Get-ICCID {
  param(
    [string]$Ip, [string]$User, [securestring]$Pass, [int]$Port, [int]$TimeoutSec, [string]$Iface
  )
  # Accept both "Cellular0/0/0" and "0/0/0"
  $ifaceNoPrefix = ($Iface -replace '(?i)^Cellular','')

  $cmds = @(
    "show cellular $Iface all",
    "show cellular $ifaceNoPrefix all",
    "show cellular $Iface hardware",
    "show cellular $ifaceNoPrefix hardware",
    "show cellular $Iface",
    "show cellular $ifaceNoPrefix"
  )

  $outs = Run-CiscoCommands -Ip $Ip -User $User -Pass $Pass -Port $Port -TimeoutSec $TimeoutSec -Commands $cmds

  # Try several ICCID patterns:
  $iccid = $null
  foreach ($o in $outs) {
    $text = $o.Output
    $m = [regex]::Match($text, '(?im)\bICCID\b[^0-9A-Za-z]*([0-9]{15,22})') # ICCID: 89...
    if (-not $m.Success) {
      $m = [regex]::Match($text, '(?im)Integrated\s+Circuit\s+Card\s+ID.*?\b([0-9]{15,22})')
    }
    if ($m.Success) { $iccid = $m.Groups[1].Value; break }
  }
  # Last-resort: any 19–22 digit starting with 89 (ICCIDs usually start with 89)
  if (-not $iccid) {
    $m2 = [regex]::Match(($outs | ForEach-Object {$_.Output} | Out-String), '(?m)\b(89\d{17,21})\b')
    if ($m2.Success) { $iccid = $m2.Groups[1].Value }
  }
  $iccid
}

function Send-SMS {
  param(
    [string]$Ip, [string]$User, [securestring]$Pass, [int]$Port, [int]$TimeoutSec,
    [string]$Iface, [string]$Number, [string]$Message
  )
  $ifaceNoPrefix = ($Iface -replace '(?i)^Cellular','')

  # Try multiple IOS flavors:
  $cmds = @(
    "cellular $Iface gsm sms send $Number `"$Message`"",
    "cellular $ifaceNoPrefix gsm sms send $Number `"$Message`"",
    "cellular $Iface lte sms send $Number `"$Message`"",
    "cellular $ifaceNoPrefix lte sms send $Number `"$Message`"",
    "cellular $Iface sms send $Number `"$Message`"",
    "cellular $ifaceNoPrefix sms send $Number `"$Message`""
  )

  $outs = Run-CiscoCommands -Ip $Ip -User $User -Pass $Pass -Port $Port -TimeoutSec $TimeoutSec -Commands $cmds

  $ok = $false
  foreach ($o in $outs) {
    if ($o.Output -match '(?im)\b(OK|Message sent|SMS sent)\b') { $ok = $true; break }
    if ($o.Output -notmatch '(?im)(invalid input detected|incomplete command|unknown command|error)') {
      # best-effort accept (some images print nothing on success)
      $ok = $true; break
    }
  }
  [pscustomobject]@{ Success = $ok; Raw = $outs }
}

# ------------- MAIN -------------
try {
  Ensure-PoshSsh
  if (-not $Password -and $PasswordPlain) {
    $Password = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
  }

  if ($PSCmdlet.ParameterSetName -eq 'File') {
    if (-not (Test-Path $RouterList)) { throw "RouterList file not found: $RouterList" }
    $Routers = Get-Content -Path $RouterList | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_.Trim() }
  }

  $results = @()

  foreach ($ip in $Routers) {
    Write-Host "==== $ip ====" -ForegroundColor Cyan
    try {
      # Find Cellular interfaces
      $probe = Run-CiscoCommands -Ip $ip -User $Username -Pass $Password -Port $Port -TimeoutSec $TimeoutSec -Commands @(
        "show ip interface brief | include Cellular"
      )
      $ifText = $probe[0].Output
      $ifaces = Get-CellularInterfacesFromText -Text $ifText

      if (-not $ifaces -or $ifaces.Count -eq 0) {
        Write-Host "No Cellular interface found." -ForegroundColor Yellow
        $results += [pscustomobject]@{
          RouterIP = $ip; Ifaces = @(); ICCID = $null; SMSAttempted = $false; SMSSuccess = $false; SentTo = ""; Note = "No Cellular iface"
        }
        continue
      }

      $foundIccid = $null
      $usedIface  = $null
      foreach ($iface in $ifaces) {
        Write-Host "Found $iface; reading ICCID..."
        $iccid = Get-ICCID -Ip $ip -User $Username -Pass $Password -Port $Port -TimeoutSec $TimeoutSec -Iface $iface
        if ($iccid) { $foundIccid = $iccid; $usedIface = $iface; break }
      }

      if (-not $foundIccid) {
        Write-Host "ICCID not found (will still try to send SMS)." -ForegroundColor Yellow
      } else {
        Write-Host "ICCID: $foundIccid" -ForegroundColor Green
      }

      $sentAny   = $false
      $perNumber = @()
      if (-not $NoSend) {
        $ifaceToUse = if ($usedIface) { $usedIface } else { $ifaces[0] }
        $msg = "From $ip ICCID $foundIccid"

        # primary + secondary (dedup, ignore blanks)
        $targets = @($Number, $SecondaryNumber) |
                   Where-Object { $_ -and $_.Trim() -ne '' } |
                   Select-Object -Unique

        foreach ($dst in $targets) {
          $res = Send-SMS -Ip $ip -User $Username -Pass $Password -Port $Port -TimeoutSec $TimeoutSec `
                          -Iface $ifaceToUse -Number $dst -Message $msg
          $ok = [bool]$res.Success
          $perNumber += [pscustomobject]@{ Number = $dst; Success = $ok; Raw = $res.Raw }
          if ($ok) {
            $sentAny = $true
            Write-Host "SMS SENT to $dst" -ForegroundColor Green
          } else {
            Write-Host "SMS send may have failed to $dst. Check Raw output." -ForegroundColor Yellow
          }
        }
      } else {
        Write-Host "NoSend set: skipping SMS."
      }

      $results += [pscustomobject]@{
        RouterIP     = $ip
        Ifaces       = ($ifaces -join ', ')
        ICCID        = $foundIccid
        SMSAttempted = (-not $NoSend)
        SMSSuccess   = $sentAny     # true if ANY destination succeeded
        SentTo       = ($perNumber | ForEach-Object { "$($_.Number):$($_.Success)" }) -join '; '
        Note         = if ($NoSend) {"Detection only"} else {"Tried via gsm/lte path"}
        RawSMS       = $perNumber   # contains Raw outputs per number
      }
    }
    catch {
      Write-Warning ("Error on {0}: {1}" -f $ip, $_.Exception.Message)
      $results += [pscustomobject]@{
        RouterIP     = $ip
        Ifaces       = $null
        ICCID        = $null
        SMSAttempted = $false
        SMSSuccess   = $false
        SentTo       = ""
        Note         = ("Error: " + $_.Exception.Message)
      }
    }
  }

  # Show table
  $results | Select-Object RouterIP, Ifaces, ICCID, SMSAttempted, SMSSuccess, SentTo, Note | Format-Table -AutoSize

  # Return objects
  $results
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}