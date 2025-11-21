<# 
Allied-Failover-Fix.ps1  (PowerShell 5.1, CONSOLE ONLY)

Connection: 
- User is asked to choose:
    1) COM1 (Serial)
    2) COM3 (USB)
- Script then opens that COM port at the given BaudRate.

Script consists of:

1. Set Cellular0/0/0 (or detected Cellular, e.g. Cellular0/1/0) as main track for failover,
   and if fail, go to GigabitEthernet0/0 (G0/0).
   - Reset config for IP SLA 1 / track 1 / our default routes, then add new config.

2. Use ip sla 1 and remove old ip sla 1 first.

3. Make sure Tunnel1 tunnel source is Loopback0:
   - If already Loopback0: do nothing for step 3 (but steps 1 & 4 still run).
   - If NOT:
       a) Change Tunnel1 tunnel source into Loopback0.
       b) Ensure route-maps exist:
            route-map 4G-NAT-D1 permit 10
             match ip address 100
             match interface GigabitEthernet0/0
            route-map 4G-NAT-D2 permit 10
             match ip address 100
             match interface Cellular0/0/0 (we adapt to detected Cellular)
            route-map D2-Incoming permit 10
             match ip address D2-Incoming
             set ip next-hop 1.0.0.1
            route-map D1-Incoming permit 10
             match ip address D1-Incoming
             set ip next-hop 1.1.1.1
       c) Ensure NAT lines exist:
            ip nat inside source route-map 4G-NAT-D1 interface GigabitEthernet0/0 overload
            ip nat inside source route-map 4G-NAT-D2 interface CellularX/Y/Z overload
       d) Ensure ACL lines exist (1, 10, 23, 100, 101 as provided).

4. Ensure static routes exist:
      ip route 0.0.0.0 0.0.0.0 CellularX/Y/Z 5 track 1
      ip route 1.1.1.1 255.255.255.255 <G0/0-gateway> 9
      ip route 0.0.0.0 0.0.0.0 dhcp 20

   Gateway for 1.1.1.1:
     - if G0/0 IP is 192.168.0.x => 192.168.0.1
     - if G0/0 IP is 192.168.1.x => 192.168.1.1
     - if G0/0 IP is 10.1.1.x   => 10.1.1.1
#>

[CmdletBinding()]
param(
  [int]$BaudRate = 9600,
  [string]$ProbeTarget = '8.8.8.8'
)

### ---------- Serial helpers (CONSOLE) ----------

function Open-Serial {
  param([string]$PortName,[int]$Baud)
  $sp = [System.IO.Ports.SerialPort]::new($PortName, $Baud, 'None', 8, 'One')
  $sp.NewLine      = "`r"
  $sp.ReadTimeout  = 4000
  $sp.WriteTimeout = 4000
  $sp.Open()
  return $sp
}

function Read-Chunk {
  param($sp)
  $buf = New-Object System.Text.StringBuilder
  Start-Sleep -Milliseconds 150
  while ($sp.IsOpen -and $sp.BytesToRead -gt 0) {
    [void]$buf.Append($sp.ReadExisting())
    Start-Sleep -Milliseconds 80
  }
  return $buf.ToString()
}

function Expect-Prompt {
  param($sp,[int]$TimeoutSec=20)
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $all = New-Object System.Text.StringBuilder
  while ((Get-Date) -lt $deadline) {
    $part = Read-Chunk $sp
    if ($part) {
      [void]$all.Append($part)
      if ($all.ToString() -match '--More--') {
        $sp.Write(" ")
        Start-Sleep -Milliseconds 120
      }
      if ($all.ToString() -match "(?m)[\r\n].*[>#]\s*$") { break }
    } else {
      Start-Sleep -Milliseconds 120
    }
  }
  return $all.ToString()
}

function Send-Line {
  param($sp,[string]$cmd,[int]$WaitSec=5)
  $sp.DiscardInBuffer()
  $sp.WriteLine($cmd)
  Start-Sleep -Milliseconds 150
  return (Expect-Prompt $sp $WaitSec)
}

function Enter-Enable {
  param($sp)
  $sp.Write("`r"); Start-Sleep -Milliseconds 200
  $banner = Expect-Prompt $sp 8

  $out = Send-Line $sp "enable" 8
  if ($out -match "(?i)Password:") {
    $pw = Read-Host "Enable password" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    $sp.WriteLine($plain)
    Start-Sleep -Milliseconds 250
    $out2 = Expect-Prompt $sp 8
    if ($out2 -notmatch '#\s*$') {
      throw "Enable failed (no privileged prompt '#')."
    }
  } elseif ($out -match '#\s*$') {
    # already privileged
  } else {
    $out2 = Expect-Prompt $sp 6
    if ($out2 -notmatch '#\s*$') {
      $chk = Send-Line $sp "show privilege" 6
      if ($chk -notmatch '(?i)privilege level 15' -and $chk -notmatch '#\s*$') {
        Write-Warning "Could not verify privileged mode; continuing."
      }
    }
  }

  [void](Send-Line $sp "terminal length 0" 5)
}

function Get-RunningConfig {
  param($sp)
  $sp.DiscardInBuffer()
  $sp.WriteLine("show running-config")
  $txt = Expect-Prompt $sp 60
  return $txt
}

### ---------- Detection helpers ----------

function Detect-CellularInterfaceFromConfig {
  param([string[]]$Lines)
  foreach ($ln in $Lines) {
    if ($ln -match '^\s*interface\s+(Cellular\S+)') {
      return $matches[1]
    }
  }
  return $null
}

function Detect-G0IPFromConfig {
  param([string[]]$Lines)
  $inG0 = $false
  foreach ($ln in $Lines) {
    if ($ln -match '^\s*interface\s+GigabitEthernet0/0\b') {
      $inG0 = $true
      continue
    }
    if ($inG0) {
      if ($ln -match '^\s*!') { break }
      if ($ln -match '^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+|dhcp)') {
        return $matches[1]
      }
    }
  }
  return $null
}

function Derive-GatewayFromG0IP {
  param([string]$G0IP)
  if (-not $G0IP) { return $null }

  if ($G0IP -match '^192\.168\.0\.\d+') {
    return '192.168.0.1'
  }
  elseif ($G0IP -match '^192\.168\.1\.\d+') {
    return '192.168.1.1'
  }
  elseif ($G0IP -match '^10\.1\.1\.\d+') {
    return '10.1.1.1'
  }
  else {
    return $null
  }
}

function Tunnel1-Exists {
  param([string]$RunCfg)
  return ($RunCfg -match '(?m)^interface Tunnel1\b')
}

function Tunnel1-HasLoopbackSource {
  param([string]$RunCfg)
  return ($RunCfg -match '(?ms)^interface Tunnel1\s+.*?^\s*tunnel source Loopback0\b')
}

### ---------- Config builders ----------

# Steps 1 + 2 + 4 (IP SLA 1 + static routes)
function Build-FailoverAndRoutesCommands {
  param(
    [string]$CellIface,
    [string]$BackupIf,
    [string]$ProbeTarget,
    [string[]]$RunLines
  )

  if (-not $CellIface) {
    throw "No Cellular interface detected; cannot build failover config."
  }

  # Detect G0/0 IP and derive gateway for the 1.1.1.1 route
  $g0IP = Detect-G0IPFromConfig -Lines $RunLines
  $g0Gw = Derive-GatewayFromG0IP -G0IP $g0IP
  if ($g0IP) {
    Write-Host "Detected G0/0 IP: $g0IP" -ForegroundColor Green
  } else {
    Write-Warning "Could not detect G0/0 IP from running-config."
  }
  if ($g0Gw) {
    Write-Host "Derived G0/0 gateway for 1.1.1.1 route: $g0Gw" -ForegroundColor Green
  } else {
    Write-Warning "Could not derive G0/0 gateway; 1.1.1.1 /32 route will be skipped if gateway is unknown."
  }

  $cmds = @(
    "configure terminal",

      # RESET old IP SLA 1 / track 1 / our default routes
      "no ip sla 1",
      "no track 1",
      "no ip route 0.0.0.0 0.0.0.0 Cellular0/0/0 5 track 1",
      "no ip route 0.0.0.0 0.0.0.0 Cellular0/1/0 5 track 1",
      "no ip route 0.0.0.0 0.0.0.0 $BackupIf 20",
      "no ip route 0.0.0.0 0.0.0.0 dhcp 20",

      # NEW IP SLA 1
      "ip sla 1",
      " icmp-echo $ProbeTarget source-interface $CellIface",
      " frequency 5",
      "ip sla schedule 1 life forever start-time now",

      "track 1 ip sla 1 reachability",

      # Static routes:
      # 0.0.0.0/0 via Cellular (tracked)
      "ip route 0.0.0.0 0.0.0.0 $CellIface 5 track 1",

      # 0.0.0.0/0 via DHCP with higher AD
      "ip route 0.0.0.0 0.0.0.0 dhcp 20"
  )

  # 1.1.1.1/32 via derived gateway (if we could derive)
  if ($g0Gw) {
    $cmds += "ip route 1.1.1.1 255.255.255.255 $g0Gw 9"
  }

  $cmds += "end"
  $cmds += "write memory"

  return $cmds
}

# Step 3: Tunnel1 / route-maps / NAT / ACLs (only if Tunnel1 source != Loopback0)
function Build-TunnelAndNatCommandsIfNeeded {
  param(
    [string]$RunCfg,
    [string]$CellIface
  )

  $runLines = $RunCfg -split "`r?`n"

  if (-not (Tunnel1-Exists -RunCfg $RunCfg)) {
    Write-Warning "interface Tunnel1 not found; step 3 (Tunnel/NAT/ACLs) will be skipped."
    return @()
  }

  if (Tunnel1-HasLoopbackSource -RunCfg $RunCfg) {
    Write-Host "Tunnel1 already has 'tunnel source Loopback0'. Step 3 (Tunnel/NAT/ACLs) not needed." -ForegroundColor Green
    return @()
  }

  Write-Host "Tunnel1 is NOT using Loopback0 as tunnel source. Building fix for Tunnel1 + route-maps + NAT + ACLs..." -ForegroundColor Yellow

  # Route-map blocks (using detected Cellular for the 4G-NAT-D2 interface)
  $routeMapBlocks = @(
    ,@(
      "route-map 4G-NAT-D1 permit 10",
      " match ip address 100",
      " match interface GigabitEthernet0/0"
    )
    ,@(
      "route-map 4G-NAT-D2 permit 10",
      " match ip address 100",
      " match interface $CellIface"
    )
    ,@(
      "route-map D2-Incoming permit 10",
      " match ip address D2-Incoming",
      " set ip next-hop 1.0.0.1"
    )
    ,@(
      "route-map D1-Incoming permit 10",
      " match ip address D1-Incoming",
      " set ip next-hop 1.1.1.1"
    )
  )

  # NAT lines
  $natLines = @(
    "ip nat inside source route-map 4G-NAT-D1 interface GigabitEthernet0/0 overload",
    "ip nat inside source route-map 4G-NAT-D2 interface $CellIface overload"
  )

  # ACL lines
  $aclLines = @(
    "access-list 1 permit any",
    "access-list 10 permit 192.168.0.0 0.0.255.255",
    "access-list 23 remark Permit VTY Access",
    "access-list 23 permit 192.168.0.0 0.0.255.255",
    "access-list 23 permit 10.0.0.0 0.255.255.255",
    "access-list 23 permit 172.16.0.0 0.0.0.255",
    "access-list 23 permit 172.17.0.0 0.0.255.255",
    "access-list 23 permit 192.168.200.0 0.0.0.255",
    "access-list 100 deny   ip any 10.0.0.0 0.255.255.255",
    "access-list 100 deny   ip any 172.16.0.0 0.15.255.255",
    "access-list 100 deny   ip any 172.1.0.0 0.16.255.255",
    "access-list 100 deny   ip any 192.168.0.0 0.0.255.255",
    "access-list 100 permit ip 192.168.0.0 0.0.255.255 any",
    "access-list 100 permit ip host 1.1.1.1 any",
    "access-list 101 deny   ip any 10.0.0.0 0.255.255.255",
    "access-list 101 deny   ip any 172.16.0.0 0.15.255.255",
    "access-list 101 deny   ip any 172.1.0.0 0.16.255.255",
    "access-list 101 deny   ip any 192.168.0.0 0.0.255.255",
    "access-list 101 permit ip 192.168.100.0 0.0.0.255 any",
    "access-list 101 permit ip host 1.1.1.1 any"
  )

  $cmds = @("configure terminal")

  # 3a) Tunnel1 -> Loopback0
  $cmds += @(
    "interface Tunnel1",
    "tunnel source Loopback0",
    "exit"
  )

  # 3b) Route-maps
  foreach ($block in $routeMapBlocks) {
    $top = $block[0]
    if (-not ($runLines -contains $top)) {
      Write-Host "Route-map block missing: $top (will add full block)" -ForegroundColor Yellow
      $cmds += $block
    }
  }

  # 3c) NAT lines
  foreach ($line in $natLines) {
    if (-not ($runLines -contains $line)) {
      Write-Host "NAT line missing: $line (will add)" -ForegroundColor Yellow
      $cmds += $line
    }
  }

  # 3d) ACL lines
  foreach ($line in $aclLines) {
    if (-not ($runLines -contains $line)) {
      Write-Host "ACL line missing: $line (will add)" -ForegroundColor Yellow
      $cmds += $line
    }
  }

  $cmds += "end"
  $cmds += "write memory"

  return $cmds
}

### ---------- MAIN (CONSOLE selection) ----------

try {
  Write-Host "Select console port:" -ForegroundColor Cyan
  Write-Host "  1) COM1 (Serial)" -ForegroundColor Cyan
  Write-Host "  2) COM3 (USB)"    -ForegroundColor Cyan
  $choice = Read-Host "Enter 1 or 2"
  switch ($choice) {
    '1' { $portName = 'COM1' }
    '2' { $portName = 'COM3' }
    default { throw "Invalid choice. Please run again and choose 1 or 2." }
  }

  Write-Host "Opening $portName @ $BaudRate (console)..." -ForegroundColor Cyan
  $sp = Open-Serial -PortName $portName -Baud $BaudRate

  try {
    Enter-Enable $sp | Out-Null

    Write-Host "Fetching running-config (for detection)..." -ForegroundColor Cyan
    $runCfg   = Get-RunningConfig $sp
    $runLines = $runCfg -split "`r?`n"

    # Detect Cellular interface
    $cellIface = Detect-CellularInterfaceFromConfig -Lines $runLines
    if (-not $cellIface) {
      Write-Warning "No 'interface Cellular...' found in config; probing Cellular0/0/0 and 0/1/0..."
      $probe0 = Send-Line $sp "show cellular 0/0/0 all" 8
      if ($probe0 -match '(?i)Hardware|Model|IMEI|ICCID') {
        $cellIface = "Cellular0/0/0"
      } else {
        $probe1 = Send-Line $sp "show cellular 0/1/0 all" 8
        if ($probe1 -match '(?i)Hardware|Model|IMEI|ICCID') {
          $cellIface = "Cellular0/1/0"
        }
      }
    }
    if (-not $cellIface) {
      throw "Unable to detect a working Cellular interface (0/0/0 or 0/1/0)."
    }
    Write-Host "Using Cellular interface: $cellIface" -ForegroundColor Green

    $backupIf = "GigabitEthernet0/0"
    Write-Host "Using backup interface: $backupIf" -ForegroundColor Green

    # ---- Step 1 + 2 + 4: IP SLA 1, track 1, default routes ----
    $failoverCmds = Build-FailoverAndRoutesCommands -CellIface $cellIface -BackupIf $backupIf -ProbeTarget $ProbeTarget -RunLines $runLines

    Write-Host "Applying IP SLA 1 / track 1 / default routes configuration..." -ForegroundColor Green
    foreach ($c in $failoverCmds) {
      Write-Host " > $c" -ForegroundColor DarkCyan
      [void](Send-Line $sp $c 8)
    }

    # Re-fetch running config for Tunnel / route-map / NAT / ACL checks
    $runCfg2    = Get-RunningConfig $sp
    $tunnelCmds = Build-TunnelAndNatCommandsIfNeeded -RunCfg $runCfg2 -CellIface $cellIface

    if ($tunnelCmds.Count -gt 0) {
      Write-Host "Applying Tunnel1 / route-map / NAT / ACL fixes..." -ForegroundColor Green
      foreach ($c in $tunnelCmds) {
        Write-Host " > $c" -ForegroundColor DarkCyan
        [void](Send-Line $sp $c 8)
      }
    }

    # Final summary
    Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
    Write-Host "IP SLA 1 / Track 1 / Routes:" -ForegroundColor Cyan
    [void](Send-Line $sp "show ip sla summary | include 1" 10)
    [void](Send-Line $sp "show track 1" 10)
    [void](Send-Line $sp "show ip route 0.0.0.0" 10)

    if (Tunnel1-Exists -RunCfg $runCfg2) {
      Write-Host "`nTunnel1 + NAT + ACL snippets:" -ForegroundColor Cyan
      [void](Send-Line $sp "show run | s interface Tunnel1" 10)
      [void](Send-Line $sp "show run | i ip nat inside source route-map" 10)
      [void](Send-Line $sp "show run | i ^route-map" 10)
      [void](Send-Line $sp "show access-lists 1" 10)
      [void](Send-Line $sp "show access-lists 10" 10)
      [void](Send-Line $sp "show access-lists 23" 10)
      [void](Send-Line $sp "show access-lists 100" 10)
      [void](Send-Line $sp "show access-lists 101" 10)
    }

    Write-Host "`nDone." -ForegroundColor Green
  }
  finally {
    if ($sp -and $sp.IsOpen) { $sp.Close(); $sp.Dispose() }
  }

} catch {
  Write-Error $_.Exception.Message
  exit 1
}