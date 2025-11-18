<# 
Allied-Failover-G0-Primary.ps1  (PowerShell 5.1, CONSOLE ONLY)

Connection:
- User is asked:
    1) COM1 (Serial)
    2) COM3 (USB)
- Script then opens that COM port at BaudRate.

Script consists of:

1. Set G0/0 manually into IP (ask user for IP + subnet mask),
   then set G0/0 as main path and Cellular0/0/0 (or detected Cellular0/x/0)
   as failover. Reset config then add new config:

   - use ip sla 1 and remove old ip sla 1 first
   - ip sla 1
      icmp-echo <ProbeTarget> source-interface <CellularX/Y/Z>
      frequency 5
     ip sla schedule 1 life forever start-time now
   - track 20 ip sla 1 reachability
   - static routes:
      ip route 0.0.0.0 0.0.0.0 <G0-GW> 1
      ip route 0.0.0.0 0.0.0.0 <CellularX/Y/Z> 5 track 20
      ip route 1.1.1.1 255.255.255.255 <G0-GW> 9

   Where <G0-GW> is derived from the user-entered G0/0 IP:
     - if 192.168.0.x => 192.168.0.1
     - if 192.168.1.x => 192.168.1.1
     - if 10.1.1.x    => 10.1.1.1

2. Make sure Tunnel1 tunnel source is Loopback0:
   - If already Loopback0: do nothing for step 3.
   - If NOT:
       a) change Tunnel1 tunnel source into Loopback0
       b) check these route-maps exist (if not, add):
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
       c) check these NAT lines exist (if not, add):
         ip nat inside source route-map 4G-NAT-D1 interface GigabitEthernet0/0 overload
         ip nat inside source route-map 4G-NAT-D2 interface CellularX/Y/Z overload
       d) check these ACL lines exist (if not, add):
         access-list 1 permit any
         access-list 10 permit 192.168.0.0 0.0.255.255
         access-list 23 remark Permit VTY Access
         access-list 23 permit 192.168.0.0 0.0.255.255
         access-list 23 permit 10.0.0.0 0.255.255.255
         access-list 23 permit 172.16.0.0 0.0.0.255
         access-list 23 permit 172.17.0.0 0.0.255.255
         access-list 23 permit 192.168.200.0 0.0.0.255
         access-list 100 deny   ip any 10.0.0.0 0.255.255.255
         access-list 100 deny   ip any 172.16.0.0 0.15.255.255
         access-list 100 deny   ip any 172.1.0.0 0.16.255.255
         access-list 100 deny   ip any 192.168.0.0 0.0.255.255
         access-list 100 permit ip 192.168.0.0 0.0.255.255 any
         access-list 100 permit ip host 1.1.1.1 any
         access-list 101 deny   ip any 10.0.0.0 0.255.255.255
         access-list 101 deny   ip any 172.16.0.0 0.15.255.255
         access-list 101 deny   ip any 172.1.0.0 0.16.255.255
         access-list 101 deny   ip any 192.168.0.0 0.0.255.255
         access-list 101 permit ip 192.168.100.0 0.0.0.255 any
         access-list 101 permit ip host 1.1.1.1 any
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

function Derive-GatewayFromIP {
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

function Build-G0InterfaceCommands {
  param(
    [string]$G0IP,
    [string]$G0Mask
  )

  @(
    "configure terminal",
      "interface GigabitEthernet0/0",
      "no ip address",
      "ip address $G0IP $G0Mask",
      "no shutdown",
      "exit",
    "end"
  )
}

# Steps 1 + 2 + 4 (IP SLA 1 + static routes with G0 primary, Cellular backup)
function Build-FailoverAndRoutesCommands {
  param(
    [string]$G0IP,
    [string]$CellIface,
    [string]$ProbeTarget
  )

  if (-not $CellIface) {
    throw "No Cellular interface detected; cannot build failover config."
  }
  if (-not $G0IP) {
    throw "No G0/0 IP provided; cannot build routes."
  }

  $g0Gw = Derive-GatewayFromIP -G0IP $G0IP
  if (-not $g0Gw) {
    throw "Could not derive gateway from G0/0 IP $G0IP (expected 192.168.0.x / 192.168.1.x / 10.1.1.x)."
  }

  Write-Host "Derived G0/0 gateway for default + 1.1.1.1 routes: $g0Gw" -ForegroundColor Green

  $cmds = @(
    "configure terminal",

      # RESET old IP SLA 1 / track 20 / our default routes
      "no ip sla 1",
      "no track 20",
      "no ip route 0.0.0.0 0.0.0.0 $g0Gw 1",
      "no ip route 0.0.0.0 0.0.0.0 $CellIface 5 track 20",
      "no ip route 1.1.1.1 255.255.255.255 $g0Gw 9",

      # NEW IP SLA 1 (monitor via Cellular)
      "ip sla 1",
      " icmp-echo $ProbeTarget source-interface $CellIface",
      " frequency 5",
      "ip sla schedule 1 life forever start-time now",

      # Track 20 on SLA 1 reachability
      "track 20 ip sla 1 reachability",

      # Static routes:
      # 0.0.0.0/0 via G0/0 gateway (primary)
      "ip route 0.0.0.0 0.0.0.0 $g0Gw 1",

      # 0.0.0.0/0 via Cellular with track 20
      "ip route 0.0.0.0 0.0.0.0 $CellIface 5 track 20",

      # 1.1.1.1 /32 via G0/0 gateway (for DMVPN / test)
      "ip route 1.1.1.1 255.255.255.255 $g0Gw 9",

    "end",
    "write memory"
  )

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

### ---------- MAIN (CONSOLE selection + user G0/0 IP) ----------

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

  # Ask user for G0/0 IP configuration
  $g0ip   = Read-Host "Enter G0/0 IP address (e.g. 192.168.0.10)"
  $g0mask = Read-Host "Enter G0/0 subnet mask (e.g. 255.255.255.0)"

  Write-Host "Opening $portName @ $BaudRate (console)..." -ForegroundColor Cyan
  $sp = Open-Serial -PortName $portName -Baud $BaudRate

  try {
    Enter-Enable $sp | Out-Null

    # Configure G0/0 with user IP
    Write-Host "Configuring GigabitEthernet0/0 with $g0ip $g0mask..." -ForegroundColor Green
    $g0Cmds = Build-G0InterfaceCommands -G0IP $g0ip -G0Mask $g0mask
    foreach ($c in $g0Cmds) {
      Write-Host " > $c" -ForegroundColor DarkCyan
      [void](Send-Line $sp $c 8)
    }

    # Fetch running config for detection
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

    # ---- Step 1 + 2 + 4: IP SLA 1, track 20, routes ----
    $failoverCmds = Build-FailoverAndRoutesCommands -G0IP $g0ip -CellIface $cellIface -ProbeTarget $ProbeTarget

    Write-Host "Applying IP SLA 1 / track 20 / default routes configuration..." -ForegroundColor Green
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
    Write-Host "IP SLA 1 / Track 20 / Routes:" -ForegroundColor Cyan
    [void](Send-Line $sp "show ip sla summary | include 1" 10)
    [void](Send-Line $sp "show track 20" 10)
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