<# 
.SYNOPSIS
  Check Cisco router for Cellular/LTE presence via SSH or Console.

.EXAMPLES
  # SSH (password)
  .\Check-LTE.ps1 -IpAddress 192.168.18.43 -Username admin -Password (Read-Host -AsSecureString 'Password')

  # SSH (plain password – convenience)
  .\Check-LTE.ps1 -IpAddress 192.168.18.43 -Username admin -PasswordPlain 'Bryan2011'

  # Console (typical Cisco console 9600 baud)
  .\Check-LTE.ps1 -ComPort COM5 -BaudRate 9600

  # Console with enable password (if device prompts)
  .\Check-LTE.ps1 -ComPort COM5 -BaudRate 9600 -EnablePasswordPlain 'cisco'
#>

[CmdletBinding(DefaultParameterSetName='SSH')]
param(
  # === SSH mode ===
  [Parameter(Mandatory=$true, ParameterSetName='SSH')]
  [string]$IpAddress,

  [Parameter(Mandatory=$true, ParameterSetName='SSH')]
  [string]$Username,

  [Parameter(Mandatory=$false, ParameterSetName='SSH')]
  [securestring]$Password,

  [Parameter(Mandatory=$false, ParameterSetName='SSH')]
  [string]$PasswordPlain,

  [Parameter(Mandatory=$false, ParameterSetName='SSH')]
  [string]$KeyFile,

  [Parameter(Mandatory=$false, ParameterSetName='SSH')]
  [int]$Port = 22,

  # === Console/Serial mode ===
  [Parameter(Mandatory=$true, ParameterSetName='Serial')]
  [string]$ComPort,

  [Parameter(Mandatory=$false, ParameterSetName='Serial')]
  [int]$BaudRate = 9600,

  [Parameter(Mandatory=$false, ParameterSetName='Serial')]
  [string]$EnablePasswordPlain
)

function ConvertTo-Plain {
  param([securestring]$Secure)
  if (-not $Secure) { return $null }
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Invoke-CiscoOverSSH {
  param(
    [string]$Ip, [string]$User, [securestring]$SecurePass, [string]$Key, [int]$Port
  )
  if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    throw "Posh-SSH module not found. Install it with: Install-Module Posh-SSH -Scope CurrentUser"
  }
  Import-Module Posh-SSH -ErrorAction Stop

  $sessParams = @{
    ComputerName = $Ip
    Port         = $Port
    Credential   = (New-Object System.Management.Automation.PSCredential($User, $SecurePass))
    AcceptKey    = $true
    ConnectionTimeout = 15
  }
  if ($Key) { $sessParams['KeyFile'] = $Key }

  $session = New-SSHSession @sessParams
  try {
    # Avoid pagination
    Invoke-SSHCommand -SSHSession $session -Command "terminal length 0" | Out-Null

    $ifOut = (Invoke-SSHCommand -SSHSession $session -Command "show ip interface brief | include Cellular").Output -join "`n"
    $invOut = (Invoke-SSHCommand -SSHSession $session -Command "show inventory").Output -join "`n"

    [pscustomobject]@{
      Method          = "SSH"
      Target          = $Ip
      InterfacesText  = $ifOut
      InventoryText   = $invOut
    }
  }
  finally {
    if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
  }
}

function Invoke-CiscoOverSerial {
  param(
    [string]$PortName, [int]$Baud, [string]$EnablePassword
  )
  $sp = [System.IO.Ports.SerialPort]::new($PortName, $Baud, 'None', 8, 'One')
  $sp.NewLine = "`r"
  $sp.ReadTimeout = 4000
  $sp.WriteTimeout = 4000

  $readAll = {
    Start-Sleep -Milliseconds 200
    $buf = New-Object System.Text.StringBuilder
    while ($sp.IsOpen -and $sp.BytesToRead -gt 0) {
      $buf.Append($sp.ReadExisting()) | Out-Null
      Start-Sleep -Milliseconds 100
    }
    $buf.ToString()
  }

  $send = {
    param($cmd)
    $sp.DiscardInBuffer()
    $sp.WriteLine($cmd)
    Start-Sleep -Milliseconds 400
    & $readAll
  }

  try {
    $sp.Open()
    # Wake the console
    $sp.Write("`r`r") ; Start-Sleep -Milliseconds 500
    $banner = & $readAll

    # Try to get into enable if needed (best-effort)
    $resp = & $send "enable"
    if ($resp -match "Password:") {
      if ($EnablePassword) {
        $sp.WriteLine($EnablePassword)
        Start-Sleep -Milliseconds 400
        $resp = & $readAll
      } else {
        # Try blank
        $sp.WriteLine("")
        Start-Sleep -Milliseconds 300
        $resp = & $readAll
      }
    }

    # No paging
    & $send "terminal length 0" | Out-Null

    $ifOut  = & $send "show ip interface brief | include Cellular"
    $invOut = & $send "show inventory"

    [pscustomobject]@{
      Method          = "Console"
      Target          = $PortName
      InterfacesText  = $ifOut
      InventoryText   = $invOut
    }
  }
  finally {
    if ($sp.IsOpen) { $sp.Close() }
    $sp.Dispose()
  }
}

function Test-LTEPresence {
  param([string]$InterfacesText, [string]$InventoryText)

  # Interfaces: any Cellular* present?
  $hasCellInIf = ($InterfacesText -match '(?im)\bCellular\d(?:/\d/\d)?\b')

  # Inventory: look for LTE/cellular module hints
  $hasCellInInv = $false
  if ($InventoryText) {
    $hasCellInInv = ($InventoryText -match '(?im)\b(LTE|Cellular|EHWIC-.*LTE|4G-LTE|3G|MC77|MC73|Sierra|Quectel|Huawei)\b')
  }

  [pscustomobject]@{
    CellularInInterfaces = $hasCellInIf
    CellularInInventory  = $hasCellInInv
    Detected             = ($hasCellInIf -or $hasCellInInv)
  }
}

# === MAIN ===
try {
  if ($PSCmdlet.ParameterSetName -eq 'SSH') {
    if (-not $Password -and $PasswordPlain) {
      $Password = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
    }
    if (-not $Password -and -not $KeyFile) {
      throw "Provide -Password / -PasswordPlain or -KeyFile for SSH."
    }
    $raw = Invoke-CiscoOverSSH -Ip $IpAddress -User $Username -SecurePass $Password -Key $KeyFile -Port $Port
  } else {
    $raw = Invoke-CiscoOverSerial -PortName $ComPort -Baud $BaudRate -EnablePassword $EnablePasswordPlain
  }

  $result = Test-LTEPresence -InterfacesText $raw.InterfacesText -InventoryText $raw.InventoryText

  if ($result.Detected) {
    Write-Host "LTE Card is detected" -ForegroundColor Green
  } else {
    Write-Host "LTE Card not detected" -ForegroundColor Yellow
  }

  # Print quick summaries
  Write-Host ("`n=== Summary ({0} => {1}) ===" -f $raw.Method, $raw.Target)
  Write-Host ("Cellular in interfaces : {0}" -f ($result.CellularInInterfaces))
  Write-Host ("Cellular in inventory  : {0}" -f ($result.CellularInInventory))

  # Optional: show the matched lines/snippets
  if ($raw.InterfacesText) {
    Write-Host "`n-- Interfaces (Cellular lines) --"
    ($raw.InterfacesText -split "`r?`n") | Where-Object { $_ -match 'Cellular' } | ForEach-Object { Write-Host $_ }
  }
  if ($raw.InventoryText) {
    Write-Host "`n-- Inventory (matched hints) --"
    ($raw.InventoryText -split "`r?`n") | Where-Object { $_ -match '(LTE|Cellular|EHWIC|4G|3G|MC77|MC73|Sierra|Quectel|Huawei)' } | ForEach-Object { Write-Host $_ }
  }

  # Return a structured object (handy for exporting to CSV/Excel later)
  [pscustomobject]@{
    Method               = $raw.Method
    Target               = $raw.Target
    CellularInInterfaces = $result.CellularInInterfaces
    CellularInInventory  = $result.CellularInInventory
    Detected             = $result.Detected
  }
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}