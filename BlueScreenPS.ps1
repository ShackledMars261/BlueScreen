$logo = "
             ___
 ______     /  /
/_____/    /  /
/_____/   (  (
           \  \
            \__\"


$Passwords = "Zeus", "Athena", "Apollo", "Anubis", "Medusa", "Odin", "Hercules", "Aphrodite", "Poseidon", "Krishna",
             "Ra", "Shiva", "Hades", "Freyja", "Persephone", "Loki", "Artemis", "Osiris", "Horus", "Ganesh",
             "Amaterasu", "Fenrir", "Hera", "Kali", "Baldur", "Quetzalcoatl", "Durga", "Thor", "Hestia", "Gaea",
             "Uranus", "Pontus", "Horus", "Atlas", "Oceanus", "Cronus", "Nyx", "Zephyrus", "Morpheus", "Pallas",
             "Pontus", "Tartarus", "Ares", "Castor", "Chaos", "Crios", "Dionysus", "Helios", "Hyperion", "Hypnos"

$characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+"

$hostname = hostname
$user = whoami
$ipaddr = (Get-NetIPAddress | Where-Object { $_.AddressState -eq "Preferred" -and $_.AddressFamily -eq "IPv4" -and $_.IPAddress -NotContains "127.0.0.1"}).IPAddress
$subnet = (Get-NetIPAddress | Where-Object { $_.AddressState -eq "Preferred" -and $_.AddressFamily -eq "IPv4" -and $_.IPAddress -NotContains "127.0.0.1"}).PrefixLength

$combinedaddr = $ipaddr + "/" + $subnet

$wshell = New-Object -ComObject Wscript.Shell
$jsonPath = "$env:USERPROFILE\Desktop\script.json"
$jsonURL = "https://raw.githubusercontent.com/MCA-Dev-Team/BlueScreen/refs/heads/main/script.json"


function updatescript {
    del ~/Desktop/BlueScreenPS.ps1.temp
    Invoke-WebRequest https://raw.githubusercontent.com/MCA-Dev-Team/BlueScreen/refs/heads/main/BlueScreenPS.ps1 -OutFile ~/Desktop/BlueScreenPS.ps1.temp
    Invoke-WebRequest $jsonURL -OutFile ~/Desktop/script.json
    powershell -NoProfile -ExecutionPolicy Bypass -Command {mv -Force ~/Desktop/BlueScreenPS.ps1.temp ~/Desktop/BlueScreenPS.ps1}
    Write-Host "Script Updated!"
    Write-Host "Press any key to exit"
    [void][System.Console]::ReadKey($true)
}

function header {
    Clear-Host
    Write-Host $logo "`n`nWelcome to BlueScreen PWSH.`nCollecting Info, Please Wait..."
    Write-Host "Version:" $PSVersionTable.BuildVersion
    Write-Host "Hostname:" $hostname
    Write-Host "User:" $user
    Write-Host "IP Address:" $ipaddr
}
function prereqs {
    Write-Host "Setting up Prerequisites"
    Write-Host "Checking for and Importing AD Module"
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory
        Write-Host "AD Module is already installed"
    } else {
        Write-Host "AD Module is not installed"
        Write-Host "Installing AD Module"
        Install-Module -Name ActiveDirectory -Force
        Import-Module ActiveDirectory
    }
    Write-Host "Checking for Choco package manager"
    if (Test-Path 'C:\ProgramData\chocolatey\choco.exe') {
        Write-Host "Choco is already installed"
        choco feature enable -n allowGlobalConfirmation
        mainMenu
    } else {
        Write-Host "Choco is not installed"
        installChoco
    }
}

function installChoco {
    Write-Host "Setting up Choco package manager"
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Host "Choco Installed!"
    Write-Host "Need to restart script for Choco to work"
    Write-Host "Press any key to exit"
    [void][System.Console]::ReadKey($true)
}

function ResetPasswords {
    Get-ADUser -Filter * | ForEach-Object {
        $ADuser = $_.SamAccountName
        $newPassword = $Passwords | Get-Random -Count 1
        $newPassword | ConvertTo-SecureString -AsPlainText -Force | Set-ADAccountPassword $ADuser -NewPassword -Reset -PassThru
        Write-Host "Password for $ADuser has been reset to $newPassword"
        Write-File -Path $env:USERPROFILE\Desktop\PasswordReset.txt -InputObject "Password for $ADuser has been reset to $newPassword" -Append
    }
    Get-LocalUser -Name * | Where-Object { $_.Enabled -eq 'True' } | ForEach-Object {
        $LocalUser = $_.Name
        $newPassword = $Passwords | Get-Random -Count 1
        $newPassword | ConvertTo-SecureString -AsPlainText -Force | Set-LocalUser -Name $user -Password
    }

}

function RunWinUtil {
    Invoke-WebRequest -Uri $jsonURL -OutFile $jsonPath
    iwr christitus.com/win -OutFile $env:USERPROFILE\Desktop\WinUtil.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File $env:USERPROFILE\Desktop\WinUtil.ps1 -Config $jsonPath
    Write-Host "Press any key to exit"
    [void][System.Console]::ReadKey($true)
}

function mainMenu {
    $mainMenu = 'X'
    while($mainMenu -ne ''){
        Clear-Host
        header

        Write-Host -ForegroundColor Cyan "Main Menu"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Programs"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Updates"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Lockdown"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "4"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Update Script"


        $mainMenu = Read-Host "`nSelection (leave blank to quit)"
        # Launch submenu1
        if($mainMenu -eq 1){
            subMenu1
        }
        # Launch submenu2
        if($mainMenu -eq 2){
            subMenu2
        }
        # Launch submenu3
        if($mainMenu -eq 3){
            subMenu3
        }
        #update script
        if($mainMenu -eq 4){
            updatescript
        }

    }
}

function subMenu1 {
    $subMenu1 = 'X'
    while($subMenu1 -ne ''){
        Clear-Host
        header

        Clear-Host
        Write-Host -ForegroundColor Cyan "Programs"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Nmap"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Chromium"
        $subMenu1 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu1 -eq 1){
            Write-Host 'Installing Nmap'
            choco install nmap
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu1 -eq 2){
            choco install chromium
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}

function subMenu2 {
    $subMenu2 = 'X'
    while($subMenu2 -ne ''){
        Clear-Host
        header
        Write-Host -ForegroundColor Cyan "Updates"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Show processes"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Show PS Version"
        $subMenu2 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu2 -eq 1){
            Get-Process
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu2 -eq 2){
            $PSVersionTable.PSVersion
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}

function subMenu3 {
    $subMenu3 = 'X'
    while($subMenu3 -ne ''){
        Clear-Host
        header
        Write-Host -ForegroundColor Cyan "Lockdown"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "1"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Show processes"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "2"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Scan Subnet"
        Write-Host -ForegroundColor DarkCyan -NoNewline "`n["; Write-Host -NoNewline "3"; Write-Host -ForegroundColor DarkCyan -NoNewline "]"; `
            Write-Host -ForegroundColor DarkCyan " Run CTT WinUtil"
        $subMenu3 = Read-Host "`nSelection (leave blank to quit)"
        $timeStamp = Get-Date -Uformat %m%d%y%H%M
        # Option 1
        if($subMenu3 -eq 1){
            Get-CimInstance -Class Win32_Process | Select-Object -Property Name, HandleCount, ProcessId, ParentProcessId, Path, CommandLine, WriteTransferCount, ReadTransferCount, WorkingSetSize > $timeStamp-processes.txt
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 2
        if($subMenu3 -eq 2){
            nmap -A $ipaddress/$subnet -vv -oN $timeStamp-nmap.txt
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
        # Option 3
        if($subMenu3 -eq 3){
            $Output = $wshell.Popup("Just go to Tweaks and Hit 'Run Tweaks'")
            wget https://raw.githubusercontent.com/MCA-Dev-Team/BlueScreen/refs/heads/main/script.json > ~/Desktop/script.json
            RunWinUtil
            # Pause and wait for input before going back to the menu
            Write-Host -ForegroundColor DarkCyan "`nScript execution complete."
            Write-Host "`nPress any key to return to the previous menu"
            [void][System.Console]::ReadKey($true)
        }
    }
}
prereqs
mainMenu
