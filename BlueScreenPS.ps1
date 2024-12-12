$logo = "
             ___
 ______     /  /
/_____/    /  /
/_____/   (  (
           \  \
            \__\"
Write-Host $logo " Welcome to BlueScreen PWSH.
Collecting Info, Please Wait..."

$Passwords = "Zeus", "Athena", "Apollo", "Anubis", "Medusa", "Odin", "Hercules", "Aphrodite", "Poseidon", "Krishna",
             "Ra", "Shiva", "Hades", "Freyja", "Persephone", "Loki", "Artemis", "Osiris", "Horus", "Ganesh",
             "Amaterasu", "Fenrir", "Hera", "Kali", "Baldur", "Quetzalcoatl", "Durga", "Thor", "Hestia", "Gaea",
             "Uranus", "Pontus", "Horus", "Atlas", "Oceanus", "Cronus", "Nyx", "Zephyrus", "Morpheus", "Pallas",
             "Pontus", "Tartarus", "Ares", "Castor", "Chaos", "Crios", "Dionysus", "Helios", "Hyperion", "Hypnos"

$characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+"




$WinVer = [System.Environment]::OSVersion.Platform
$hostname = hostname
$user = whoami
#find command for this that works please
$ipaddr = "No Clue RN"

Write-Host "Version:"$WinVer 
Write-Host "Hostname:"$hostname
Write-Host "User:"$user
Write-Host "IP Address:"$ipaddr

