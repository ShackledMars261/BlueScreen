# BlueScreen
Dedicate Repository for rapid hardening of vulnerable systems. 
Recommended use is to paste the single line creation command from the txt into the CLI.

## Functions Include
- Password Reset All Users
- SSH Banner Creation
- SSH Config (Allowed Users)
- Firewall Config and Lockdown (Iptables, as well as iptables persist install)
- Disabling of IPv6 (Why Lockdown 4 and leave 6 up?)
- Shadow & Root Files Lockdown
- Who monitoring and kill
- Update all services

## Menu
(Hit Ctrl+C at any time to exit or return to previous menu)
### Main Menu
- 1 Run Lockdown
   - Runs all function in the most efficient order possible to reduce surface area of attack in the shortest amount of time.
- 2 Configure Services
  - Opens Secondary Menu, allowing configuration of each service independently
    - 1 Configure SSH
    - 2 Configure Firewall
    - 3 Lockdown Shadow Root
    - 4 Update All Services
    - 5 Password Reset
- 3 Wack A Red Teamer
  - True/False Non-Friendlies on account, if true will kick all users except you even on same username, if false will leave other users on the same name alone. Will continuously kick any users that are not permitted if they somehow get in. Also sends a fun message to the kicked user: '<<< Exterminate! >>>'

## Important Things to know
- Firewall config (ip-tables) will disable all connections you do not explicity allow
- It is recommended you always allow 80, and 443 on the default gateway so you can run updates!
- Update Services is ran in a secondary thread during lockdown config, it is recommended you always run lockdown first in order to update services ASAP
- Password follow the format Godnamehere_{6 Random Characters}, this makes it easy to reference in a competition environment without giving away the actual password. 
