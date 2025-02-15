import os
import platform
import subprocess
import random
import re
import time
from threading import Thread


class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    CWHITE = '\33[37m'

banner_path = '/etc/ssh/banner'
FileLockDownCommands = [
    'chown root:shadow /etc/shadow && chmod 640 /etc/shadow',
    'chown root:root /etc/group && chmod 644 /etc/group',
    'chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow',
    'chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd',
    'chown root:root /etc/passwd- && chmod 600 /etc/passwd-',
    'chown root:root /etc/shadow- && chmod 600 /etc/shadow-',
    'chown root:root /etc/group- && chmod 600 /etc/group-',
    'chown root:root /etc/gshadow- && chmod 600 /etc/gshadow-'
]

Art = '''
   _             _             _
  | |{}___________{}| |{}___________{}| |
  | |{}___________{}| |{}___________{}| |
  | |           | |           | |
  | |           | |           | |
  | |{}___________{}| |{}___________{}| |
  | |{}___________{}| |{}___________{}| |
  | |           | |           | |
  | |           | |           | |
  <<<<<<<<<<<{}Blue Screen{}>>>>>>>>>
'''.format(
    Color.BLUE, Color.END, Color.BLUE, Color.END,
    Color.BLUE, Color.END, Color.BLUE, Color.END,
    Color.BLUE, Color.END, Color.BLUE, Color.END,
    Color.BLUE, Color.END, Color.BLUE, Color.END,
    Color.BLUE, Color.END
)

Passwords = ['Zeus', 'Athena', 'Apollo', 'Anubis', 'Medusa', 'Odin', 'Hercules',
             'Aphrodite', 'Poseidon', 'Krishna', 'Ra', 'Shiva', 'Hades', 'Freyja',
             'Persephone', 'Loki', 'Artemis', 'Osiris', 'Horus', 'Ganesh', 'Amaterasu',
             'Fenrir', 'Hera', 'Kali', 'Baldur', 'Quetzalcoatl', 'Durga', 'Thor',
             'Hestia', 'Gaea', 'Uranus', 'Pontus', 'Horus', 'Atlas', 'Oceanus',
             'Cronus', 'Nyx', 'Zephyrus', 'Morpheus', 'Pallas', 'Pontus', 'Tartarus',
             'Ares', 'Castor', 'Chaos', 'Crios', 'Dionysus', 'Helios', 'Hyperion', 'Hypnos']

characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+'
DefaultGateway = '192.168.1.1'


def command_exists(command):
    """Return the full path to the command if it exists, or None otherwise."""
    for path in os.environ.get("PATH", "").split(os.pathsep):
        full_path = os.path.join(path, command)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path
    return None

PACKAGE_MANAGER = None
def main():
    global PACKAGE_MANAGER
    if command_exists("apt-get"):
        PACKAGE_MANAGER = "apt"
    elif command_exists("dnf"):
        PACKAGE_MANAGER = "dnf"
    print(Art)
    MyOS = platform.system()
    # Decode output immediately
    Me = subprocess.Popen(['whoami'], shell=True, stdout=subprocess.PIPE).stdout.read().decode().strip()
    # Fix the decoding order for 'who am i'
    who_am_i_output = subprocess.Popen(['who am i'], shell=True, stdout=subprocess.PIPE).stdout.read().decode().strip()
    WhoAmI_parts = who_am_i_output.split()
    if len(WhoAmI_parts) >= 5:
        username = WhoAmI_parts[0]
        terminal_line = WhoAmI_parts[1]
        login_time = WhoAmI_parts[2]  # Adjust if needed
        ip_address = WhoAmI_parts[4].replace('(', '').replace(')', '')
    else:
        username = Me  # fallback
        terminal_line = ''
        login_time = ''
        ip_address = ''
    
    # Get default gateway
    default_gateway = next(line.split()[2] for line in subprocess.check_output(['ip', 'route']).decode().splitlines() if 'default' in line)

    
    print('''Detected: {}{}{}
Running As: {}{}{}
Username: {}{}{}
Terminal Line: {}{}{}
Login Time: {}{}{}
IP Address: {}{}{}
Default Gateway: {}{}{}'''.format(
        Color.CYAN, PACKAGE_MANAGER, Color.YELLOW,
        Color.GREEN, Me, Color.YELLOW,
        Color.GREEN, username, Color.YELLOW,
        Color.PURPLE, terminal_line, Color.YELLOW,
        Color.PURPLE, login_time, Color.YELLOW,
        Color.PURPLE, ip_address, Color.YELLOW,
        Color.BLUE, default_gateway, Color.END
    ))
    
    # MENU
    try:
        while True:
            Options = get_specific_input(
                int,
                '{}Choose from the Following options:{}\n'
                '1 : Run Lockdown\n'
                '2 : Configure Services\n'
                '3 : Play Wack-a-Red-Teamer\n'
                '0 : Run Internal Console{}\n>>> '.format(Color.YELLOW, Color.CYAN, Color.END)
            )
            if Options == 0:
                try:
                    while True:
                        command = get_specific_input(str, '{}BlueScreen>>>{} '.format(Color.BLUE, Color.END))
                        os.system(command)
                except KeyboardInterrupt:
                    print('Returning to Main Menu')
            elif Options == 1:  # Standard Lockdown
                command_thread = Thread(target=UpdateServices)
                command_thread.start()
                pkill_other_users(username, terminal_line, True, ip_address)
                print('{}All Non-Freindlies {}Exterminated{}.'.format(Color.YELLOW, Color.RED, Color.END))
                password_reset()
                pkill_other_users(username, terminal_line, True, ip_address)
                print('{}All Non-Freindlies {}Exterminated{}.'.format(Color.YELLOW, Color.RED, Color.END))
                lockdown_shadow_and_root()
                print('{}etc/Shadow&Passwd&Group: {}Secured{}'.format(Color.YELLOW, Color.GREEN, Color.END))
                banner_message = '''{}Hello {}Red Team{}, you have been politely {}Uninvited{} from this device. We advise you go bother someone else.{}'''.format(Color.YELLOW, Color.RED, Color.YELLOW, Color.PURPLE, Color.YELLOW, Color.END)
                create_ssh_banner(banner_message, banner_path)
                update_ssh_config(banner_path, username)
                print('{}SSHd Config:{} Updated. Banner path: {}. Only {} can SSH.'.format(
                    Color.YELLOW, Color.GREEN, banner_path, Color.GREEN + username + Color.END))
                print('{}Services Update:{} Waiting for Update Thread'.format(Color.YELLOW, Color.END))
                print('{}Services Update:{} Update Complete{}'.format(Color.YELLOW, Color.GREEN, Color.END))
                config_firewall(ip_address, DefaultGateway, username)
                print('IPv4 Firewall: {}Enabled{}'.format(Color.GREEN, Color.END))
                Errors = Install_IpTables_Persist()
                if Errors:
                    print('Errors occurred during update:')
                    for error in Errors:
                        print(Color.RED + 'Error: ' + Color.END + error)
                    Errors = []
                disable_ipv6()
                print('IPv6: {}Disabled{}'.format(Color.RED, Color.END))
                print('IPv4 Firewall: {}Config Saved{}'.format(Color.CYAN, Color.END))
                command_thread.join()
                if Errors:
                    print('Errors occurred during update:')
                    for error in Errors:
                        print(Color.RED + 'Error: ' + Color.END + error)
                    Errors = []
                pkill_other_users(username, terminal_line, True, ip_address)
                print('{}All Non-Freindlies {}Exterminated{}.'.format(Color.YELLOW, Color.RED, Color.END))
                check_services()
            elif Options == 2:  # Custom Config
                try:
                    while True:
                        ConfigOptions = get_specific_input(
                            int,
                            '{}Choose from the Following options:{}\n'
                            '1 : Configure SSH\n'
                            '2 : Configure Firewall\n'
                            '3 : Lockdown Shadow and Root\n'
                            '4 : Update All Services\n'
                            '5 : Purge Services\n'
                            '6 : Change all Passwords{}\n>>> '.format(Color.YELLOW, Color.CYAN, Color.END)
                        )
                        if ConfigOptions == 1:
                            new_banner = get_specific_input(str, 'Enter New Banner: ')
                            create_ssh_banner(new_banner, banner_path)
                            allowed_users = get_specific_input(str, 'Enter allowed Users Seperated by ,: ')
                            update_ssh_config(banner_path, allowed_users)
                        elif ConfigOptions == 2:
                            config_firewall(ip_address, DefaultGateway, username)
                            disable_ipv6()
                            print('IPv6: {}Disabled{}'.format(Color.RED, Color.END))
                            print('IPv4 Firewall: {}Config Saved{}'.format(Color.CYAN, Color.END))
                        elif ConfigOptions == 3:
                            lockdown_shadow_and_root()
                        elif ConfigOptions == 4:
                            UpdateServices()
                        elif ConfigOptions == 5:
                            check_services()
                        elif ConfigOptions == 6:
                            password_reset()
                        else:
                            print('Please choose a valid configuration option.')
                except KeyboardInterrupt:
                    print('Returning to Main Menu')
            elif Options == 3:  # Wack a Red Teamer
                try:
                    IHaveFriendlies = get_specific_input(bool_check, 'I have Non-Friendlies on my account, true/false: ')
                    print('{}Scanning For All {} Non-Friendlies{}.'.format(Color.YELLOW, Color.RED, Color.END))
                    while True:
                        pkill_other_users(username, terminal_line, IHaveFriendlies, ip_address)
                        time.sleep(0.1)
                except KeyboardInterrupt:
                    print('Returning to Main Menu')
            else:
                print('Please Choose a valid option')
    except KeyboardInterrupt:
        print('Exiting BlueScreen')

def pkill_other_users(username, terminal_line, No_Friendlies, ip_address):
    while True:
        enemy_count = 0
        who_output = subprocess.Popen(['who'], stdout=subprocess.PIPE).communicate()[0].decode().splitlines()
        for line in who_output:
            user_info = line.split()
            if len(user_info) < 2:
                continue

            if user_info[0] == username and user_info[1] == terminal_line:
                continue
            if( 'tt' in user_info[1]):
                continue
            if user_info[0] == username and not No_Friendlies:
                continue
                
            if(ip_address!=''):
                if len(user_info) >= 5 and user_info[-1].startswith('(') and user_info[-1].endswith(')'):
                    session_ip = user_info[-1].strip('()')
                    if session_ip == ip_address:
                        continue

            enemy_count += 1
            BeGone = [
                '<<< Exterminate! >>>',
                '<<<Resistence Is Futile>>>',
                '<<<We are the Borg. You will be assimilated. Resistance is futile.>>>',
                '<<<Bite Me>>>',
                '<<<Kill The Spare!>>>',
                '<<<They Never Learn. Such A Pity.>>>'
            ]
            message = random.choice(BeGone)

            # Send a message to the user on that terminal.
            write_process = subprocess.Popen(['write', user_info[0], user_info[1]],
                                             stdin=subprocess.PIPE)
            write_process.communicate(input=message.encode())

            # Kill all processes on the target terminal.
            subprocess.call(['pkill', '-9', '-t', user_info[1]])
            print('{}Exterminated:{} User {} on {}'.format(
                Color.RED, Color.END, user_info[0], user_info[1]))
        if enemy_count == 0:
            break

def Install_IpTables_Persist():
    Errors = []
    with open(os.devnull, 'w') as devnull:
        if PACKAGE_MANAGER == 'apt':
            try:
                subprocess.check_call('echo \'iptables-persistent iptables-persistent/autosave_v4 boolean true\' | debconf-set-selections',
                                        shell=True, stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
            try:
                subprocess.check_call('echo \'iptables-persistent iptables-persistent/autosave_v6 boolean true\' | debconf-set-selections',
                                        shell=True, stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
            try:
                subprocess.check_call('apt-get install iptables-persistent -y', shell=True, stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
        elif PACKAGE_MANAGER == 'dnf':
            try:
                subprocess.check_call('dnf install install iptables-persistent -y', shell=True, stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
        else:
            Errors.append('No supported package manager found.')
    with open('/etc/iptables/rules.v4', 'w') as rules_file:
        subprocess.Popen(['iptables-save'], stdout=rules_file)
    return Errors

def UpdateServices():
    Errors = []
    with open(os.devnull, 'w') as devnull:
        if PACKAGE_MANAGER == 'apt':
            try:
                subprocess.check_call(['apt-get', 'update', '-y'], stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
            try:
                subprocess.check_call(['apt-get', 'upgrade', '--fix-missing', '-y'], stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
            try:
                subprocess.check_call(['apt-get', 'upgrade', '-y'], stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
        elif PACKAGE_MANAGER == 'dnf':
            try:
                subprocess.check_call(['dnf', 'update', '-y'], stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
            try:
                subprocess.check_call(['dnf', 'upgrade', '-y'], stdout=devnull, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                Errors.append(str(e))
        else:
            Errors.append('No supported package manager found.')
    return Errors

def deny_terminal_access_to_all_users():
    passwd_file = '/etc/passwd'
    passwd_backup_file = '/etc/passwd.backup'
    if not os.path.exists(passwd_backup_file):
        with open(passwd_file, 'r') as src, open(passwd_backup_file, 'w') as dst:
            dst.writelines(src.readlines())
    with open(passwd_file, 'r') as f:
        lines = f.readlines()
    modified = False
    for i, line in enumerate(lines):
        parts = line.strip().split(':')
        if parts[-1] != '/bin/false':
            parts[-1] = '/bin/false'
            lines[i] = ':'.join(parts) + '\n'
            modified = True
    if modified:
        with open(passwd_file, 'w') as f:
            f.writelines(lines)
        print('{}Terminal Access:{} Denied for all users. #SuckItBob'.format(Color.YELLOW, Color.RED))
    else:
        print('No changes needed. All users already have terminal access denied.')

def get_specific_input(data_type, custom_text):
    try:
        myinput = raw_input
    except NameError:
        myinput = input
    while True:
        try:
            user_input = myinput(custom_text)
            data = data_type(user_input)
            return data
        except ValueError:
            print('Please enter a valid {}!'.format(data_type.__name__))

def expand_ip_range(short_ip_range):
    parts = short_ip_range.split('.')
    expanded_parts = []
    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            expanded_part = (start, end)
        else:
            expanded_part = (int(part), int(part))
        expanded_parts.append(expanded_part)
    return expanded_parts

def password_reset():
    passwd_output = subprocess.check_output(['cut', '-d:', '-f1', '/etc/passwd']).decode().strip()
    users = passwd_output.split('\n')
    if '' in users:
        users.remove('')
    for account in users:
        try:
            new_password = random.choice(Passwords) + '_' + ''.join(random.choice(characters) for _ in range(6))
            process = subprocess.Popen(['passwd', account],
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       universal_newlines=True)
            stdout, stderr = process.communicate(new_password + '\n' + new_password + '\n')
            print('User: {}{}{} \n>>Password: {}{}{}'.format(Color.YELLOW, account, Color.END, Color.YELLOW, new_password, Color.END))
        except Exception as e:
            print('User: {}{}{} \n>>Error: {}{}{}'.format(Color.YELLOW, account, Color.END, Color.RED, str(e), Color.END))

def bool_check(given):
    return str(given).lower() == 'true'

def string_to_number_list(string_numbers):
    return [int(x) for x in string_numbers.split(',')]

def config_firewall(MyIP, DefaultGateway, Username):
    subprocess.call(['iptables', '-F'])
    subprocess.call('iptables -A INPUT -s {} -j ACCEPT'.format(MyIP), shell=True)
    subprocess.call('iptables -A OUTPUT -d {} -j ACCEPT'.format(MyIP), shell=True)
    print('{}Configure Firewall: {}Preserved Access of {}{}'.format(Color.YELLOW, Color.END, Color.GREEN, Username + Color.END))
    subprocess.call(['iptables', '-P', 'INPUT', 'DROP'])
    subprocess.call(['iptables', '-P', 'FORWARD', 'DROP'])
    subprocess.call(['iptables', '-P', 'OUTPUT', 'DROP'])
    print('{}Configure Firewall: {}Default IN-OUT set to Drop{}'.format(Color.YELLOW, Color.RED, Color.END))
    DGports = get_specific_input(string_to_number_list,
                                 '{}Configure Firewall: {}Ports to allow from the default gateway. (Seperate with ,):'.format(Color.YELLOW, Color.END))
    for Port in DGports:
        subprocess.call('iptables -A INPUT -p tcp -s {} --dport {} -j ACCEPT'.format(DefaultGateway, Port), shell=True)
        subprocess.call('iptables -A OUTPUT -p tcp -d {} --dport {} -j ACCEPT'.format(DefaultGateway, Port), shell=True)
    print(('{}Default Gateway Allowed{}: {}' + ', '.join(map(str, DGports)) + '{}').format(Color.YELLOW, Color.END, Color.RED, Color.END))
    print('{}Installing{} IPTables-persistent{} to function as {}Sys-Firewall{}'.format(Color.YELLOW, Color.PURPLE, Color.END, Color.GREEN, Color.END))
    backup_dir = '/etc/iptables/'
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    with open('/etc/iptables/rules.v4.backup', 'w') as backup_file:
        subprocess.Popen(['iptables-save'], stdout=backup_file)
    print('{}Configure Firewall: {}Allowed Ports{} and {}Ip\'s{} that can connect to them:'.format(Color.YELLOW, Color.PURPLE, Color.END, Color.RED, Color.END))
    while True:
        Port = get_specific_input(int, '{}Port:{} Enter Port # or {}0{} when done:'.format(Color.YELLOW, Color.END, Color.RED, Color.END))
        if Port == 0:
            break
        UserIpInput = get_specific_input(str, '{}Port:{} {}{}{} Please enter Ips (Seperate with,):'.format(Color.YELLOW, Color.END, Color.RED, Port, Color.END))
        IPs = [ip.strip() for ip in UserIpInput.split(',')]
        if 'all' in UserIpInput.lower():
            subprocess.call('iptables -A INPUT -p tcp --dport {} -j ACCEPT'.format(Port), shell=True)
            subprocess.call('iptables -A OUTPUT -p tcp --dport {} -j ACCEPT'.format(Port), shell=True)
        elif all(len(item.split('.')) == 4 for item in IPs):
            ConfiguredIps = '{}Configured Allowed Ips on Port {}:'.format(Color.YELLOW, Port)
            for ip in IPs:
                MinMaxIP = expand_ip_range(ip)
                MinIP = '{}.{}.{}.{}'.format(MinMaxIP[0][0], MinMaxIP[1][0], MinMaxIP[2][0], MinMaxIP[3][0])
                MaxIP = '{}.{}.{}.{}'.format(MinMaxIP[0][1], MinMaxIP[1][1], MinMaxIP[2][1], MinMaxIP[3][1])
                ip_range = MinIP + '-' + MaxIP
                subprocess.call('iptables -A INPUT -p tcp --dport {} -m iprange --src-range {} -j ACCEPT'.format(Port, ip_range), shell=True)
                subprocess.call('iptables -A OUTPUT -p tcp --sport {} -m iprange --src-range {} -j ACCEPT'.format(Port, ip_range), shell=True)
                ConfiguredIps += '\n' + ip_range
            print(Color.END + ConfiguredIps)
        else:
            print('{}Configure Firewall:{} YO DUMASS, use a valid format next time: X.X.X.X,X.X-X.X-X.X-X{}'.format(Color.YELLOW, Color.END, Color.RED, Color.END))
    print('Firewall rules configured successfully.')

def disable_ipv6():
    subprocess.call('ip6tables-save > /etc/iptables/rules.v6.backup', shell=True)
    subprocess.call('ip6tables -P INPUT DROP', shell=True)
    subprocess.call('ip6tables -P FORWARD DROP', shell=True)
    subprocess.call('ip6tables -P OUTPUT DROP', shell=True)
    subprocess.call('ip6tables-save > /etc/iptables/rules.v6', shell=True)

def check_services():
    services = get_all_services()
    print('{}Found services:{}'.format(Color.YELLOW, Color.END))
    for service in services:
        print(' -', service)
    print('\n{}For each service, decide if you want to force quit it.{}\n'.format(Color.YELLOW, Color.END))
    for service in services:
        answer = get_specific_input(str,'{}Do you want to force quit {}\'{}\'{}? (y/n): {}'.format(Color.YELLOW, Color.RED, service, Color.YELLOW,Color.END)).strip().lower()
        if answer == 'y':
            force_quit_service(service)
            delete_service(service)
        else:
            print('{}Skipping: {}{}{}'.format(Color.YELLOW, Color.GREEN, service,Color.END)) 

def delete_service(service):
    cmd = ['systemctl', 'show', service, '-p', 'FragmentPath']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    fragment_line = p.communicate()[0].strip()
    
    if fragment_line.startswith('FragmentPath='):
        fragment_path = fragment_line.split('=', 1)[1]
        if fragment_path:
            print('Deleting service file at {}...'.format(fragment_path))
            subprocess.call(['sudo', 'rm', '-f', fragment_path])
            print('Reloading systemd daemon...')
            subprocess.call(['sudo', 'systemctl', 'daemon-reload'])
        else:
            print('No service file found for {}. It may be a transient or generated unit.'.format(service))
    else:
        print('Could not determine the service file for {}.'.format(service))

def get_all_services():
    cmd = ['systemctl', 'list-units', '--type=service', '--all', '--no-legend', '--no-pager']
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    output = p.communicate()[0]
    services = []
    for line in output.strip().split('\n'):
        if line:
            service = line.split()[0]
            services.append(service)
    return services

def force_quit_service(service):
    print('Force quitting {}...'.format(service))
    subprocess.call(['sudo', 'systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', service])

def lockdown_shadow_and_root():
    for command in FileLockDownCommands:
        if command.strip():
            subprocess.Popen(command, shell=True)

def backup_config(file_path):
    subprocess.Popen(['cp', file_path, file_path + '.backup'])

def create_ssh_banner(message, banner_path):
    with open(banner_path, 'w') as f:
        f.write(message)
    print('{}SSHd Config:{} Banner created at: {}'.format(Color.YELLOW, Color.END, banner_path))

def update_ssh_config(banner_path, allowed_user):
    sshd_config_path = '/etc/ssh/sshd_config'
    sshd_config_backup_path = '/etc/ssh/sshd_config.backup'
    try:
        os.rename(sshd_config_path, sshd_config_backup_path)
        with open(sshd_config_backup_path, 'r') as f_in:
            config_content = f_in.read()
        allow_users_match = re.search(r'^\s*#?\s*AllowUsers.*$', config_content, flags=re.MULTILINE)
        if allow_users_match:
            config_content = re.sub(allow_users_match.group(), 'AllowUsers {}'.format(allowed_user), config_content)
        else:
            config_content += '\nAllowUsers {}\n'.format(allowed_user)
        config_content = re.sub(r'^\s*#?\s*Banner.*$', 'Banner {}'.format(banner_path), config_content, flags=re.MULTILINE)
        with open(sshd_config_path, 'w') as f_out:
            f_out.write(config_content)
        subprocess.call(['systemctl', 'restart', 'ssh'])
    except Exception as e:
        os.rename(sshd_config_backup_path, sshd_config_path)
        print('An error occurred: {}'.format(e))

if __name__ == '__main__':
    main()
