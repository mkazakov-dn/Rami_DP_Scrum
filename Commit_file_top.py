import datetime
import sys
import time
import threading
from collections import OrderedDict
from .Class_SSH_Con import SSH_Conn
import re

INTERFACE_REGEX = r'\bge\d+-\d+/\d+/\d+\b'


class BaseConnector():

    def __init__(self, ip, username, interface=None):
        self.ip = ip
        self.username = username
        self.interface = '' if interface is None else interface

        try:
            self.connection: SSH_Conn = SSH_Conn(host=self.ip, authentication=None, localized_exec=True,
                                                 session_log='test_con.log',
                                                 icmp_test=True)
            self.connection.connect()

        except Exception as e:
            print(f'Error: {e}')
            self.connection: SSH_Conn = None

    def get_interfaces(self, *args):
        if self.connection is None:
            print('Error: Connection failed')
            return
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_SHOW)
        output = self.connection.exec_command(cmd=f'show interfaces {args}' if args else 'show interfaces', timeout=100)
        interfaces = re.findall(INTERFACE_REGEX, output)
        # Convert to a set and back to a list to remove duplicates
        interfaces = list(OrderedDict.fromkeys(interfaces))
        return interfaces

    def backup_config(self):
        if self.connection is None:
            print('Error: Connection failed')
            return
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        self.connection.exec_command('save Automated_Snapshot')

    def load_override_factory_default(self):
        if self.connection is None:
            print('Error: Connection failed')
            return
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        self.connection.exec_command('load override factory default')

    def load_merge_config(self, filename):
        if filename is None:
            filename = 'Automator'
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        if not self.connection.exec_command(cmd=f'load merge {filename}',timeout=3600):
            print(f'Failed to load config')
        else:
            print(f'Load overriding original config prior to changes.')
            if not self.connection.commit_cfg():
                print(f'Commit FAILED please reffer to test_con_log')
                sys.exit(1)


class LLDP_Enable(BaseConnector):

    def __init__(self, ip, username, interface=None):
        super().__init__(ip, username, interface)



    def configure_lldp(self):
        # What interfaces exist
        interfaces = self.get_interfaces()
        # As a start every interface configured with fec none and admin-enabled
        for interface in interfaces:
            if self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG):
                # Im in config
                lldp_interface = [f'interface {interface} admin-state enabled fec rs-fec-528-514',
                                  f'protocols lldp interface {interface} ^']
                self.connection.exec_command(cmd=lldp_interface)

        # commit the config
        if not self.connection.commit_cfg(timeout=30):
            return False

        time.sleep(10)

        up_interfaces = self.get_interfaces('| inc up')
        if len(up_interfaces) == 0:
            print('failed to bring interfaces to Up state')


class Commit_with_htop(BaseConnector):

    def __init__(self, ip, username, interface=None):
        super().__init__(ip, username, interface)
        self.host_connection: SSH_Conn = SSH_Conn(host=self.ip, authentication=None, localized_exec=True,
                                                  session_log='test_con_2.log',
                                                  icmp_test=True)
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        self.host_connection.connect()
        self.host_connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.HOST)
        self.stop_monitoring = threading.Event()

    def load_and_commit_config(self, filename):
        self.host_connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.HOST)
        # Start monitoring during both operations
        self.begin_monitoring()

        self.connection.exec_command(cmd=f'load override {filename}', timeout=3600)

        # Log separation message
        with open('top_results.txt', 'a') as f:
            f.write('\n----- Switching to commit operation -----\n')

        self.connection.commit_cfg(timeout=3600, commit_check=False)
        self.connection.disconnect()
        self.host_connection.disconnect()
        self.end_monitoring()

    def begin_monitoring(self):
        self.stop_monitoring.clear()
        self.monitor_thread = threading.Thread(target=self.monitor_top_mode_mem)
        self.monitor_thread.start()

    def end_monitoring(self):
        self.stop_monitoring.set()
        self.monitor_thread.join()

    def exec_top_mode_mem(self):
        cmd = ["top -n 1 -b | grep 'MiB Me'", 'top -n 1 -b | grep "%Cpu(s)"']
        MKaz = self.host_connection.exec_command(cmd=cmd, output_object_type=dict, timeout=3000)

        memory_stat = MKaz.get("top -n 1 -b | grep 'MiB Me'", [""])[0].strip()
        cpu_stat = MKaz.get('top -n 1 -b | grep "%Cpu(s)"', [""])[0].strip()
        current_time = datetime.datetime.now().strftime('%H:%M:%S')

        with open('top_results.txt', 'a') as f:
            f.write(f' At {current_time} memory util was {memory_stat}, The cpu is {cpu_stat}\n')

    def monitor_top_mode_mem(self):
        while not self.stop_monitoring.is_set():
            self.exec_top_mode_mem()
            time.sleep(5)


if __name__ == '__main__':
    with open('top_results.txt', 'w') as f:  # Clear the file for fresh results
        f.write('')
    Marker = Commit_with_htop('WJ31B77Y00003A2', 'dnroot')
    Config_file = 'Automator'
    Marker.load_and_commit_config(Config_file)
    #HTOP_ACess_host()