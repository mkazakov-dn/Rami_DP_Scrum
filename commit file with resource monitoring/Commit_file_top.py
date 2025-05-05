import datetime
import sys
import time
import threading
import Class_SSH_Con
import re


TOP_MEM_EXEC = "top -n 1 -b | grep 'MiB Me'"
TOP_CPU_EXEC = 'top -n 1 -b | grep "%Cpu(s)"'
MEMORY_RE_PARSER = r"MiB Mem\s+:\s+(\d+\.\d+)\s+total,\s+(\d+\.\d+)\s+free"
CPU_RE_PARSER = r"%Cpu\(s\): (\d+\.\d+) us"


class LLDP_Enable(Class_SSH_Con.BaseConnector):

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


class Commit_with_htop(Class_SSH_Con.BaseConnector):

    def __init__(self, ip, username, interface=None):
        super().__init__(ip, username, interface)
        self.host_connection: Class_SSH_Con.SSH_Conn = Class_SSH_Con.SSH_Conn(host=self.ip, authentication=None,
                                                                              localized_exec=True,
                                                                              session_log='test_con_2.log',
                                                                              icmp_test=True)
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        self.host_connection.connect()
        self.host_connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.HOST)
        self.stop_monitoring = threading.Event()

    def parse_memory_stat(self, memory_stat):
        # regex pattern to extract total and free memory
        match = re.search(MEMORY_RE_PARSER, memory_stat)

        # If a match is found, format the string accordingly
        if match:
            total_memory, free_memory = match.groups()
            return f"MiB Mem: {free_memory} free out of {total_memory} total"
        else:
            return memory_stat  # return original string if no match is found

    def parse_cpu_stat(self, cpu_stat):
        # regex pattern to extract the 'us' value
        match = re.search(CPU_RE_PARSER, cpu_stat)

        # If a match is found, format the string accordingly
        if match:
            us_value = match.group(1)
            return f"%Cpu(s): {us_value} us"
        else:
            return cpu_stat  # return original string if no match is found

    def exec_top_mode_mem(self):
        cmd = [TOP_MEM_EXEC, TOP_CPU_EXEC]
        MKaz = self.host_connection.exec_command(cmd=cmd, output_object_type=dict, timeout=3000)

        memory_stat = self.parse_memory_stat(MKaz.get(TOP_MEM_EXEC, [""])[0].strip())
        cpu_stat = self.parse_cpu_stat(MKaz.get(TOP_CPU_EXEC, [""])[0].strip())
        current_time = datetime.datetime.now().strftime('%H:%M:%S')

        with open('../top_results.txt', 'a') as f:
            f.write(f' At {current_time} memory util was {memory_stat}, The cpu is {cpu_stat}\n')

    def load_and_commit_config(self, filename):
        self.host_connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.HOST)
        # Start monitoring during both operations
        self.begin_monitoring()
        try:
            self.connection.exec_command(cmd=f'load override {filename}', timeout=3600)
        except:
            print(f'Loading failed for file {filename}, Check if file exists please. Exiting program')
            sys.exit(0)

        # Log separation message
        with open('../top_results.txt', 'a') as f:
            f.write('\n----- Switching to commit operation -----\n')

        self.connection.commit_cfg(timeout=3600, commit_check=False)
        with open('../top_results.txt', 'a') as f:
            f.write('\n----- Finished commit operation -----\n')
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

    def monitor_top_mode_mem(self):
        while not self.stop_monitoring.is_set():
            self.exec_top_mode_mem()
            time.sleep(5)


if __name__ == '__main__':
    #with open('../top_results.txt', 'w') as f:  # Clear the file for fresh results
    #    f.write('')
    #Marker = Commit_with_htop('dn40-cl-301a-ncc0', 'dnroot')
    #interfaces = Marker.get_interfaces()
    print('hello')
    # Config_file = 'Automator'
    # Marker.load_and_commit_config(Config_file)
    # HTOP_ACess_host()
