from Rami_DP_Scrum import Class_SSH_Con
import re

LLDP_400G_interface = ['admin-state enabled','fec rs-fec-544-514','speed 100', 'fec rs-fec-528-514']
LLDP_100G_interface = ['admin-state enabled', 'fec rs-fec-528-514', 'fec none']
LLDP_10G_interface =  ['admin-state enabled', 'fec none']
lldp_neighbor_found = False



class LLDP_Enable(Class_SSH_Con.BaseConnector):
    LLDP_400G_interface = ['admin-state enabled', 'fec rs-fec-544-514', 'speed 100', 'fec rs-fec-528-514']
    LLDP_100G_interface = ['admin-state enabled', 'fec rs-fec-528-514', 'fec none']
    LLDP_10G_interface = ['admin-state enabled', 'fec none']
    def __init__(self, ip, username, interface=None):
        super().__init__(ip, username, interface)

    def parse_lldp_output(self,output):
        # Parsing the output into a list of dictionaries
        parsed_data = []
        for line in output.split('\n'):
            # Using regular expression to find the required fields
            match = re.search(r'\|\s*(\S+)\s*\|\s*([^|]+?)\s*\|\s*(\S+)\s*\|', line)
            if match:
                local_interface, neighbor, neighbor_interface = match.groups()
                # Skipping entries without a Neighbor value
                if neighbor.strip():
                    parsed_data.append({
                        'Local Interface': local_interface,
                        'Neighbor': neighbor,
                        'Neighbor Interface': neighbor_interface
                    })

        return parsed_data

    def retreive_lldp_neighbors(self, interface=None):
        if self.connection is None:
            print('Error: Connection failed')
            return
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_SHOW)
        if interface is None:
            output = self.connection.exec_command(cmd=f'show lldp neighbors | inc ge', timeout=100)
            parsed_output = self.parse_lldp_output(output)
        else:
            output = self.connection.exec_command(cmd=f'show lldp neighbors | inc {interface}', timeout=100)
            parsed_output = self.parse_lldp_output(output)
        return parsed_output

    def configure_interface(self, interface, commands):
        """
        Configures a given interface with a set of commands.
        """
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        for command in commands:
            self.connection.exec_command(cmd=command)
            self.connection.commit_cfg(timeout=20)
            LLDP_info = self.retreive_lldp_neighbors(interface=interface)
            if LLDP_info:
                filename = "LLDP_info.txt"
                with open(filename, 'a') as file:
                    file.write(LLDP_info, indent=4)
                return True
        return False

    def configure_lldp(self):
        self.backup_config(filename='Automated_Snapshot')
        self.load_override_factory_default()
        self.connection.commit_cfg()

        interfaces = self.get_interfaces()
        for interface in interfaces:
            if interface.startswith('ge400-'):
                if self.configure_interface(interface, self.LLDP_400G_interface):
                    continue

            elif interface.startswith('ge100-'):
                if self.configure_interface(interface, self.LLDP_100G_interface):
                    continue

            elif interface.startswith('ge10-'):
                if self.configure_interface(interface, self.LLDP_10G_interface):
                    continue



if __name__ == '__main__':
    lldp_enabler = LLDP_Enable('WDY1CBV400005', 'dnroot')
    outputer = lldp_enabler.retreive_lldp_neighbors()
    print(outputer)
