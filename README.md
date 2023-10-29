# Rami_DP_Scrum
The project is designed to have a connection handler for DriveNets devices to give the team members a way to interact with DriveNets via python.
In addition the project will share projects done by the team members.

## Getting started 
(this guide will assume you have python 3.7 running)
1. Clone the repository into your working directoy.
2. The Class_SSH_Con uses a specific library that should be installed.
3. initiate pip install netmiko

### Starting to code.

After you have both Class_SSH_Con.py and netmiko installed you should be able to run the scripts listed on Commit_file_top.py and begin writing your own scripts.
As an example let's create an new file.

That file will import the Class_SSH_Con.
from <directory_name> import <file_name>
or just import <filename> if under the same directory.

The user can create an instance of the DUT with the following command
i.e 
class BaseConnector():

    def __init__(self, ip):
        self.ip = ip
        try:
            self.connection: SSH_Conn = SSH_Conn(host=self.ip, authentication=None, localized_exec=True,
                                                 session_log='test_con.log',
                                                 icmp_test=True)
            self.connection.connect()

Now we have created self.connection that utilized the SSH_Conn method (the self.connection: SSH_Conn is important if you want auto-completion based on the functions inside the class)

From that point forward self.connection is capable of sending commands and retreiving information from the device.
In a separate function we can call the inner functions of self.connection i.e 

    def get_QoS_policies(self):
        if self.connection is None: 
            print('Error: Connection failed')
            return
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_SHOW)
        output = self.connection.exec_command(cmd=f'show conf qos | inc policy', timeout=100)
        qos_policies = re.findall(INTERFACE_REGEX, output)
        return qos_policies 

        
Same goes for configuration and commit operations 

    def configure_qos_traffic_classes(self):
        cmd = [LIST_OF_FLATTEN_COMMANDS]
        self.connection.change_mode(requested_cli=self.connection.SSH_ENUMS.CLI_MODE.DNOS_CFG)
        self.connection.exec_command(cmd=cmd, output_object_type=dict, timeout=3000)
        self.connection.commit_cfg()




In the end the instanciation should be like this 

if __name__ == '__main__':
    Marker = BaseConnector('WJ31B77Y00003A2')
    Marker.get_QoS_policies()
    Marker.configure_qos_traffic_classes
    

