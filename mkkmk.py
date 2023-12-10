import Class_SSH_Con
import tkinter as tk
import sys
from tkinter import ttk
import ipaddress
import paramiko
from scp import SCPClient

def upload_file_scp(filename, remote_host, remote_user, remote_pass, remote_path):
    try:
        # Create an SSH client instance.
        ssh = paramiko.SSHClient()

        # Automatically add the remote host (prevents MissingHostKeyPolicy error)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote host
        ssh.connect(remote_host, username=remote_user, password=remote_pass)

        # SCPCLient takes a paramiko transport as its only argument
        scp = SCPClient(ssh.get_transport())

        # Upload the file to the remote host
        scp.put(filename, remote_path=remote_path)

        # Close the SCP instance
        scp.close()

    except Exception as e:
        print(f"An error occurred while uploading the file: {e}")


class ConfigGenerator(tk.Tk):
    def __init__(self, interfaces):
        super().__init__()

        self.interfaces = interfaces

        # Create the widgets
        self.title("Interface Config Generator")

        ttk.Label(self, text="Choose Interface:").grid(row=0, column=0, padx=10, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(self, textvariable=self.interface_var, values=self.interfaces)
        self.interface_dropdown.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(self, text="Number of Sub-Interfaces:").grid(row=1, column=0, padx=10, pady=5)
        self.num_sub_interfaces_var = tk.IntVar(value=1)
        self.num_sub_interfaces_entry = ttk.Entry(self, textvariable=self.num_sub_interfaces_var)
        self.num_sub_interfaces_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(self, text="Starting VLAN ID:").grid(row=2, column=0, padx=10, pady=5)
        self.start_vlan_var = tk.IntVar(value=1)
        self.start_vlan_entry = ttk.Entry(self, textvariable=self.start_vlan_var)
        self.start_vlan_entry.grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(self, text="VLAN Increment:").grid(row=3, column=0, padx=10, pady=5)
        self.vlan_increment_var = tk.IntVar(value=1)
        self.vlan_increment_entry = ttk.Entry(self, textvariable=self.vlan_increment_var)
        self.vlan_increment_entry.grid(row=3, column=1, padx=10, pady=5)

        ttk.Label(self, text="Starting IP Address:").grid(row=4, column=0, padx=10, pady=5)
        self.start_ip_var = tk.StringVar(value="1.1.1.254/24")
        self.start_ip_entry = ttk.Entry(self, textvariable=self.start_ip_var)
        self.start_ip_entry.grid(row=4, column=1, padx=10, pady=5)

        ttk.Label(self, text="IP Increment:").grid(row=5, column=0, padx=10, pady=5)
        self.ip_increment_var = tk.StringVar(value="0.0.1.0")
        self.ip_increment_entry = ttk.Entry(self, textvariable=self.ip_increment_var)
        self.ip_increment_entry.grid(row=5, column=1, padx=10, pady=5)

        self.generate_button = ttk.Button(self, text="Generate Config", command=self.generate_config)
        self.generate_button.grid(row=6, column=0, columnspan=2, pady=10)

    def generate_config(self):
        # Extract values
        interface = self.interface_var.get()
        num_sub_interfaces = self.num_sub_interfaces_var.get()
        start_vlan = self.start_vlan_var.get()
        vlan_increment = self.vlan_increment_var.get()
        start_ip = ipaddress.ip_interface(self.start_ip_var.get())
        ip_increment = ipaddress.ip_network(self.ip_increment_var.get(), strict=False)

        config_lines = []

        for i in range(num_sub_interfaces):
            config_lines.append(f"interfaces {interface}.{start_vlan} admin-state enabled")
            config_lines.append(f"interfaces {interface}.{start_vlan} ipv4-address {start_ip}")
            config_lines.append(f"interfaces {interface}.{start_vlan} vlan-id {start_vlan}")
            start_vlan += vlan_increment
            start_ip = ipaddress.ip_interface(
                str(start_ip.ip + int(ip_increment.network_address)) + '/' + str(start_ip.network.prefixlen))

        # Save to a file in the same directory as the script
        filename = 'Interfaces_automated.txt'
        with open(filename, 'w') as file:
            file.write('\n'.join(config_lines))
        print(f"Configuration saved to {filename}")

        upload_file_scp('Interfaces_automated.txt', 'WJ31B77Y00003A2', 'dnroot', 'dnroot', '/config')

        # You'd need to create an instance of the class containing the `commit_backup_config` method (assuming it's `BaseConnector` class).
        chosen_device = Class_SSH_Con.BaseConnector(ip='WJ31B77Y00003A2', username='dnroot')
        chosen_device.load_merge_config('Interfaces_automated.txt')
        sys.exit(1)


if __name__ == "__main__":
    # Example list of interfaces
    chosen_device = Class_SSH_Con.BaseConnector('WJ31B77Y00003A2', 'dnroot')
    available_interfaces = chosen_device.get_interfaces()
    app = ConfigGenerator(available_interfaces)
    app.mainloop()