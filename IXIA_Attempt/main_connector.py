import logging
import time
import tkinter as tk
from tkinter import ttk, messagebox
from ixnetwork_restpy import SessionAssistant
import re
from Rami_DP_Scrum.Class_SSH_Con import BaseConnector


class IxiaConfigurator:

    def __init__(self, api_server_ip, clear_config=False):
        """Initialize the IxNetwork session and configurator."""
        self.api_server_ip = api_server_ip
        self.clear_config = clear_config
        self.session_assistant = None
        self.ixnetwork = None
        self.logger = logging.getLogger("IxiaConfigurator")
        self.vports = []

    def connect(self):
        """Establish connection to the IxNetwork API."""
        try:
            self.logger.debug(f"Connecting to IxNetwork API Server at {self.api_server_ip}...")
            self.session_assistant = SessionAssistant(
                IpAddress=self.api_server_ip,
                LogLevel='info',
                ClearConfig=self.clear_config
            )
            self.ixnetwork = self.session_assistant.Ixnetwork
            self.logger.info("Connected to IxNetwork API Server successfully.")
        except Exception as e:
            self.logger.error(f"Failed to connect to IxNetwork API Server: {e}")
            raise RuntimeError(f"Failed to connect to IxNetwork API Server: {e}")

    def disconnect(self):
        """Gracefully disconnect the session."""
        try:
            if self.session_assistant:
                self.session_assistant.Session.remove()
                self.logger.info("Disconnected from IxNetwork.")
        except Exception as e:
            self.logger.warning(f"Failed to disconnect gracefully: {e}")

    def _map_ports(self, ports):
        """Map the physical ports."""
        try:
            port_map = self.session_assistant.PortMapAssistant()
            for port in ports:
                port_map.Map(**port)
            port_map.Connect(ForceOwnership=True, HostReadyTimeout=20, IgnoreLinkUp=True)
            self.logger.info("Ports mapped and connected successfully.")
        except Exception as e:
            self.logger.error(f"Failed to map ports: {e}")
            raise RuntimeError(f"Failed to map ports: {e}")

    def _check_ports_status(self, retries=5, delay=2):
        """Check if all Vports are Up, with retries."""
        for attempt in range(retries):
            self.vports = self.ixnetwork.Vport.find()
            if all(vport.ConnectionState == "connectedLinkUp" for vport in self.vports):
                self.logger.debug("All ports are up.")
                return True
            self.logger.debug(f"Attempt {attempt + 1}/{retries}: Ports are not Up yet. Retrying in {delay} seconds...")
            time.sleep(delay)
        self.logger.error("Ports failed to come Up within retries.")
        return False

    def _configure_ports(self):
        """Apply L1 configurations to all Vports."""
        l1_config_params = {
            "IeeeL1Defaults": False,
            "FirecodeForceOn": True
        }
        self.logger.debug("Configuring ports...")
        for vport in self.vports:
            l1_config = vport.L1Config.find()
            novusHundredGig = l1_config.NovusHundredGigLan.find()
            novusHundredGig.update(**l1_config_params)
        self.logger.debug("Ports configured successfully.")

    def prepare_ports(self, ports):
        """Prepare ports by mapping and verifying their status."""
        self._map_ports(ports)
        if not self._check_ports_status():
            self.logger.warning("Some ports are down. Applying configurations to bring them up...")
            self._configure_ports()
            time.sleep(2)
            if not self._check_ports_status():
                raise RuntimeError("Failed to bring ports up after configuration.")

    def configure_ipv4(self, ethernet, ip_address):
        """Configure IPv4 and gateway settings."""
        ipv4 = ethernet.Ipv4.add(Name=f"IPv4_{ip_address}")
        ipv4.Address.Single(ip_address)
        octets = ip_address.split('.')
        gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.2"
        ipv4.GatewayIp.Single(gateway_ip)
        ipv4.Prefix.Single(24)
        return ipv4

    def configure_BGP_VRF(self,device_group, bgp_peer, local_as):
        # The value for the BGP VRF RT Import/Export is
        self.logger.info("Configuring BGP VRF")
        vrf = bgp_peer.BgpVrf.add(Name="BGP_VRF_")
        rt = vrf.BgpExportRouteTargetList.find()
        rt.TargetAsNumber.Single(local_as)

        VPN_GROUP = device_group.NetworkGroup.add(Name="VPN", Multiplier='1')
        IPv4_VPN = VPN_GROUP.Ipv4PrefixPools.add(NumberOfAddresses='1')
        IPv4_VPN.PrefixLength.Single(24)






    def configure_bgp_with_loopback(self, device_group, loopback, local_as, peer_type):
        """Configure BGP with Loopback."""
        self.logger.info("Configuring BGP with loopback...")

        # Add an IPv4 Loopback interface
        ipv4_loopback = device_group.Ipv4Loopback.add(Name='PE 1 Loopback')
        ipv4_loopback.Address.Single(loopback)

        # Add the BGP Peer
        bgp_peer = ipv4_loopback.BgpIpv4Peer.add(Name='BGP_PE1')

        # Configure BGP Peer settings
        bgp_peer.DutIp.Single('100.100.100.100')  # DUT IP
        bgp_peer.LocalAs2Bytes.Single(local_as)  # Local AS
        bgp_peer.Type.Single(peer_type)  # Internal or external BGP

        # Add BFD to IPv4 Loopback and enable BFD for the BGP Peer
        ipv4_loopback.Bfdv4Interface.add(Name='Bravo_Echo', NoOfSessions=1)  # Configure BFD
        bgp_peer.EnableBfdRegistration.Single(True)  # Enable BFD registration for the BGP Peer

        self.logger.info(f"BGP with loopback configured: DUT IP {loopback}, Local AS {local_as}, Type {peer_type}.")

        return bgp_peer

    def configure_ospf_and_ldp(self, device_group, ipv4, loopback):
        """Configure OSPF and LDP."""
        ospf = ipv4.Ospfv2.add()
        ipv4.Bfdv4Interface.add(Name='BFD_1', NoOfSessions=1)
        device_group_router_data = device_group.RouterData.find()
        device_group_router_data.RouterId.Single(loopback)
        ospf.AreaId.Single(0)
        ospf.NetworkType.Single('pointtopoint')
        ospf.EnableBfdRegistration.Single(True)

        self.logger.info("OSPF configured.")
        self.logger.info("Attempting to push LDP.")
        ipv4.LdpBasicRouter.add(Name="LDP_P1")

    def Loopback_creator(self, device_group, loopback):
        """Create network group and loopback configuration."""
        network_group = device_group.NetworkGroup.add(Name='Loopback', Multiplier='1')
        ipv4_prefix_pool = network_group.Ipv4PrefixPools.add(NumberOfAddresses='1')
        ipv4_prefix_pool.NetworkAddress.Increment(start_value=loopback, step_value='0.0.0.1')
        ipv4_prefix_pool.PrefixLength.Single(32)


    def configure_network_group(self, device_group, loopback):
        """Configure network group with IPv4 prefix pool."""
        self.logger.info("Configuring network group...")

        # Add a network group to the device group
        network_group = device_group.NetworkGroup.add(Name='Loopback', Multiplier='1')

        # Configure the IPv4 prefix pool within the network group
        ipv4_prefix_pool = network_group.Ipv4PrefixPools.add(NumberOfAddresses='1')
        ipv4_prefix_pool.NetworkAddress.Increment(start_value=loopback, step_value='0.0.0.1')
        ipv4_prefix_pool.PrefixLength.Single(32)

        self.logger.info(f"Network group configured with loopback {loopback}.")

    def configure_traffic(self):
        """Configure traffic from MKaz_Helper IPv4 to VPN Group in Topology 2."""
        self.logger.info("Configuring traffic from MKaz_Helper to VPN Group in Topology 2...")



        # Find the source: MKaz_Helper's IPv4
        mkaz_helper = self.ixnetwork.Topology.find(Name="Topology 1").DeviceGroup.find(Name="MKaz_Helper")
        source_ethernet = mkaz_helper.Ethernet.find()
        source_ipv4 = source_ethernet.Ipv4.find()

        # Find the destination: VPN Group under Topology 2
        destination_vrf = self.ixnetwork.Topology.find(Name="Topology 2").DeviceGroup.find(Name="Device Group 2")
        vpn_group = destination_vrf.NetworkGroup.find(Name="VPN 1")

        # Add Traffic Item
        traffic_item = self.ixnetwork.Traffic.TrafficItem.add(Name='VRF', BiDirectional=False, TrafficType="ipv4")
        traffic_item.EndpointSet.add(Sources=source_ipv4, Destinations=vpn_group)

        # Generate and apply traffic
        traffic_item.Generate()

    def configure_topology(self, vports, vlan_ids, directions, ip_addresses, loopbacks):
        """Create topology and configure VLANs, IPv4, OSPF, and BGP."""
        for index, (port, vlan_id, direction, ip_address, loopback) in enumerate(zip(vports, vlan_ids, directions, ip_addresses,
                                                                  loopbacks)):
            topology = self.ixnetwork.Topology.add(Vports=[port])
            device_group = topology.DeviceGroup.add(Multiplier=1)

            # Configure Ethernet
            ethernet = device_group.Ethernet.add(Name=f"Ethernet_{port.Name}")
            ethernet.UseVlans = True
            vlan = ethernet.Vlan.add() if not ethernet.Vlan.find() else ethernet.Vlan.find()
            vlan.VlanId.Single(vlan_id)

            # Configure IPv4
            ipv4 = self.configure_ipv4(ethernet, ip_address)

            # Configure OSPF and LDP
            self.configure_ospf_and_ldp(device_group, ipv4, loopback)

            # Configure Network Group
            self.configure_network_group(device_group, loopback)

            # Configure BGP with Loopback
            bgp_peer = self.configure_bgp_with_loopback(device_group, loopback, local_as=6500, peer_type="internal")

            self.configure_BGP_VRF(device_group, bgp_peer,local_as=6500)

            # Add additional device group only under the first topology
            if index == 0:
                extra_device = topology.DeviceGroup.add(Multiplier=1, Name="MKaz_Helper")
                extra_device = topology.DeviceGroup.find(Name="MKaz_Helper")

                # Configure Ethernet
                ethernet_extra = extra_device.Ethernet.add(Name="Vlan 999")
                ethernet_extra = extra_device.Ethernet.find()
                ethernet_extra.UseVlans = True

                # Configure VLAN
                vlan = ethernet_extra.Vlan.add() if not ethernet_extra.Vlan.find() else ethernet_extra.Vlan.find()
                vlan.VlanId.Single(999)

                # Configure IPv4
                additional_ip = ethernet_extra.Ipv4.add(Name="IPv4_7.7.7.1")
                additional_ip = ethernet_extra.Ipv4.find()
                additional_ip.Address.Single("7.7.7.1")
                additional_ip.GatewayIp.Single("7.7.7.7")
                additional_ip.Prefix.Single(24)




class IxiaConfiguratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ixia Port Configurator")

        ttk.Label(root, text="API Server IP").grid(row=0, column=0, padx=5, pady=5)
        self.api_server_ip = tk.StringVar()
        ttk.Entry(root, textvariable=self.api_server_ip).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(root, text="Chassis IP").grid(row=1, column=0, padx=5, pady=5)
        self.chassis_ip = tk.StringVar()
        ttk.Entry(root, textvariable=self.chassis_ip).grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(root, text="Port 1 (CardID:PortID)").grid(row=2, column=0, padx=5, pady=5)
        self.port1 = tk.StringVar()
        ttk.Entry(root, textvariable=self.port1).grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(root, text="Port 2 (CardID:PortID)").grid(row=3, column=0, padx=5, pady=5)
        self.port2 = tk.StringVar()
        ttk.Entry(root, textvariable=self.port2).grid(row=3, column=1, padx=5, pady=5)

        ttk.Label(root, text="Device ID").grid(row=4, column=0, padx=5, pady=5)
        self.device_id = tk.StringVar()
        ttk.Entry(root, textvariable=self.device_id).grid(row=4, column=1, padx=5, pady=5)

        ttk.Label(root, text="Inbound Interface").grid(row=5, column=0, padx=5, pady=5)
        self.inbound_interface = tk.StringVar()
        ttk.Entry(root, textvariable=self.inbound_interface).grid(row=5, column=1, padx=5, pady=5)

        ttk.Label(root, text="Outbound Interface").grid(row=6, column=0, padx=5, pady=5)
        self.outbound_interface = tk.StringVar()
        ttk.Entry(root, textvariable=self.outbound_interface).grid(row=6, column=1, padx=5, pady=5)

        ttk.Button(root, text="Configure Ports", command=self.configure_ports).grid(row=9, columnspan=2, pady=10)
        ttk.Button(root, text="Upload Config", command=self.upload_config_to_device).grid(row=10, columnspan=2, pady=10)


    def modify_config(self):
        inbound = self.inbound_interface.get().strip()
        outbound = self.outbound_interface.get().strip()

        if not inbound or not outbound:
            messagebox.showerror("Input Error", "Both interfaces must be provided.")
            return

        try:
            with open("configuration_for_DNOS.txt", "r") as file:
                config_data = file.read()

            config_data = re.sub(r"ge100-0/0/3", inbound, config_data)
            config_data = re.sub(r"ge100-0/0/30", outbound, config_data)

            with open("modified_configuration.txt", "w") as file:
                file.write(config_data)

            messagebox.showinfo("Success", "Configuration modified and saved as 'modified_configuration.txt'")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")


    def configure_ports(self):
        api_server_ip = self.api_server_ip.get()
        chassis_ip = self.chassis_ip.get()
        port1 = self.port1.get().split(":")
        port2 = self.port2.get().split(":")

        ports_to_map = [
            {"IpAddress": chassis_ip, "CardId": int(port1[0]), "PortId": int(port1[1]), "Name": "Port1"},
            {"IpAddress": chassis_ip, "CardId": int(port2[0]), "PortId": int(port2[1]), "Name": "Port2"}
        ]

        configurator = IxiaConfigurator(api_server_ip=api_server_ip, clear_config=True)
        try:
            configurator.connect()
            configurator.prepare_ports(ports=ports_to_map)
            vports = configurator.ixnetwork.Vport.find()
            vlan_ids = [100, 200]
            directions = ['Inbound', 'Outbound']
            ip_addresses = ['192.168.1.1', '192.168.2.1']
            loopbacks = ['1.1.1.1', '2.2.2.2']
            configurator.configure_topology(vports, vlan_ids, directions, ip_addresses, loopbacks)
            configurator.configure_traffic()
        finally:
            configurator.disconnect()


    def commit_check(self, connector):
        connector.connection.change_mode(requested_cli='DNOS_CFG')
        if not connector.connection.exec_command(cmd=f'load merge modified_configuration.txt', timeout=3600):
            logging.log(f'Failed to load config')
        else: # proceeding with the commit check
            final_boolean = connector.connection.exec_command(cmd='commit check')
        return  final_boolean #True if the commit check succeeded, False if the commit check failed.





    def upload_config_to_device(self):
        device_id = self.device_id.get().strip()
        self.modify_config()
        if not device_id:
            messagebox.showerror("Input Error", "Device ID must be provided.")
            return

        try:
            connector = BaseConnector(ip=device_id, username='dnroot')
            connector.backup_config()
            connector.SCP_To_Device("modified_configuration.txt")
            messagebox.showinfo("Success", "Configuration uploaded successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to upload config: {e}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    root = tk.Tk()
    app = IxiaConfiguratorApp(root)
    root.mainloop()