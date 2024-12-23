import logging
import time
import tkinter as tk
from tkinter import ttk
from ixnetwork_restpy import SessionAssistant


class IxiaSessionManager:
    def __init__(self, api_server_ip, clear_config=False):
        """Initialize the IxNetwork session."""
        self.api_server_ip = api_server_ip
        self.clear_config = clear_config
        self.session_assistant = None
        self.ixnetwork = None
        self.logger = logging.getLogger("IxiaSessionManager")

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


class PortManager:
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.logger = logging.getLogger("PortManager")
        self.vports = []

    def _map_ports(self, ports):
        """Map the physical ports."""
        try:
            port_map = self.session_manager.session_assistant.PortMapAssistant()
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
            self.vports = self.session_manager.ixnetwork.Vport.find()
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


class TopologyManager:
    def __init__(self, session_manager):
        self.session_manager = session_manager
        self.logger = logging.getLogger("TopologyManager")

    def create_topology_with_vlan_and_ipv4(self, vports, vlan_ids, directions, ip_addresses):
        """Create topologies, assign unique VLANs to each Vport, and configure IPv4."""
        for port, vlan_id, direction, ip_address in zip(vports, vlan_ids, directions, ip_addresses):
            topology_name = f"Topology_{direction}"
            device_group_name = f"DeviceGroup_{direction}"

            # Add a topology associated with each Vport
            topology = self.session_manager.ixnetwork.Topology.add(Name=topology_name, Vports=[port])
            device_group = topology.DeviceGroup.add(Name=device_group_name, Multiplier=1)



            # Configure Ethernet layer
            ethernet = device_group.Ethernet.add(Name=f"Ethernet_{port.Name}")
            ethernet.UseVlans = True

            if not ethernet.Vlan.find():
                vlan = ethernet.Vlan.add()
            else:
                vlan = ethernet.Vlan.find()
            vlan.VlanId.Single(vlan_id)

            # Configure IPv4
            ipv4 = ethernet.Ipv4.add(Name=f"IPv4_{ip_address}")
            ipv4.Address.Single(ip_address)
            octets = ip_address.split('.')
            gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.2"
            ipv4.GatewayIp.Single(gateway_ip)
            ipv4.Prefix.Single(24)

            # Add OSPF
            self.configure_ospf(device_group ,ipv4, ip_address)

            self.logger.info(
                f"Device group '{device_group.Name}' with VLAN ID {vlan_id} and IPv4 {ip_address} added to topology '{topology.Name}'.")

    def configure_ospf(self, device, ipv4, ip_address, area_id="0",):
        """Add OSPF to a given device group."""
        ospf = ipv4.Ospfv2.add(Name=f'OSPF {ipv4.Name}')
        device.RouterData.RouterId.Single(ip_address)
        ospf.AreaId.Single(area_id)
        ospf.NetworkType.Single("pointtopoint")
        self.logger.info(f"OSPF configured for device group '{ipv4.Name}' in Area {area_id}.")


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

        ttk.Button(root, text="Configure Ports", command=self.configure_ports).grid(row=4, columnspan=2, pady=10)

    def configure_ports(self):
        api_server_ip = self.api_server_ip.get()
        chassis_ip = self.chassis_ip.get()
        port1 = self.port1.get().split(":")
        port2 = self.port2.get().split(":")

        ports_to_map = [
            {"IpAddress": chassis_ip, "CardId": int(port1[0]), "PortId": int(port1[1]), "Name": "Port1"},
            {"IpAddress": chassis_ip, "CardId": int(port2[0]), "PortId": int(port2[1]), "Name": "Port2"}
        ]

        session_manager = IxiaSessionManager(api_server_ip=api_server_ip, clear_config=True)
        try:
            session_manager.connect()

            port_manager = PortManager(session_manager)
            port_manager.prepare_ports(ports=ports_to_map)

            topology_manager = TopologyManager(session_manager)
            vports = session_manager.ixnetwork.Vport.find()
            vlan_ids = [100, 200]
            directions = ['Inbound', 'Outbound']
            ip_addresses = ['192.168.1.1', '192.168.2.1']
            topology_manager.create_topology_with_vlan_and_ipv4(vports, vlan_ids, directions, ip_addresses)

        finally:
            session_manager.disconnect()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

    root = tk.Tk()
    app = IxiaConfiguratorApp(root)
    root.mainloop()
