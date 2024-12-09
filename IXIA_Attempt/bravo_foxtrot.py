import os
import logging
from ixnetwork_restpy import TestPlatform, SessionAssistant, Files


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("IXIA_Config_Updater")


class IxiaConfigUpdater:
    def __init__(self, api_server_ip, api_server_port=11009):
        """
        Initialize the IxiaConfigUpdater.

        :param api_server_ip: IP or hostname of the machine running IxNetwork API server (e.g., 'win-client257').
        :param api_server_port: Port number for the IxNetwork REST API server (default: 11009).
        """
        self.api_server_ip = api_server_ip
        self.api_server_port = api_server_port
        self.session_assistant = None
        self.ixnetwork = None

    def connect_to_existing_or_create(self):
        """
        Use TestPlatform to find existing sessions and attach using SessionAssistant.
        """
        logger.info(f"Connecting to IxNetwork at {self.api_server_ip}:{self.api_server_port}...")
        try:
            # Initialize TestPlatform
            testplatform = TestPlatform(ip_address=self.api_server_ip, rest_port=self.api_server_port)

            # Authenticate if required
            testplatform.Authenticate("admin", "admin")  # Adjust credentials as needed

            # Find existing sessions
            sessions = testplatform.Sessions.find()
            if len(sessions) > 0:
                session = sessions[0]  # Attach to the first existing session
                logger.info(f"Attaching to existing session: ID={session.Id}, Name={session.Name}")
            else:
                # Create a new session if none exist
                logger.info("No existing sessions found. Creating a new session...")
                session = testplatform.Sessions.add("ixnrest")

            # Use SessionAssistant to interact with the session
            self.session_assistant = SessionAssistant(
                IpAddress=self.api_server_ip,
                RestPort=self.api_server_port,
                SessionId=session.Id,
                LogLevel=SessionAssistant.LOGLEVEL_INFO,
                ClearConfig=False
            )
            self.ixnetwork = self.session_assistant.Ixnetwork
            logger.info(f"Connected to session: ID={session.Id}, Name={session.Name or 'Unnamed'}")
        except Exception as e:
            logger.error(f"Failed to connect to IxNetwork session: {e}")
            raise

    def add_chassis(self, chassis_ip):
        """
        Add the chassis to the IxNetwork configuration if not already added.
        :param chassis_ip: The IP address of the chassis to add.
        """
        available_chassis = self.ixnetwork.AvailableHardware.Chassis.find()
        if not available_chassis or not available_chassis.find(Hostname=chassis_ip):
            logger.info(f"Adding chassis: {chassis_ip}")
            self.ixnetwork.AvailableHardware.Chassis.add(Hostname=chassis_ip)
        else:
            logger.info(f"Chassis {chassis_ip} is already added.")

    def remap_ports(self, new_ports):
        """
        Remap new ports after removing all old vports by name.

        :param new_ports: A list of dictionaries with new port mappings.
                          Example: [{"IpAddress": "100.64.0.56", "CardId": 2, "PortId": 30, "Name": "Port1"}]
        """
        # Step 1: Detect and remove all old vports by name
        logger.info("Removing old vports...")
        old_port_names = self.detect_old_ports_by_name()
        if old_port_names:
            self.remove_ports_by_name(old_port_names)
            logger.info("Old vports removed.")
        else:
            logger.info("No old vports found to remove.")


        # Step 3: Add and map new vports
        logger.info("Adding and mapping new ports...")
        port_map = self.session_assistant.PortMapAssistant()
        for new_port in new_ports:
            port_map.Map(**new_port)
        port_map.Connect(ForceOwnership=True, HostReadyTimeout=20, IgnoreLinkUp=True)
        logger.info("New ports mapped and connected successfully.")
        # Step 4: Connect the ports


    def detect_old_ports_by_name(self):
        """
        Detect all existing vports by their names.
        Returns a list of port names.
        """
        logger.info("Detecting current vports by name...")
        vports = self.ixnetwork.Vport.find()
        old_port_names = [vport.Name for vport in vports]

        for name in old_port_names:
            logger.info(f"Detected vport: {name}")

        return old_port_names

    def remove_ports_by_name(self, port_names):
        """
        Remove the specified vports by name.

        :param port_names: List of vport names to remove.
        """
        for name in port_names:
            vport = self.ixnetwork.Vport.find(Name=name)
            if len(vport) > 0:
                logger.info(f"Removing vport: {name}")
                vport.remove()
            else:
                logger.warning(f"No vport found with name: {name}")

    def save_config(self, output_path):
        """
        Save the updated configuration to a new file.

        :param output_path: The path on the Windows machine where the config file will be saved.
        """
        logger.info(f"Saving updated configuration to {output_path}...")
        self.ixnetwork.SaveConfig(Files=output_path)
        logger.info("Configuration saved successfully.")


if __name__ == "__main__":
    source_ixia_file = "dn@mkazakov-dev:/home/dn/mark_kazakov_LU.ixncfg"
    target_windows_client = "win-client257"
    new_ports = [
        {"IpAddress": "100.64.0.56", "CardId": 2, "PortId": 30, "Name": "Port1"},
        {"IpAddress": "100.64.0.56", "CardId": 2, "PortId": 29, "Name": "Port2"}
    ]

    # Initialize and connect to IxNetwork
    ixia = IxiaConfigUpdater(api_server_ip=target_windows_client, api_server_port=11009)

    ixia.connect_to_existing_or_create()

    # Remap ports
    ixia.remap_ports(new_ports=new_ports)

    # Save updated configuration
    updated_config_path = "C:\\configs\\updated_ixia_config_file.ixncfg"
    ixia.save_config(output_path=updated_config_path)
    logger.info("IXIA configuration updated and saved successfully.")