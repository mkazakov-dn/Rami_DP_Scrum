import os
import time
import logging
import subprocess
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
        self.port_map = None


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
            self.port_map = self.session_assistant.PortMapAssistant()
            logger.info(f"Connected to session: ID={session.Id}, Name={session.Name or 'Unnamed'}")
        except Exception as e:
            logger.error(f"Failed to connect to IxNetwork session: {e}")
            raise


    def _check_ports_status(self, retries=5, delay=2):
        """Check if all Vports are Up, with retries."""
        for attempt in range(retries):
            self.vports = self.ixnetwork.Vport.find()  # Re-fetch Vports
            if all(vport.ConnectionState == "connectedLinkUp" for vport in self.vports):
                logger.debug("All ports are up.")
                return True
            logger.debug(f"Attempt {attempt + 1}/{retries}: Ports are not Up yet. Retrying in {delay} seconds...")
            time.sleep(delay)
        logger.error("Ports failed to come Up within retries.")
        return False

    def _configure_ports(self):
        """Apply L1 configurations to all Vports."""
        l1_config_params = {
            "IeeeL1Defaults": False,
            "FirecodeForceOn": True
        }
        logger.debug("Configuring ports...")
        for vport in self.vports:
            l1_config = vport.L1Config.find()
            novusHundredGig = l1_config.NovusHundredGigLan.find()
            novusHundredGig.update(**l1_config_params)
        logger.debug("Ports configured successfully.")

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
        for new_port in new_ports:
            self.port_map.Map(**new_port)
        self.port_map.Connect(ForceOwnership=True, HostReadyTimeout=20, IgnoreLinkUp=True)

        if not self._check_ports_status():
            logger.warning("Some ports are down. Applying configurations to bring them up...")
            self._configure_ports()
            time.sleep(2)
            if not self._check_ports_status():
                raise RuntimeError("Failed to bring ports up after configuration.")

        logger.info("New ports mapped and connected successfully.")
        # Step 4: Connect the ports

    def load_config(self, local_config_path):
        """
        Load a configuration file into the IxNetwork session.

        :param local_config_path: The path to the configuration file to load.
        """
        try:
            logger.info(f"Loading configuration from: {local_config_path}")
            self.ixnetwork.LoadConfig(Files(local_config_path, local_file=False))
            logger.info("Configuration loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise RuntimeError(f"Failed to load configuration: {e}")

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

def transfer_file_to_windows(source_path, target_host, target_path, mkazakov_password):
    """
    Transfer the file from Linux source to the Windows IXIA client using SCP.

    :param source_path: Path of the file on mkazakov-dev (e.g., "dn@mkazakov-dev:/home/dn/file.ixncfg").
    :param target_host: Target Windows IXIA machine hostname or IP (e.g., "win-client257").
    :param target_path: Directory path on the target machine (e.g., "C:\\configs\\").
    :param mkazakov_password: Password for the mkazakov-dev user.
    """
    logger.info(f"Transferring file from {source_path} to {target_host}:{target_path}...")

    # Construct the target file path
    remote_target_path = f"dn@{target_host}:{target_path}"

    try:
        # Use sshpass to provide the password for mkazakov-dev
        subprocess.check_call([
            "sshpass", "-p", mkazakov_password,
            "scp", source_path, remote_target_path
        ])
        logger.info(f"File successfully transferred to {remote_target_path}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to transfer file: {e}")
        raise

    return target_path + os.path.basename(source_path)

if __name__ == "__main__":
    source_ixia_file = "dn@mkazakov-dev:/home/dn/mark_kazakov_LU.ixncfg"
    target_windows_client = "win-client257"
    new_ports = [
        {"IpAddress": "ixia01.dev.drivenets.net", "CardId": 2, "PortId": 30, "Name": "Port1"},
        {"IpAddress": "ixia01.dev.drivenets.net", "CardId": 2, "PortId": 29, "Name": "Port2"}
    ]

    # Initialize and connect to IxNetwork
    ixia = IxiaConfigUpdater(api_server_ip=target_windows_client, api_server_port=11009)

    ixia.connect_to_existing_or_create()
    windows_config_path = transfer_file_to_windows(source_ixia_file, target_windows_client, "C:\\configs\\", "drive1234!")
    ixia.load_config(local_config_path=windows_config_path)


    # Load the configuration file

    # Remap ports
    ixia.remap_ports(new_ports=new_ports)

    logger.info("IXIA configuration updated and saved successfully.")