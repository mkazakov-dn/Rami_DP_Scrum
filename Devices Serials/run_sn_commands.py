#!/usr/bin/env python3
import json
import re
from Class_SSH_Con import SSH_Conn

# List of device serial numbers to process
SERIALS = [
    "WNG1C7VS00017P2",
    "WDY1CBV400005"
]

def parse_transceiver_output(output):
    """Parse transceiver output into interface blocks"""
    # Split into blocks starting with "Interface "
    blocks = re.split(r'(?=Interface\s)', output)
    interface_blocks = {}
    
    for block in blocks:
        if not block.strip():
            continue
            
        # Extract interface name from first line
        first_line = block.split('\n')[0].strip()
        if not first_line.startswith("Interface "):
            continue
            
        interface_name = first_line.split()[1]
        
        # Check second non-blank line
        lines = [line for line in block.split('\n') if line.strip()]
        if len(lines) > 1 and "transceiver not present" in lines[1].lower():
            continue
            
        interface_blocks[interface_name] = block
    
    return interface_blocks

def collect_device_data(serial):
    """Collect data from a single device"""
    try:
        # Initialize SSH connection
        ssh = SSH_Conn(host=serial, icmp_test=False)
        
        # Connect to device
        ssh.connect()
        
        # Execute show commands
        system_output = ssh.exec_command("show system")
        transceiver_output = ssh.exec_command("show interface transceiver")
        
        # Parse transceiver output into interface blocks
        interface_blocks = parse_transceiver_output(transceiver_output)
        
        # Create data structure
        device_data = {
            "serial": serial,
            "status": "success",
            "system_output": system_output,
            "interfaces": interface_blocks
        }
        
        return device_data
        
    except Exception as e:
        return {
            "serial": serial,
            "status": "error",
            "error_message": str(e)
        }
    
    finally:
        try:
            ssh.disconnect()
        except:
            pass

def main():
    # Collect data from all devices
    all_devices_data = []
    for serial in SERIALS:
        print(f"Collecting data from {serial}...")
        device_data = collect_device_data(serial)
        all_devices_data.append(device_data)
        print(f"Done with {serial}")
    
    # Save all data to a single JSON file
    with open("devices_data.json", "w") as f:
        json.dump(all_devices_data, f, indent=2)
    
    print("\nData collection complete. Results saved to devices_data.json")

if __name__ == "__main__":
    main() 