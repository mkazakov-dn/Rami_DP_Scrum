#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk
import json
import os

class DeviceViewer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Device Viewer")
        self.geometry("600x400")
        
        # Create main Treeview
        self.tree = ttk.Treeview(self)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Add columns
        self.tree["columns"] = ("status",)
        self.tree.column("#0", width=300)
        self.tree.column("status", width=100)
        
        # Add headings
        self.tree.heading("#0", text="Device/Command")
        self.tree.heading("status", text="Status")
        
        # Bind double-click event
        self.tree.bind("<Double-1>", self.on_double_click)
        
        # Load and display data
        self.load_data()
    
    def load_data(self):
        """Load data from JSON file and populate the tree"""
        try:
            with open("devices_data.json", "r") as f:
                devices_data = json.load(f)
            
            for device in devices_data:
                # Add device node
                device_node = self.tree.insert("", "end", text=device["serial"])
                
                if device["status"] == "success":
                    # Add system output node
                    self.tree.insert(device_node, "end", text="show system", 
                                   values=(device["system_output"],))
                    
                    # Add transceiver node and its interfaces
                    transceiver_node = self.tree.insert(device_node, "end", 
                                                      text="interface transceiver")
                    
                    # Add interface nodes
                    for interface, block in device["interfaces"].items():
                        self.tree.insert(transceiver_node, "end", text=interface,
                                       values=(block,))
                    
                    self.tree.set(device_node, "status", "✔ done")
                else:
                    # Show error status
                    self.tree.set(device_node, "status", f"✖ error: {device['error_message']}")
                    self.tree.insert(device_node, "end", text=device["error_message"])
        
        except FileNotFoundError:
            # Show error if data file doesn't exist
            self.tree.insert("", "end", text="No data file found", 
                           values=("Run run_sn_commands.py first",))
        except Exception as e:
            # Show any other errors
            self.tree.insert("", "end", text="Error loading data", 
                           values=(str(e),))
    
    def on_double_click(self, event):
        """Handle double-click on tree items"""
        item = self.tree.identify_row(event.y)
        if not item:
            return
            
        # Get parent to check if this is a command node
        parent = self.tree.parent(item)
        if not parent:
            return
            
        # Skip if it's the transceiver parent node
        if self.tree.item(item)["text"] == "interface transceiver":
            return
            
        # Get the stored output
        output = self.tree.item(item)["values"][0]
        if not output:
            return
        
        # Create popup window
        popup = tk.Toplevel(self)
        popup.title(self.tree.item(item)["text"])
        
        # Create text widget
        text = tk.Text(popup, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(popup, orient="vertical", command=text.yview)
        scrollbar.pack(side="right", fill="y")
        text.configure(yscrollcommand=scrollbar.set)
        
        # Insert text and make read-only
        text.insert("1.0", output)
        text.configure(state="disabled")

def main():
    app = DeviceViewer()
    app.mainloop()

if __name__ == "__main__":
    main() 