# LAN-Detect
LAN-Detect is a Python script that scans the local network for connected devices and notifies the user of any unknown devices.

# Installation
To install LAN-Detect, first clone the repository:

`git clone https://github.com/dcluomax/lan-detect.git`

Then, install the required modules:

`pip install -r requirements.txt`

# Usage
To run LAN-Detect, navigate to the cloned directory and run the following command:

`python main.py`
This will start the Flask application and open it on port 5000. You can then access the following endpoints:

`/scan`: scans the network for connected devices and returns a JSON list of devices, along with a known parameter indicating whether each device is known or unknown.
`/start`: starts a scheduler that scans the network at a specified interval (default 60 seconds).
`/stop`: stops the scheduler.
API Reference
`/scan`
Sends an ARP request to the local network and returns a JSON list of connected devices. Each device has the following parameters:

    `ip`: the IP address of the device.
    `mac`: the MAC address of the device.
    `known`: a boolean indicating whether the device is known (added to the /known-macs list) or not.

`/known-macs` [Get]
Returns a JSON list of known MAC addresses.

`/known-macs` [Post]
Adds a known MAC address to the list. Requires a mac parameter in the request body.
```
POST /known-macs
Content-Type: application/json

{
    [
        "00:11:22:33:44:55",
        "11:22:33:44:55:66",
        "22:33:44:55:66:77"
    ]
}
```

`/start`
Starts a scheduler that runs the /scan endpoint at a specified interval. Requires an optional interval parameter in the query string, which specifies the interval in seconds (default 60).

`/stop`
Stops the scheduler.
