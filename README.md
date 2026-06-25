# ahlora
A WIP dashboard that sends IoT data over a DFLoRaWAN Gateway.
The primary goal of this project is to gain experience with IoT and Postgres workflows and make a dashboard that can be deployed on a dedicated platform like Railway or Render. It's coded primarily by AI and is not certified for secure use in enterprise environments, though I'd say is perfectly cromulent for a local connection or a VPN connection through wireguard, tailscale, and whatever else tickles your fancy.

The site supports mobile and desktop scaling, PWA, and a for the most part functioning server data polling system that uses an API key to secure it's data. The variable is set as seen in the .env.example file. The postgres database url is also set in the .env file, as seen in the example along with the API key

WIP Features:
The device_classifier.py has not been thoroughly tested, if the correct device type does not appear when an EUID is imported, then simply change the dropdown selection to a device type that most similarly aligns with the device type. To properly configure your device, check the hexadecimal values that your LoRaWAN compatible device sends and set the placements (offsets) of the values in the byte offset menu.

Sound Devices are in testing and have not been properly configured, do not use for produciton environments
# Dependencies
psycopg2
