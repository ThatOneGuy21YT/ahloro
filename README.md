# ahlora
A WIP dashboard that sends IoT data over a DFLoRaWAN Gateway.
The primary goal of this project is to gain experience with IoT and Postgres workflows and make a dashboard that can be deployed on a dedicated platform like Railway or Render. It's coded primarily by AI and is not certified for secure use in enterprise environments, though I'd say is perfectly cromulent for a local connection or a VPN connection through wireguard, tailscale, and whatever else tickles your fancy.

The site supports mobile and desktop scaling, PWA, and a for the most part functioning server data polling system that uses an API key to secure it's data. The variable is set as seen in the .env.example file. The postgres database url is also set in the .env file, as seen in the example along with the API key

# WIP Features
## Device Classifier
The device_classifier.py has not been thoroughly tested, if the correct device type does not appear when an EUID is imported, then simply change the dropdown selection to a device type that most similarly aligns with the device type. To properly configure your device, check the hexadecimal values that your LoRaWAN compatible device sends and set the placements (offsets) of the values in the byte offset menu.
## Sound Sensors
Sound Devices are in testing and have not been properly configured, do not use for produciton environments.
# Planned Features/Roadmap
## Multi-Gateway
I plan to implement the ability to gain data from multiple gateways at once from different brands as I get the ability to, though it is not the primary goal at this time.
## PostgreSQL Table Viewer
Having a table viewer built into the dashboard makes it easier to see what the logs look like from the database POV instead of a simple event viewer. This would allow for other developers to extract data from the dashboard and implement the data in other scripts. This is especially of use for those that like to script event based actions, like turning a light on when pressing a button, or kicking up their AC if the temperature in a specific room is different from the rest of their house (so most AC units).
# Dependencies
psycopg2
