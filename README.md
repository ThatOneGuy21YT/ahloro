# ahlora
A WIP dashboard that sends IoT data over a DFLoRaWAN or Milesight UG65 Gateway.
The primary goal of this project is to gain experience with IoT and Postgres workflows and make a dashboard that can be deployed on a dedicated platform like Railway or Render. It's coded primarily by AI and is not certified for secure use in enterprise environments, though I'd say is perfectly cromulent for a local connection or a VPN connection through wireguard, tailscale, and whatever else tickles your fancy.

The site supports mobile and desktop scaling, PWA, and a for the most part functioning server data polling system that uses an API key to secure it's data. The variable is set as seen in the .env.example file. The postgres database url is also set in the .env file, as seen in the example along with the API key.

# Implemented Features
## PostgreSQL Table Viewer
Having a table viewer built into the dashboard makes it easier to see what the logs look like from the database POV instead of a simple event viewer. This would allow for other developers to extract data from the dashboard and implement the data in other scripts. This is especially of use for those that like to script event based actions, like turning a light on when pressing a button, or kicking up their AC if the temperature in a specific room is different from the rest of their house (so most AC units).

## Certification Checks and Encryption
Traffic is sent securely by a user defined API_KEY. Their is also a customizable BROWSER_PASSWORD variable that asks the client for a password to access the site. Though note that if a BROWSER_PASSWORD is used, OAuth will be disabled.

## User Account Control (OAuth)
Using OAuth from Google's APIs, there is now email login support as well as a variable based whitelist for access. By default the entire site is blocked until the user logs in, but even after login, all hidden files and scripts cannot be accessed remotely.

Though not implemented yet, I plan to add support for devices to be attached to accounts across multiple gateways. Or at the very least, I want to be able to assign gateways to individual accounts.

## Multi-Gateway/Poller Support
Implemented the Milesight UG65 as a secondary option for a gateway. by having multiple pollers configured and sending data to the same dashboard, you can see devices across an array of gateways in one place. UG65 requires browser token to access data since chirpstack is read only. Once you log in, the token expiration isn't enforced (probably a bug, but definitely taking advantage of it) and by setting a variable as the token (can be found in inspect window in most requests) then the payload can be grabbed from the gateway directly.

This method will probably need to be updated in the future for newer firmware releases, but it's acceptable for now as long as it's done within a closed non production environment.

# WIP Features
## Device Classifier
The device_classifier.py has not been thoroughly tested, if the correct device type does not appear when an EUID is imported, then simply change the dropdown selection to a device type that most similarly aligns with the device type. To properly configure your device, check the hexadecimal values that your LoRaWAN compatible device sends and set the placements (offsets) of the values in the byte offset menu. The script by default will guess based on the text content of the device name.

## Sound Sensors
Sound Devices are in testing and have not been properly configured, currently it is only tested with Milesight WS302 and takes average db data. In any case, using the byte offset will allow any sensor to work theoretically, it just hasn't been given the time it deserves.

# Planned Features/Roadmap
## UI Customization
As of right now, the UI can be configured with a specific device selected, but I'd rather have a dashboard that can have data from multiple devices visible at once. Testing of the new UI can be found on the UI-Custom branch

# Dependencies 
psycopg2, postgresql, cryptography, a computer??????
