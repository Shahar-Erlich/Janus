# Janus - Isolated Network Filtering & Protection
## About
This project's goal is to simulate live networks in the cloud in real time using [Docker](https://www.docker.com/) and the containerization technology

## The Goal of the Project
Janus simulates multiple networks that are isolated from each other.  
The networks are seperated to:  
`🟢Trusted Networks`  
`🔴Untrusted Networks`

Each network only has **1 gateway** and that is the `Janus Core`,   all packets must pass through it to reach other networks.

The `Janus Core`'s goal is to filter any  and all unwanted / harmful data that comes from `🔴Untrusted Networks`
and block it from reaching `🟢Trusted Networks`.

## Currently Implemented Parts
### Simulation
Currently the project only simulates 2 networks with 4 total computers:  
- 1 `🟢Trusted Networks` computer
- 3 `🔴Untrusted Networks` computers

**To start the simulation run:**  
`cd Janus`  
`docker compose up -d` *(d stands for "detached", seperating the simulated machines' terminal from the host one)*  

**To end the simulation (assuming already in the Janus directory) run:**
`docker compose down`  

### Filtering
Filters currently implemented (will be added to the list when implemented):  
- IP Blacklisting: simple checking if the ip who sent the packet is allowed  

- Vector Filtering: prefilter to search for smsall signatures using SIMD operations
- Aho Corasick: trie based algorithm to find signatures in text in a single run
- Regex: regular expression search in a string

## Stuff to Implement
### DPI
- ~~Aho-Corasick~~
- ~~Vector Filtering~~
### SPI
~~- More Efficient Blacklisting~~
### General
~~- PCAP Reading and Proccesing~~  
- ~~Figure out TCP stream stuff~~  
- Optimize
- Database
- Frontend for Statistics

 *!!Work In Progress!!*