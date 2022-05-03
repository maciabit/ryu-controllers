# Laboratory of Network Programmability and Automation - Notes

## Linux networking and namespaces commands

Show network configuration
```
$ ip addr
```

Traceroute
```
$ traceroute <IP_ADDR | URL>
```

Add a namespace (virtual host)
```
$ ip netns add <NAMESPACE>
```

Delete a namespace
```
$ ip netns del <NAMESPACE>
```

Delete all namespaces
```
$ ip -all netns delete
```

List existing namespaces
```
$ ip netns list
```

Execute a command on a namespace
```
$ ip netns exec <NAMESPACE> <COMMAND>
```

Create a virtual bridge
```
$ ip link add <BRIDGE> type bridge
```

Create a virtual bridge
```
$ ip link add <BRIDGE> type bridge
```

Create a virtual ethernet cable with two named plugs
```
$ ip link add <PLUG1> type veth peer name <PLUG2>
```

Connect a virtual ethernet plug to a namespace
```
$ ip link set <PLUG> netns <NAMESPACE>
```

Connect a virtual ethernet plug to a bridge
```
$ ip link set <PLUG> master <BRIDGE>
```

Enable a virtual ethernet interface (prefix `ip netns exec <NAMESPACE>` to do it on a namespace)
```
$ ip link set <PLUG | BRIDGE> up
```

Set the IP of a virtual ethernet interface (prefix `ip netns exec <NAMESPACE>` to do it on a namespace)
```
$ ip addr add <IP>/<MASK> dev <PLUG>
```

Set default gateway for a namespace
```
$ ip netns exec <NAMESPACE> ip route add default via <GATEWAY_IP>
```

Add a routing table entry in a namespace (useful for configuring virtual gateways)
```
$ ip netns exec <NAMESPACE> ip route add <IP>/<MASK> via <GATEWAY_IP>
```

## Mininet usage

Run Mininet with the default topology
```
$ sudo mn
```

Start a Mininet topology with the default configuration (TOPOLOGY_NAME must be defined in the topology.py file)
```
$ sudo mn --custom <topology.py> --topo <TOPOLOGY_NAME> --link tc,bw=10
```

Start a Mininet topology with a custom configuration (that must be defined in the topology.py folder)
```
$ sudo python3 <topology.py>
```

Start a Mininet topology with a custom controller (previously started with `ryu-manager`)
```
$ sudo mn --custom <topology.py> --topo <TOPOLOGY_NAME> --controller remote --switch ovsk --link tc,bw=10
```

Clear Mininet configuration
```
$ sudo mn -c
```

List available operations
```
mininet> ?
```

Print network nodes
```
mininet> nodes
```

Print network connections
```
mininet> links
```

Print network topology
```
mininet> net
```

Print switches port configuration
```
mininet> ports
```

Dump nodes info
```
mininet> dump
```

Test connectivity between all hosts
```
mininet> pingall
```

Ping one host from another
```
mininet> <HOST1> ping <HOST2>
```

Open a shell on an host
```
mininet> xterm <HOST>
```

Execute a command on an host
```
mininet> <HOST> <COMMAND>
```

## Open vSwitch usage

Dump OpenFlow rules on a Mininet switch
```
sudo ovs-ofctl dump-flows <SWITCH>
```

List controllers alongside their configuration
```
sudo ovs-vsctl list controller
```

Create a virtual bridge
```
sudo ovs-vsctl add-br <NAME>
```

Delete a virtual bridge
```
sudo ovs-vsctl del-br <NAME>
```

Create a virtual port
```
sudo ovs-vsctl add-port <BRIDGE> <INTERFACE>
```

Delete a virtual port
```
sudo ovs-vsctl del-port <NAME>
```

## Ryu usage

List default ryu apps (located at `~/ryu/ryu/app`)
```
$ ryu-manager --app-lists
```

Start a ryu controller app
```
$ ryu-manager <app.py>
```

Start a ryu controller on a custom port (default ones are 6633 and 6653)
```
$ ryu-manager --ofp-tcp-listen-port <PORT> <app.py>
```

Start a ryu controller along with a REST API for controlling it (`--wsapi-port <API_PORT>` can be omitted to start it on port 8080)
```
$ ryu-manager --ofp-tcp-listen-port <OFP_PORT> --wsapi-port <API_PORT> <app.py> <ofctl_rest.py>
```

## CURL usage

GET request
```
$ curl -X GET <URL>
```

POST request with JSON body
```
$ curl -d "@<body.json>" -X POST <URL>
```

## iPerf usage

Start server
```
$ iperf -s -p 55555
```

Test network performance between the current host and the given server.
- `-i 1`: report results every 1 second
- `-t 5`: set test duration to 5 seconds
```
$ iperf -c <SERVER_IP> -p 55555 -i 1 -t 5
```

## Network Function Virtualization

### Definitions

- **ETSI**: European Telecommunications Standards Institute
- **VNF**: Virtual Network Function
- **CNF**: Containerized Network Function
- **KNF**: Kubernetes Network Function
- **EM**: Element Management
- **NFVI**: Network Function Virtualization Infrastructure
- **VIM**: Virtualized Infrastructure Manager
- **NFVO**: Network Function Virtualization Orchestrator
- **VNFM**: Virtual Network Function Manager
- **VNFD**: Virtual Network Function Descriptor
- **NSD**: Network Service Descriptor

YAML keys:
- `df`: deployment flavour
- `ext-cpd`: external-connection point descriptor
- `vdu`: virtual deployment unit

## Definitions

### Day 0 operations
Management setup during instantiation

### Day 1 operations
Service initialization right after instantiation

### Day 2 operations
Re-configuration during runtime

### SIP
The Session Initiation Protocol (SIP) is a signaling protocol used for initiating, maintaining and terminating real-time sessions that include voice, video and messaging applications.

### RTP
The Real-Time Transport Protocol (RTP) is a network protocol for delivering audio and video over IP networks, using UDP.

### PBX
A Private Branch Exchange is a system that connects telephone extensions to the public switched telephone network (PSTN) and provides internal communication for a business.

### Ansible
Ansible is an open-source software provisioning, configuration management, and application-deployment tool enabling infrastructure as code. It runs on many Unix-like systems, and can configure both Unix-like systems as well as Microsoft Windows.\
**Ansible playbooks** are YAML files that express configurations, deployment and orchestration in Ansible.

### Helm
Helm is a package manager for Kubernetes. Helm packages are called charts.

### JUJU

**Native charms**

**Proxy charms**