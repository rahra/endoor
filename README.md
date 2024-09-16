# Endoor

Endoor is a powerful penetration testing tool which supports network
reconnaissance and network infiltration.  Endoor is intended to be run on a
small device with 2 Ethernet interfaces, such as a Raspberry Pi, and shall be
plugged in between the victim's network and a node of the network (e.g. a
computer or printer).  Endoor transparently switches all frames back and forth
between its 2 network interfaces.  After a learning phase you can access the
network. Endoor transparently reuses the MAC address and the IP address of the
victim's node thereby being almost undetectable and bypassing L2 protection
mechanisms such as MAC filtering or 802.1x authentication.

The following diagram depicts its general use-case.

```
                        outside           inside
                       interface         interface
                           |                 |
( victim's network ) <----> ( Endoor device ) <----> ( victim's node )
                                    ^
                                    |
                           ( mobile network )
                                    |
                                    |
                               ( attacker )
```

# How to use Endoor

As already said it is intended to be installed on a small device (the endoor
device) on which endoor is run. The endoor device must have 2 Ethernet
interfaces and any 3rd interface through which you (the pentester) can access
the device. In real scenarios this most probably will be through a mobile
network but in lab environments you could access it through Wifi as well.

Once setup properly (see **Preparation** below) just connect it in between a
computer (or other device) and the uplink. Then ssh to it through your access
network and attack ;)

# Preparation

The 2 network interfaces are called "inside" and "outside" interface where
inside is the interface to the node and outside is the interface to the network
(see diagram above).

First of all **you have to disable** _generic receive offloading_ (GRO) and
_large receive offloading_ (LRO) on both interfaces. This is a hardware feature
to speed up network throughput but in this case it will cause packet drops
because Endoor processes and forwards frames in software. At some time I'll
probably implement it directly into Endoor. It is done with the `ethtool`:

```
ethtool -K eth0 gro off
ethtool -K eth0 lro off
ethtool -K eth1 gro off
ethtool -K eth1 lro off
```

These 2 network interfaces shoud be completely unconfigured and silent. That
means set it up in such a way that there are no IP addresses configured and the
DHCP client has to be disabled (otherwise the Endoor device may reveal itself).

If you use a Raspberry Pi, edit the file `/etc/dhcpcd.conf` and add the
following 2 lines (assuming eth0 and eth1 are the inside and the outside
interface):
```
denyinterfaces eth0
denyinterfaces eth1
```

I also suggest to disable any service except sshd. Disable IPV6
auto-configuration and do not accept router advertisements. This is necessary to
not reveal your device (see `files/osprep` of the source package).
```
sysctl -w net.ipv4.conf.all.forwarding=0
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv6.conf.eth0.autoconf=0
sysctl -w net.ipv6.conf.eth1.accept_ra=0
```

In a next step copy the endoor package to it, unpack, compile, and install it.
```
tar xfz endoor-1.0.tar.gz
cd endoor-1.0
./configure
make
sudo make install
```

# Starting Endoor

You can now start endoor directly on the command line:
```
endoor -i eth0 -o eth1
```

It will immediately start to forward frames and will open a command line
interface. The command line is mainly for debugging. Use `help` to get a list
of commands.

Endoor will learn addresses from the network and tries to find the client's IP
address and MAC address as well as the MAC address of the router in the
network. Once found, it will open and configure a tunnel device (tun0).
The victim's device's IP address will be set locally on the tunnel device.

*Note:* Please note that the router detection is not very robust yet. You may
find the router's MAC address manually by looking at the address table (command
`addr`, or `dump`, or use the HTTP API as explained below). You can then set
the address either with the command line option `-r` or on the CLI with the
command `router`. Endoor will not override this manual setting.

From the address table in the command line you may have learned about the IP
range of the victim's network. Let's assume all internal addresses are in the
range of 192.168.0.0/16.

So open a new shell and add a route to the tunnel device:
```
sudo ip route add 192.168.0.0/16 dev tun0
```

From this point you can access any address within this range from the endoor
device, e.g.:
```
ping 192.168.17.23
```

Endoor will send all packets coming in locally on the tunnel device to the
victim's network with a source address of the victim's node's IP an MAC
address.
Internally, endoor builds up a state table. Returning packets from the victim's
network are matched against the state table and all packets with a proper state
are then diverted back to the tunnel device. All other packets are sent back to
the node. This state-based traffic splitting allows that the endoor device and
the victim's node both can access the network although using the same MAC and
IP address.

Since the states depend on the higher layer protocols, only protocols which are
implemented within Endoor are supported (from the Endoor's point of view).
Currently this is TCP, UDP, and ICMP echo requests.

But that's more than enough for now, you can e.g. `nmap` through it ;)

# API

There is a tiny HTTP API which allows you to dump the address table from within
a script.
It is bound to port 8880. Dump with the following command:

```
curl http://localhost:8880/api/v1/?dump
```

# Detectability

## Physical detection

## Bridge transparency

## Self-revealed

## Timing

## State collisions

## Switch port state

## Traffic analysis

