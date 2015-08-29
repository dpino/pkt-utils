# Packet utils

Very basic scripts for doing things with network packets.

## Pkt-info

Prints out info of packets stored in a .pcap file. Example:

```
$ pkt-info packet.pcap
Eth:    88:b4:2c:fa:ac:8 > b6:fc:5e:33:55:a0; type: 0x800
IP: 168.0.8.93 > 184.216.34.255; csum: 0x768a
TCP:    2503 > 0; csum: 0x6456
```

### Pkt-copy-hdr

Takes a packet as template and copies the packet header from a source into a new packet. Example:

```
$ pkt-copy-hdr source.pcap template.pcap /tmp/output.pcap
```

The purporse of this tool was to create packets of certain size with hping3 and later copy into them the header of other similar packets. I could ```tcprewrite``` the packet with the data from source, but that was tedious.
