#!/usr/bin/python
import socket
import sys
from struct import Struct
import struct


'''
Listen for DHCP ACK Messages and report the server IPs and the client IPs seen.

A passive recon of hosts on the network.  This listens on UDP port 68 and
therefore must run as a privileged user.  You must wait for clients to contact
the DHCP servers before any results are shown.
'''

args = sys.argv[1:]
dhcp_server = args[0] if args else None  # if no DHCP server specified, then listen for any DHCP ACK


# The DHCP Options Table
optionstable = {
        0:	("Pad",                                     None),      # Can be used to pad other options so that they are aligned to
                                                                        # the word boundary; is not followed by length byte
        1:	("Subnet mask",                             '4'),       # Must be sent before the router option (option 3) if both are included
        2:	("Time offset",                             '4'),
        3:	("Router",                                  '4 * n'),   # Available routers, should be listed in order of preference
        4:	("Time server",                             '4 * n'),   # Available time servers to synchronise with, should be listed in order of preference
        5:	("Name server",                             '4 * n'),   # Available IEN 116 name servers, should be listed in order of preference
        6:	("Domain name server",                      '4 * n'),   # Available DNS servers, should be listed in order of preference
        7:	("Log server",                              '4 * n'),   # Available log servers, should be listed in order of preference.
        8:	("Cookie server",                           '4 * n'),   # Cookie in this case means "fortune cookie" or "quote of the day",
                                                                        # a pithy or humorous anecdote often sent as part of a logon process on
                                                                        # large computers; it has nothing to do with cookies sent by websites.
        9:	("LPR Server",                              '4 * n'),	
        10:	("Impress server",                          '4 * n'),
        11:	("Resource location server",                '4 * n'),
        12:	("Host name",                               '1+' ),
        13:	("Boot file size",                          '2'),       # Length of the boot image in 4KiB blocks
        14:	("Merit dump file",                         '1+'),      # Path where crash dumps should be stored
        15:	("Domain name",                             '1+'),
        16:	("Swap server",	                            '4'),
        17:	("Root path",	                            '1+'),
        18:	("Extensions path",	                    '1+'),
        255:	("End",	                                    None),      # Used to mark the end of the vendor option field

        # IP layer parameters per host[13]:Section 4
        # Code	Name	Length	Notes

        19:	("IP forwarding enable/disable",            '1'),
        20:	("Non-local source routing enable/disable", '1'),
        21:	("Policy filter",                           '8 * n'),
        22:	("Maximum datagram reassembly size",        '2'),
        23:	("Default IP time-to-live",                 '1'),
        24:	("Path MTU aging timeout",                  '4'),
        25:	("Path MTU plateau table",                  '2 * n'),

        # IP Layer Parameters per Interface[13]:Section 5
        # Code	Name	Length	Notes

        26:	("Interface MTU",                           '2'),
        27:	("All subnets are local",                   '1'),
        28:	("Broadcast address",                       '4'),
        29:	("Perform mask discovery",                  '1'),
        30:	("Mask supplier",                           '1'),
        31:	("Perform router discovery",                '1'),
        32:	("Router solicitation address",             '4'),
        33:	("Static route",                            '8 * n'),   # A list of destination/router pairs

        # Link layer parameters per interface[13]:Section 6
        # Code	Name	Length	Notes

        34:	("Trailer encapsulation option",            '1'),
        35:	("ARP cache timeout",                       '4'),
        36:	("Ethernet encapsulation",                  '1'),

        # TCP parameters[13]:Section 7
        # Code	Name	Length	Notes

        37:	("TCP default TTL",                         '1'),
        38:	("TCP keepalive interval",                  '4'),
        39:	("TCP keepalive garbage",                   '1'),

        # Application and service parameters[13]:Section 8
        # Code	Name	Length	Notes

        40:	("Network information service domain",      '1 * n'),
        41:	("Network information servers",             '4 * n'),
        42:	("Network Time Protocol (NTP) servers",     '4 * n'),
        43:	("Vendor-specific information",             '1 * n'),
        44:	("NetBIOS over TCP/IP name server",         '4 * n'),
        45:	("NetBIOS over TCP/IP datagram Distribution Server", 	'4 * n'),
        46:	("NetBIOS over TCP/IP node type",           '1'),
        47:	("NetBIOS over TCP/IP scope",               '1+'),
        48:	("X Window System font server",             '4 * n'),
        49:	("X Window System display manager",         '4 * n'),
        64:	("Network Information Service+ domain",     '1+'),
        65:	("Network Information Service+ servers",    '4 * n'),
        68:	("Mobile IP home agent",                    '4 * n'),
        69:	("Simple Mail Transfer Protocol (SMTP) server",         '4 * n'),
        70:	("Post Office Protocol (POP3) server",      '4 * n'),
        71:	("Network News Transfer Protocol (NNTP) server",        '4 * n'),
        72:	("Default World Wide Web (WWW) server",     '4 * n'),
        73:	("Default Finger protocol server",          '4 * n'),
        74:	("Default Internet Relay Chat (IRC) server",'4 * n'),
        75:	("StreetTalk server",                       '4 * n'),
        76:	("StreetTalk Directory Assistance (STDA) server", 	'4 * n'),

        # DHCP extensions[13]:Section 9
        # Code	Name	Length	Notes

        50:	("Requested IP address",                    '4'),
        51:	("IP address lease time",                   '4'),
        52:	("Option overload",                         '1'),
        53:	("DHCP message type",                       '1'),
        54:	("Server identifier",                       '4'),
        55:	("Parameter request list",                  '1+'),
        56:	("Message",                                 '1+'),
        57:	("Maximum DHCP message size",               '2'),
        58:	("Renewal (T1) time value",                 '4'),
        59:	("Rebinding (T2) time value",               '4'),
        60:	("Vendor class identifier",                 '1+'),
        61:	("Client-identifier",                       '2+'),
        66:	("TFTP server name",                        '1+'),
        67:	("Bootfile name",                           '1+'),

        # Client vendor identification
        # An option exists to identify the vendor and functionality of a DHCP client.
        # The information is a variable-length string of characters or octets which has
        # a meaning specified by the vendor of the DHCP client. One method that a
        # DHCP client can utilize to communicate to the server that it is using a
        # certain type of hardware or firmware is to set a value in its DHCP requests
        # called the Vendor Class Identifier (VCI) (Option 60).

        # This method allows a DHCP server to differentiate between the two kinds of
        # client machines and process the requests from the two types of modems
        # appropriately. Some types of set-top boxes also set the VCI (Option 60) to
        # inform the DHCP server about the hardware type and functionality of the
        # device. The value this option is set to gives the DHCP server a hint about
        # any required extra information that this client needs in a DHCP response.

        # Documented elsewhere
        # Documented DHCP options
        # Code	Name	Length	RFC

        82:	("Relay agent information",                 '2+'),
        85:	("Novell Directory Service (NDS) servers",  '4 * n'),
        86:	("NDS tree name",                           '0+'),
        87:	("NDS context",                             '0+'),
        100:	("Time zone, POSIX style",                  '0+'),
        101:	("Time zone, tz database style",            '0+'),
        119:	("Domain search",                           '0+'),
        121:	("Classless static route",                  '0+'),

}

seenIps = {}


sock = socket.socket(socket.AF_INET,  socket.SOCK_DGRAM)
sock.bind(("255.255.255.255", 68))

fmt = '>BBBBLHHLLLLQ64s128sL' 
#fmt = '>BBBBLHHLLLLLLLL192xL'

# Array indices for unpacked data
IDX_OPCODE          = 0
IDX_HTYPE           = 1
IDX_HLEN            = 2
IDX_HOPS            = 3
IDX_XID             = 4
IDX_SECONDSELAPSED  = 5
IDX_BOOTPFLAGS      = 6
IDX_CLIENTADDR      = 7
IDX_YOURADDR        = 8
IDX_SERVERADDR      = 9
IDX_GIADDR          = 10
IDX_CHADDR          = 11
IDX_SNAME           = 12
IDX_BOOTNAME        = 13
IDX_MAGICCOOKIE     = 14

dst = Struct(fmt)
siz = dst.size

while True:
    gotit = sock.recvfrom(1024)
    data, whofrom = gotit
    if len(whofrom) > 1 and whofrom[1] != 67:
        print("Error: source from wrong port")
        continue
    sourceType = seenIps.get(whofrom[0], None)
    if not sourceType:
        seenIps[whofrom[0]] = 'Server'
        print(whofrom[0], 'Server')

    if dhcp_server and dhcp_server != whofrom[0]:
        continue

    udata = dst.unpack_from(data[:siz])

    if udata[IDX_OPCODE] != 2 or udata[IDX_HTYPE] != 1 or udata[IDX_HLEN] != 6 or udata[IDX_HOPS] != 0:
        continue
    if udata[IDX_MAGICCOOKIE] != 0x63825363:
        print("Error: magic number is wrong")
        print(udata)
        continue

    leasee = "%d.%d.%d.%d" % (((udata[7]>>24)&0xff), ((udata[7]>>16)&0xff), ((udata[7]>>8)&0xff), (udata[7]&0xff))
    serverIp = None
    dhcpMsg = None
    leasetime = None
    subnetmas = None

    options = data[siz:]
    while options:
        option  = options[0]
        options = options[1:]
        optname, optsize = optionstable.get(ord(option), (None,None))
        if optsize:
            optsize = ord(options[0])
            options = options[1:]
        optval = options[:optsize] if optsize else None
        options = options[optsize:] if optsize else options
        if optname == "Server identifier":
            if optsize == 4:
                serverIp = "%d.%d.%d.%d" % (ord(optval[0]), ord(optval[1]), ord(optval[2]), ord(optval[3]))
        elif optname == "DHCP message type":
            if optsize:
                dhcpMsg = "%d" % ord(optval[0])
        elif optname == "Subnet mask":
            if optsize == 4:
                subnetMask = "%d.%d.%d.%d" % (ord(optval[0]), ord(optval[1]), ord(optval[2]), ord(optval[3]))
        elif optname == "IP address lease time":
            if optsize == 4:
                leasetime = struct.unpack(">L",optval)[0]
        if optname == "End":
            break

    if serverIp:
        seen = seenIps.get(serverIp, None)
        if not seen:
            seenIps[serverIp] = 'Server'
            print(serverIp, "Server")

    if dhcpMsg and dhcpMsg == "5":
        seen = seenIps.get(leasee, None)
        if not seen:
            seenIps[leasee] = 'Client'
            print(leasee, "Client")

