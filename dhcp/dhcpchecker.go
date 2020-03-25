package dhcpchecker

import (
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SingleTest struct {
	SrcMac     string
	ReceivedIp string
	DhcpServer string
}

type Client struct {
	HW         net.HardwareAddr
	PeerHw     net.HardwareAddr
	IP         net.IP
	IFName     string
	ethLayer   *layers.Ethernet
	ipLayer    *layers.IPv4
	udpLayer   *layers.UDP
	dhcpLayer  *layers.DHCPv4
	opts       gopacket.SerializeOptions
	pcapHandle *pcap.Handle
	lease      uint32
	t1         uint32
	t2         uint32
	macs       []string
}

func NewClient(macsToCheck []string, ifname, hostname string) (*Client, error) {
	srcIP := net.ParseIP("0.0.0.0")

	//eth layer
	eth := &layers.Ethernet{}
	//eth.SrcMAC = hw
	eth.DstMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	eth.EthernetType = layers.EthernetTypeIPv4

	//ip layer
	ip := &layers.IPv4{}
	ip.Version = 4
	ip.Protocol = layers.IPProtocolUDP
	ip.TTL = 64
	ip.SrcIP = srcIP
	ip.DstIP = net.ParseIP("255.255.255.255")

	//udp layer
	udp := &layers.UDP{
		SrcPort:  68,
		DstPort:  67,
		Length:   0,
		Checksum: 0,
	}

	//dhcpv4 layer and options
	dhcp4 := &layers.DHCPv4{}
	dhcp4.Flags = 0x0000
	dhcp4.Operation = layers.DHCPOpRequest
	dhcp4.HardwareType = layers.LinkTypeEthernet
	dhcp4.Xid = uint32(rand.Int31())
	dhcp4.ClientIP = net.ParseIP("0.0.0.0")
	//dhcp4.ClientHWAddr = hw

	options := []byte{
		1,  // (Subnet mask)
		2,  // (Time offset)
		3,  // (Routers)
		4,  // (Time server)
		5,  // (Name server)
		6,  // (DNS server)
		7,  // (Log server)
		8,  // (Cookie server)
		9,  // (LPR server)
		10, // (Impress server)
		11, // (Resource location server)
		12, // (Host name)
		13, // (Boot file size)
		14, // (Merit dump file)
		15, // (Domainname)
		16, // (Swap server)
		17, // (Root path)
		18, // (Extensions path)
		19, // (IP forwarding)
		20, // (Non-local source routing)
		21, // (Policy filter)
		22, // (Maximum datagram reassembly size)
		23, // (Default IP TTL)
		24, // (Path MTU aging timeout)
		25, // (Path MTU plateau table)
		26, // (Interface MTU)
		27, // (All subnets local)
		28, // (Broadcast address)
		29, // (Perform mask discovery)
		30, // (Mask supplier)
		31, // (Perform router discovery)
		32, // (Router solicitation)
		33, // (Static route)
		34, // (Trailer encapsulation)
		35, // (ARP cache timeout)
		36, // (Ethernet encapsulation)
		37, // (TCP default TTL)
		38, // (TCP keepalive interval)
		39, // (TCP keepalive garbage)
		40, // (NIS domain)
		41, // (NIS servers)
		42, // (NTP servers)
		43, // (Vendor specific info)
		44, // (NetBIOS name server)
		45, // (NetBIOS datagram distribution server)
		46, // (NetBIOS node type)
		47, // (NetBIOS scope)
		48, // (X Window System font server)
		49, // (X Window System display server)
		50, // (Request IP address)
		51, // (IP address leasetime)
		52, // (Option overload)
		53, // (DHCP message type)
		54, // (Server identifier)
		55, // (Parameter Request List)
		56, // (Message)
		57, // (Maximum DHCP message size)
		58, // (T1)
		59, // (T2)
		60, // (Vendor class identifier)
		61, // (Client-identifier)
		67, // (Bootfile name)
		66, // (TFTP server name)
	}

	dhcp4Opts := []layers.DHCPOption{
		{
			Type:   layers.DHCPOptMessageType,
			Length: 1,
			Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
		},

		{
			Type:   layers.DHCPOptParamsRequest,
			Length: (uint8)(len(options)),
			Data:   options,
		},

		{
			Type: layers.DHCPOptEnd,
		},
	}
	dhcp4.Options = dhcp4Opts

	//create read packet handle
	writeHandle, err := pcap.OpenLive(ifname, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Println("pcap open read handle error: ", err.Error())
		return nil, err
	}

	c := &Client{

		IP:        srcIP,
		IFName:    ifname,
		ethLayer:  eth,
		ipLayer:   ip,
		udpLayer:  udp,
		dhcpLayer: dhcp4,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		pcapHandle: writeHandle,
		macs:       macsToCheck,
	}

	return c, nil
}

func (c *Client) Start(testChan chan<- SingleTest, status chan<- int) error {

	timeout := 3 * time.Second
	//readHandle, err := pcap.OpenLive(c.IFName, 1024, false, pcap.BlockForever)
	readHandle, err := pcap.OpenLive(c.IFName, 1024, false, timeout)

	defer readHandle.Close()

	log.Println("Start client")
	if err != nil {
		log.Println(c.HW.String(), "pcap open write handle error: ", err.Error())
		return err
	}

	endChan := make(chan int, 1)

	go c.readPacket(readHandle, endChan, len(c.macs), testChan, status)

	err = c.sendDiscover()
	if err != nil {
		log.Println(c.HW, err)
		return err
	}

	<-endChan

	close(endChan)

	return nil
}

func (c *Client) readPacket(handle *pcap.Handle, endChan chan<- int, requestsNumber int, testChan chan<- SingleTest, status chan<- int) {

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	receivedDhcpPacket := 0

	var packet gopacket.Packet
	t := time.After(time.Second * 30)
	for {
		select {
		case packet = <-src.Packets():
			{
				if dhcp4layer := packet.Layer(layers.LayerTypeDHCPv4); dhcp4layer != nil {
					log.Println("Analyizing dhcpv4 packet")
					dhcp4 := dhcp4layer.(*layers.DHCPv4)

					if dhcp4.Operation == layers.DHCPOpReply {
						log.Println("DHCP Replay message found")
						mtype := byte(layers.DHCPMsgTypeOffer)
						log.Println(dhcp4.Options)
						if dhcp4.Options[0].Data[0] == mtype {

							log.Println("DHCP Offer message found")
							log.Printf("Offered IP: %v for %v\n", dhcp4.YourClientIP, dhcp4.ClientHWAddr)
							testChan <- SingleTest{
								SrcMac:     dhcp4.ClientHWAddr.String(),
								ReceivedIp: dhcp4.YourClientIP.String(),
								DhcpServer: net.IP(dhcp4.Options[1].Data).String(),
							}

						}
						receivedDhcpPacket += 1
					}

					if receivedDhcpPacket == requestsNumber {
						log.Println("All requests completed")
						status <- 0 // Tests completed
						endChan <- 1
						return

					}

				}

			}
		case <-t:
			{
				log.Println("Timeout")
				status <- 1 // Timeout reached
				endChan <- 1
				return
			}

		}
	}
}

func (c *Client) sendDiscover() error {

	for _, mac := range c.macs {

		c.ethLayer.SrcMAC, _ = net.ParseMAC(mac)
		c.dhcpLayer.ClientHWAddr, _ = net.ParseMAC(mac)

		buff := gopacket.NewSerializeBuffer()
		dhcp4Opts := c.dhcpLayer.Options
		dhcp4Opts[0].Data = []byte{byte(layers.DHCPMsgTypeDiscover)}

		err := c.udpLayer.SetNetworkLayerForChecksum(c.ipLayer)
		if err != nil {
			log.Println(c.HW, err)
			return err
		}

		err = gopacket.SerializeLayers(buff, c.opts,
			c.ethLayer,
			c.ipLayer,
			c.udpLayer,
			c.dhcpLayer)

		if err != nil {
			log.Println(c.HW, err)
			return err
		}
		log.Printf("Sending discovery packet using mac %v ", mac)
		c.writePacket(buff.Bytes())
	}
	return nil
}

func (c *Client) writePacket(buf []byte) error {
	if err := c.pcapHandle.WritePacketData(buf); err != nil {
		log.Printf("Failed to send packet: %s\n", err)
		return err
	}
	log.Println("Packet sent")
	return nil

}

func (c Client) Lease() uint32 {
	return c.lease
}

func (c Client) T1() uint32 {
	return c.t1
}

func (c Client) T2() uint32 {
	return c.t2
}
