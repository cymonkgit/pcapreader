package test

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/cymonkgit/pcapreader/rtsplayer"
	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// var filter = flag.String("f", "tcp and dst port 554", "BPF filter for pcap")

func Test_Rtsp(t *testing.T) {
	//
	fileName := "C:/Temp/1098-packet.pcapng"
	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Fatal(err)
		t.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Print the packet details
		// fmt.Println(packet.String())

		// Extract and print the Ethernet layer
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}

		ethPacket, _ := ethLayer.(*layers.Ethernet)
		// Extract and print the IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}

		ipPacket, _ := ipLayer.(*layers.IPv4)
		if (ipPacket.Protocol & layers.IPProtocolTCP) != layers.IPProtocolTCP {
			continue
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if nil == tcpLayer {
			continue
		}

		tcpPacket, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}

		if tcpPacket.DstPort != 554 {
			continue
		}

		payload := tcpPacket.LayerPayload()
		if nil == payload || len(payload) < 1 {
			continue
		}

		reqPacket := rtsplayer.NewRtspRequestPacket(payload)
		if nil != reqPacket {
			processRequest(packet, ethPacket, ipPacket, reqPacket)
		}

		// lines := splitBytesToString(payload)
		// fmt.Println(lines)

		fmt.Println("---")
	}
}

func processRequest(packet gopacket.Packet, ethPacket *layers.Ethernet, ipPacket *layers.IPv4, reqPacket gopacket.Packet) {
	if nil == reqPacket {
		return
	}

	rtspRequestLayer := reqPacket.Layer(util.LayerType_RtspRequest)
	if nil == rtspRequestLayer {
		return
	}

	req, ok := rtspRequestLayer.(*rtsplayer.RtspRequestLayer)
	if !ok {
		return
	}

	fmt.Println("==========================================================================================")
	fmt.Println("packet index:", packet.Metadata().InterfaceIndex)
	fmt.Println("Ethernet source MAC address:", ethPacket.SrcMAC)
	fmt.Println("Ethernet destination MAC address:", ethPacket.DstMAC)

	fmt.Println("IP source address:", ipPacket.SrcIP, ipPacket.SrcIP.String())
	fmt.Println("IP destination address:", ipPacket.DstIP)

	fmt.Println("tcp payload:", hex.EncodeToString(req.LayerContents()))

	fmt.Println("Method:", req.Method, ", Uri:", req.Uri, ", Version:", req.Version, ", CSeq:", req.CSeq)
	for key, option := range req.Messages {
		fmt.Println("  option: name=", key, ", value=", option)
	}
}
