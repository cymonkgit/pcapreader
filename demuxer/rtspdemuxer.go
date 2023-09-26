package demuxer

import (
	"errors"
	"fmt"
	"time"

	"github.com/cymonkgit/pcapreader/rtplayer"
	"github.com/cymonkgit/pcapreader/rtsplayer"
	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type RtspDemuxer struct {
	Handle       pcap.Handle
	BpfFilter    string
	packetSource *gopacket.PacketSource

	firstRtspPacketTime time.Time
}

func (dmx *RtspDemuxer) Open(fileName string, ctx *rtsplayer.RtspContext) error {
	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return err
	}
	defer handle.Close()

	// set BPF filter
	bpfFilter, err := ctx.GetBPFFilter()
	if nil != err {
		return err
	}
	err = handle.SetBPFFilter(bpfFilter)
	if nil != err {
		return err
	}

	dmx.packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	if nil == dmx {
		return errors.New("failed to create packet source")
	}

	dmx.firstRtspPacketTime = ctx.FirstRtspPacketTime

	return nil
}

func (dmx *RtspDemuxer) ReadPacket() {
	// lastTimestamp := time.Time{}
	// Loop through packets in file
	for packet := range dmx.packetSource.Packets() {
		packetTimestamp := packet.Metadata().CaptureInfo.Timestamp
		if packetTimestamp.Before(dmx.firstRtspPacketTime) {
			continue
		}

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}

		ethPacket, _ := ethLayer.(*layers.Ethernet)
		if nil == ethPacket {
			continue
		}
		// Extract and print the IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}

		ipPacket, _ := ipLayer.(*layers.IPv4)
		if (ipPacket.Protocol & layers.IPProtocolTCP) != layers.IPProtocolTCP {
			// return errors.New("no ipv4 packet")
			continue
		}

		// clientIp := ipPacket.SrcIP.String()
		// serverIp := ipPacket.DstIP.String()

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if nil == tcpLayer {
			// return errors.New("no tcp packet")
			continue
		}

		tcpPacket, ok := tcpLayer.(*layers.TCP)
		if !ok || nil == tcpPacket {
			// return errors.New("no tcp packet")
			continue
		}

		payload := tcpPacket.LayerPayload()
		if nil == payload || len(payload) < 1 {
			// return errors.New("has no payload")
			continue
		}

		// fmt.Println("data:", payload[0])

		interleavedPacket := rtsplayer.NewRtspInterleavedFramePacket(payload)
		if nil == interleavedPacket {
			continue
		}

		interleavedLayer := interleavedPacket.Layer(util.LayerType_RtspInterleavedFrame)
		if nil == interleavedLayer {
			continue
		}

		rtpLayer := interleavedPacket.Layer(util.LayerType_Rtp)
		fmt.Println(rtpLayer)
		if nil == rtpLayer {
			continue
		}

		timestamp := rtpLayer.(*rtplayer.RtpLayer).Header.Timestamp

		bp := util.BytePacket{
			Payload:   payload,
			Timestamp: timestamp,
		}

		fmt.Println(bp)

		// return &bp
		// ctx.output <- &bp
	}

	return nil
}
