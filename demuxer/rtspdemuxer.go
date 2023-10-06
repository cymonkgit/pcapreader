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
	handle       *pcap.Handle
	BpfFilter    string
	packetSource *gopacket.PacketSource

	firstRtspPacketTime time.Time

	firstRtspTimestamp uint32
}

func Open(fileName string, ctx *rtsplayer.RtspContext) (dmx *RtspDemuxer, err error) {
	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return nil, err
	}

	// set BPF filter
	bpfFilter, err := ctx.GetBPFFilter()
	if nil != err {
		return nil, err
	}

	err = handle.SetBPFFilter(bpfFilter)
	if nil != err {
		return nil, err
	}

	dmx = &RtspDemuxer{}
	dmx.packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	if nil == dmx {
		return nil, errors.New("failed to create packet source")
	}

	dmx.handle = handle
	dmx.firstRtspPacketTime = ctx.FirstRtspPacketTime

	return dmx, nil
}

func (dmx *RtspDemuxer) Close() {
	if nil != dmx.handle {
		dmx.handle.Close()
	}
}

func (dmx *RtspDemuxer) ReadPacket() (*util.BytePacket, error) {
	// Loop through packets in file
	// ignore channel, ssrc id. just pass through stream server to client to emulate RTSP stream
	for {
		packet, err := dmx.packetSource.NextPacket()
		if nil != err {
			return nil, err
		}

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

		// timestamp := rtpLayer.(*rtplayer.RtpLayer).Header.Timestamp
		ssrc := rtpLayer.(*rtplayer.RtpLayer).Header.SSRC

		bp := util.BytePacket{
			Payload: payload,
			Time:    packetTimestamp,
			SSRC:    ssrc,
		}

		return &bp, nil
	}
}
