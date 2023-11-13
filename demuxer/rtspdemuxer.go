package demuxer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	rtplayer "github.com/cymonkgit/pcapreader/layers/rtp"
	rtsplayer "github.com/cymonkgit/pcapreader/layers/rtsp"
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
	lastRtspPacketTime time.Time
	lastTcpSeq         uint32
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
	Unx := ctx.FirstRtspPacketTime.UnixNano()
	fmt.Println(Unx, ctx.FirstRtspPacketTime.String())

	return dmx, nil
}

func getBPFFilter(transfer rtsplayer.TransferType, serverAddress, clientAddress, clientPort string) (filter string, err error) {
	// TCP
	if transfer == rtsplayer.TransferProtocol_TCP {
		// e.g "(src host 172.168.11.148 && src dstPort 554) || (dst host 172.168.11.148 && dst dstPort 554)"
		srcIp, srcPort, er := rtsplayer.GetIpPort(serverAddress)
		if nil != er {
			err = er
			return
		}

		dstIp, dstPort, er := rtsplayer.GetIpPort(clientAddress)
		if nil != er {
			err = er
			return
		}
		filter = fmt.Sprintf("(tcp && src host %v && src port %v && dst host %v && dst port %v)", srcIp, srcPort, dstIp, dstPort)
		return
	} else if transfer == rtsplayer.TransferProtocol_UDP {
		serverIp, rtspPort, er := rtsplayer.GetIpPort(serverAddress)
		if nil != er {
			err = er
			return
		}
		clientIp, _, er := rtsplayer.GetIpPort(clientAddress)
		if nil != er {
			err = er
			return
		}
		clientPorts := strings.Split(clientPort, "-")
		if len(clientPorts) != 2 {
			err = errors.New("invalid rtp receive port range value")
			return
		}
		filter = fmt.Sprintf("(tcp && src host %v && src port %v) || (tcp && dst host %v && dst port %v) || (udp && dst %v && portrange %v-%v)",
			serverIp, rtspPort, serverIp, rtspPort, clientIp, clientPorts[0], clientPorts[1])
		return
	} else {
		err = errors.New("invalid RTSP protocol type")
		return
	}
}

func open(fileName string, transfer rtsplayer.TransferType, serverAddress, clientAddress, clientPort string, startTime time.Time) (dmx *RtspDemuxer, err error) {
	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return nil, err
	}

	// set BPF filter
	bpfFilter, err := getBPFFilter(transfer, serverAddress, clientAddress, clientPort)
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
	dmx.firstRtspPacketTime = startTime
	fmt.Println("firstRtspPacketTime:", startTime.String())
	// dmx.firstRtspPacketTime = ctx.FirstRtspPacketTime

	return dmx, nil
}

func (dmx *RtspDemuxer) Close() {
	if nil != dmx.handle {
		dmx.handle.Close()
	}
}

func printhex16(b []byte) {
	fmt.Println("% X", b[:16])
}

func (dmx *RtspDemuxer) ReadPacket(remains *[]byte, idx int) (*util.BytePacket, error) {
	// Loop through packets in file
	// ignore channel, ssrc id. just pass through stream server to client to emulate RTSP stream
	rtpReassemble := false
	if len(*remains) > 0 {
		rtpReassemble = true
	}

	for {
		packet, err := dmx.packetSource.NextPacket()
		if nil != err {
			return nil, err
		}

		packetTimestamp := packet.Metadata().CaptureInfo.Timestamp
		captureLength := packet.Metadata().CaptureLength
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

		// skip tcp re-transmission
		if dmx.lastTcpSeq != 0 && tcpPacket.Seq == dmx.lastTcpSeq {
			continue
		}
		dmx.lastTcpSeq = tcpPacket.Seq

		payload := tcpPacket.LayerPayload()
		if nil == payload || len(payload) < 1 {
			// return errors.New("has no payload")
			continue
		}

		var payload2 []byte
		if rtpReassemble {
			payload2 = append(*remains, payload...)
			*remains = nil
		} else {
			payload2 = payload
		}

		var ilfi []util.InterleavedPacketInfo
		packetOk := false
		for {
			interleavedPacket := rtsplayer.NewRtspInterleavedFramePacket(payload2)
			if nil == interleavedPacket {
				*remains = nil
				break
			}

			interleavedLayer := interleavedPacket.Layer(util.LayerType_RtspInterleavedFrame)
			if nil == interleavedLayer {
				if len(payload) >= 4 && payload2[0] == 0x24 {
					*remains = payload2
				} else {
					*remains = nil
				}
				break
			}

			il := interleavedLayer.(*rtsplayer.RtspInterleavedFrameLayer)
			Len := il.Length + 4
			if Len > uint16(len(payload2)) {
				rtpReassemble = true
				*remains = payload2
				break
			} else {
				rtpLayer := interleavedPacket.Layer(util.LayerType_Rtp)
				// fmt.Println(rtpLayer)
				if nil == rtpLayer {
					continue
				}

				rl := rtpLayer.(*rtplayer.RtpLayer)

				packetOk = true
				if nil == ilfi {
					ilfi = make([]util.InterleavedPacketInfo, 0)
				}
				ilfi = append(ilfi, util.InterleavedPacketInfo{
					Len:       il.Length,
					Marker:    rl.Header.Marker,
					SeqNumber: int(rl.Header.SequenceNumber),
					SSRC:      rl.Header.SSRC,
					PT:        rl.Header.PayloadType,
				})
			}

			if Len >= uint16(len(payload2)) {
				break
			} else {
				payload2 = payload2[Len:]
			}
		}

		if !packetOk {
			if !dmx.lastRtspPacketTime.IsZero() && dmx.lastRtspPacketTime.Add(time.Second*5).Before(packetTimestamp) {
				// timeout
				return nil, errors.New("timeout")
			}
			continue
		}

		dmx.lastRtspPacketTime = packetTimestamp

		bp := util.BytePacket{
			Payload:       payload,
			Time:          packetTimestamp,
			CaptureLength: captureLength,
			Reassembled:   rtpReassemble,
			ILFI:          ilfi,
		}

		return &bp, nil
	}
}
