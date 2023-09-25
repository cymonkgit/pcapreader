package rtsplayer

import (
	"errors"

	"github.com/cymonkgit/pcapreader/rtp"
	"github.com/cymonkgit/pcapreader/rtplayer"
	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
)

var RtspInterleavedFrameLayerType gopacket.LayerType

func init() {
	RtspInterleavedFrameLayerType = gopacket.RegisterLayerType(
		util.LayerType_RtspInterleavedFrame,
		gopacket.LayerTypeMetadata{
			Name:    "RTSPItnerleavedFrame",
			Decoder: gopacket.DecodeFunc(decodeRtspInterleavedFrame),
		},
	)
}

type RtspInterleavedFrameLayer struct {
	Dollar  uint8
	Channel uint8
	Length  uint16
	body    []byte
	trailer []byte
}

// NewRtspRequestPacket function. RTSP request 에 해당하는 패킷인지 판별하여 패킷을 생성한다.
func NewRtspInterleavedFramePacket(data []byte) gopacket.Packet {
	return gopacket.NewPacket(
		data,
		RtspInterleavedFrameLayerType,
		gopacket.Default,
	)
}

// LayerType함수. gopacket.Layer interface의 implementation. 패킷의 LayerType을 반환
func (l RtspInterleavedFrameLayer) LayerType() gopacket.LayerType {
	return RtspInterleavedFrameLayerType
}

// LayerType함수. gopacket.Layer interface의 implementation. 패킷의 전체 byte 데이터를 반환.
func (l RtspInterleavedFrameLayer) LayerContents() []byte {
	return append(l.body, l.trailer...)
}

// LayerPayload함수. gopacket.Layer interface의 implementation. 패킷 payload byte 데이터를 반환.
func (l RtspInterleavedFrameLayer) LayerPayload() []byte {
	return l.trailer
}

func (l RtspInterleavedFrameLayer) NextLayerType() gopacket.LayerType {
	if len(l.trailer) > 0 {
		h := &(rtp.RtpHeader{})
		if _, err := h.Unmarshal(l.trailer); err == nil {
			return rtplayer.RtpLayerType
		}
	}

	return gopacket.LayerTypePayload
}

// decodeRtspInterleavedFrame 함수. rtsp interleaved frame 에 해당하는 데이터인지를 판별한다.
func decodeRtspInterleavedFrame(data []byte, p gopacket.PacketBuilder) error {
	res := parseInterleavedFrame(data)
	if nil == res {
		return errors.New("no rtp interleaved frame")
	}

	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(res)

	// todo : make option for debug
	// if nil != res.trailer && len(res.trailer) > 0 {
	// 	fmt.Println("")
	// }
	return p.NextDecoder(res.NextLayerType())
}

func parseInterleavedFrame(data []byte) *RtspInterleavedFrameLayer {
	if len(data) < 4 {
		return nil
	}

	if data[0] != '$' {
		return nil
	}

	Len := util.Beu16(data[2:])
	r := RtspInterleavedFrameLayer{
		Dollar:  data[0],
		Channel: data[1],
		Length:  Len,
		body:    data[:4],
		trailer: data[4 : Len+4],
	}

	return &r
}
