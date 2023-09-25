package rtplayer

import (
	"errors"

	"github.com/cymonkgit/pcapreader/rtp"
	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
)

var RtpLayerType gopacket.LayerType

func init() {
	RtpLayerType = gopacket.RegisterLayerType(
		util.LayerType_Rtp,
		gopacket.LayerTypeMetadata{
			Name:    "RTP",
			Decoder: gopacket.DecodeFunc(decodeRtp),
		},
	)
}

type RtpLayer struct {
	Header rtp.RtpHeader
	body   []byte
}

// LayerType함수. gopacket.Layer interface의 implementation. 패킷의 LayerType을 반환
func (l RtpLayer) LayerType() gopacket.LayerType {
	return RtpLayerType
}

// LayerType함수. gopacket.Layer interface의 implementation. 패킷의 전체 byte 데이터를 반환.
func (l RtpLayer) LayerContents() []byte {
	return l.body
}

// LayerPayload함수. gopacket.Layer interface의 implementation. 패킷 payload byte 데이터를 반환.
func (l RtpLayer) LayerPayload() []byte {
	return nil
}

func (l RtpLayer) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// decodeRtp 함수. rtp 데이터인지를 판별한다.
func decodeRtp(data []byte, p gopacket.PacketBuilder) error {
	res := parseRtp(data)
	if nil == res {
		return errors.New("no rtp packet")
	}

	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(res)

	// todo : optionize for debug
	// if nil != res.trailer && len(res.trailer) > 0 {
	// 	fmt.Println("")
	// }
	return p.NextDecoder(res.NextLayerType())
}

func parseRtp(data []byte) *RtpLayer {
	if len(data) < 4 {
		return nil
	}

	var pkt rtp.RtpPacket
	_, err := pkt.Unmarshal(data)
	if nil != err {
		return nil
	}

	ret := &RtpLayer{
		Header: pkt.Header,
	}

	return ret
}
