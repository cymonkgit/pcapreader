package rtplayer

import (
	"errors"

	"github.com/cymonkgit/pcapreader/rtspserver/rtp"
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
	rtp.RTPHeader
}

// decodeRtp 함수. rtp 데이터인지를 판별한다.
func decodeRtp(data []byte, p gopacket.PacketBuilder) error {
	res := parseResponse(data)
	if nil == res {
		return errors.New("not rtp packet")
	}

	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(res)

	// todo : optionize for debug
	// if nil != res.trailer && len(res.trailer) > 0 {
	// 	fmt.Println("")
	// }
	return p.NextDecoder(res.NextLayerType())
}

func parseResponse(data []byte) *RtpLayer {
	if len(data) < 4 {
		return nil
	}

	var pkt rtp.RtpPacket
	_, err := pkt.Unmarshal(data)
	if nil != err {
		return nil
	}
}
