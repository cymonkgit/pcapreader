package rtsplayer

import (
	"errors"

	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
)

var RtspInterleavedFrameType gopacket.LayerType

func init() {
	RtspResponseLayerType = gopacket.RegisterLayerType(
		util.LayerType_RtspInterleavedFrame,
		gopacket.LayerTypeMetadata{
			Name:    "RTSPItnerleavedFrame",
			Decoder: gopacket.DecodeFunc(decodeRtspInterleavedFrame),
		},
	)
}

type RtspInterleavedFrame struct {
	Magic   uint8
	Channel uint8
	Length  uint16
}

// decodeRtspInterleavedFrame 함수. rtsp interleaved frame 에 해당하는 데이터인지를 판별한다.
func decodeRtspInterleavedFrame(data []byte, p gopacket.PacketBuilder) error {
	res := parseResponse(data)
	if nil == res {
		return errors.New("not rtsp interleaved frame")
	}

	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(res)

	// todo : optionize for debug
	// if nil != res.trailer && len(res.trailer) > 0 {
	// 	fmt.Println("")
	// }
	return p.NextDecoder(res.NextLayerType())
}

func parseInterleavedFrame(data []byte) *RtspInterleavedFrame {
	if len(data) < 4 {
		return nil
	}

	r := RtspInterleavedFrame{
		Magic:   data[0],
		Channel: data[1],
		Length:  uint16(data[2])<<8 | uint16(data[3]),
	}

	return &r
}
