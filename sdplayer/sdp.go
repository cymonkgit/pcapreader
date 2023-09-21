package sdplayer

import (
	"errors"
	"strconv"
	"strings"

	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
)

// LayerType_Sdp

// RtspRequestLayerType RTSP Request를 분석하기 위한 레이어 구조체를 정의.
var SdpLayerType gopacket.LayerType

func init() {
	SdpLayerType = gopacket.RegisterLayerType(
		util.LayerType_Sdp,
		gopacket.LayerTypeMetadata{
			Name:    "Session Description",
			Decoder: gopacket.DecodeFunc(decodeSdp),
		},
	)
}

// SDP request parser layer
type SessionLayer struct {
	SessionName string
	Version     int
	Email       string
	ConnInfo    ConnectionInfo
	ActiveTime  string
	Attributes  []string
	MediaInfos  []MediaDesc
	body        []byte
}

// SDP connection information
type ConnectionInfo struct {
	NetworkType string
	AddressType string
	Address     string
}

type MediaDesc struct {
	Type       string
	Port       string
	Protocol   string
	Formats    []string
	Attributes []string
}

func (ci *ConnectionInfo) parse(str string) {
	strs := strings.Split(str, " ")
	if len(strs) != 3 {
		return
	}
	ci.NetworkType = strs[0]
	ci.AddressType = strs[1]
	ci.Address = strs[2]
}

// LayerType function implements gopacket.Layer.LayerType() interface function
func (l SessionLayer) LayerType() gopacket.LayerType {
	return util.LayerType_Sdp
}

// LayerContents function implements gopacket.Layer.LayerContents() interface function
func (l SessionLayer) LayerContents() []byte {
	return l.body
}

// LayerPayload function implements gopacket.Layer.LayerPayload() interface function
func (l SessionLayer) LayerPayload() []byte {
	return l.body
}

// RestOfData function implements gopacket.Layer.RestOfData() interface function
func (l SessionLayer) RestOfData() []byte {
	return nil
}

func (s *SessionLayer) parseSessionAttribute(key, value string) {
	if key == "m" && len(s.MediaInfos) >= 1 {
		s.parseMediaDescription(key, value)
		return
	}

	switch key {
	case "m":
		if nil == s.MediaInfos {
			s.MediaInfos = make([]MediaDesc, 0)
		}
		strs := strings.Split(value, " ")
		if len(strs) < 4 {
			return
		}

		formats := strs[3:]

		s.MediaInfos = append(s.MediaInfos, MediaDesc{
			Type:     strs[0],
			Port:     strs[1],
			Protocol: strs[2],
			Formats:  formats,
		})
	case "s": // session name
		s.SessionName = value
	case "v": // sdp protocol version
		s.Version, _ = strconv.Atoi(value)
	case "e": // email
		s.Email = value
	case "c": // connection information
		s.ConnInfo.parse(value)
	case "t": // time description
		s.ActiveTime = value
	case "b": // bandwidth
	case "a": // attribute
		if nil == s.Attributes {
			s.Attributes = make([]string, 0)
		}

		s.Attributes = append(s.Attributes, value)
	}
}

func (s *SessionLayer) parseMediaDescription(key, value string) {
	switch key {
	case "b": // bandwidth
	case "a":
		if nil != s.MediaInfos {
			mi := &s.MediaInfos[len(s.MediaInfos)-1]
			if nil == mi.Attributes {
				mi.Attributes = make([]string, 0)
			}
			mi.Attributes = append(mi.Attributes, value)
		}
	}
}

// NewRtspRequestPacket function. RTSP request 에 해당하는 패킷인지 판별하여 패킷을 생성한다.
func NewSdpPacket(data []byte) gopacket.Packet {
	return gopacket.NewPacket(
		data,
		SdpLayerType,
		gopacket.Default,
	)
}

/*
sdp example
0000   73 3d 4d 65 64 69 61 20 50 72 65 73 65 6e 74 61   s=Media Presenta
0010   74 69 6f 6e 0d 0a 76 3d 30 0d 0a 65 3d 4e 4f 4e   tion..v=0..e=NON
0020   45 0d 0a 63 3d 49 4e 20 49 50 34 20 30 2e 30 2e   E..c=IN IP4 0.0.
0030   30 2e 30 0d 0a 74 3d 30 20 30 0d 0a 61 3d 73 64   0.0..t=0 0..a=sd
0040   70 6c 61 6e 67 3a 65 6e 0d 0a 61 3d 63 6f 6e 74   plang:en..a=cont
0050   72 6f 6c 3a 2a 0d 0a 61 3d 72 61 6e 67 65 3a 6e   rol:*..a=range:n
0060   70 74 3d 6e 6f 77 2d 0d 0a 6d 3d 76 69 64 65 6f   pt=now-..m=video
0070   20 30 20 52 54 50 2f 41 56 50 20 39 36 0d 0a 61    0 RTP/AVP 96..a
0080   3d 66 72 61 6d 72 61 74 65 3a 32 39 0d 0a 61 3d   =framrate:29..a=
0090   72 74 70 6d 61 70 3a 39 36 20 48 32 36 35 2f 39   rtpmap:96 H265/9
00a0   30 30 30 30 0d 0a 61 3d 66 6d 74 70 3a 39 36 20   0000..a=fmtp:96
00b0   70 72 6f 66 69 6c 65 2d 73 70 61 63 65 3d 30 3b   profile-space=0;
00c0   70 72 6f 66 69 6c 65 2d 69 64 3d 31 3b 74 69 65   profile-id=1;tie
00d0   72 2d 66 6c 61 67 3d 30 3b 6c 65 76 65 6c 2d 69   r-flag=0;level-i
00e0   64 3d 31 35 33 3b 73 70 72 6f 70 2d 76 70 73 3d   d=153;sprop-vps=
00f0   51 41 45 4d 41 66 2f 2f 41 57 41 41 41 41 4d 41   QAEMAf//AWAAAAMA
0100   41 41 4d 41 41 41 4d 41 41 41 4d 41 6d 53 77 4a   AAMAAAMAAAMAmSwJ
0110   3b 73 70 72 6f 70 2d 73 70 73 3d 51 67 45 42 41   ;sprop-sps=QgEBA
0120   57 41 41 41 41 4d 41 41 41 4d 41 41 41 4d 41 41   WAAAAMAAAMAAAMAA
0130   41 4d 41 6d 61 41 44 77 49 41 52 42 38 75 69 30   AMAmaADwIARB8ui0
0140   6b 38 45 75 79 41 3d 3b 73 70 72 6f 70 2d 70 70   k8EuyA=;sprop-pp
0150   73 3d 52 41 48 42 59 55 4d 61 4e 41 37 47 51 41   s=RAHBYUMaNA7GQA
0160   3d 3d 0d 0a 61 3d 63 6c 69 70 72 65 63 74 3a 30   ==..a=cliprect:0
0170   2c 30 2c 31 30 38 30 2c 31 39 32 30 0d 0a 61 3d   ,0,1080,1920..a=
0180   66 72 61 6d 65 73 69 7a 65 3a 39 36 20 31 39 32   framesize:96 192
0190   30 2d 31 30 38 30 0d 0a 61 3d 63 6f 6e 74 72 6f   0-1080..a=contro
01a0   6c 3a 74 72 61 63 6b 49 44 3d 31 0d 0a 6d 3d 61   l:trackID=1..m=a
01b0   70 70 6c 69 63 61 74 69 6f 6e 20 30 20 52 54 50   pplication 0 RTP
01c0   2f 41 56 50 20 30 0d 0a 62 3d 41 53 3a 31 0d 0a   /AVP 0..b=AS:1..
01d0   61 3d 63 6f 6e 74 72 6f 6c 3a 74 72 61 63 6b 49   a=control:trackI
01e0   44 3d 32 0d 0a                                    D=2..
*/

// decodeRtspRequest function check is lower layer's payload is RTSP request or not.
func decodeSdp(data []byte, p gopacket.PacketBuilder) error {
	req := parseSdp(data)
	if nil == req {
		return errors.New("not rtsp request")
	}

	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(req)

	return p.NextDecoder(gopacket.LayerTypePayload)
}

func parseSdp(data []byte) (sdp *SessionLayer) {
	str := string(data)
	lines := strings.Split(str, "\r\n")
	if len(lines) < 1 {
		return
	}

	sdp = &SessionLayer{}

	for _, line := range lines {
		key, value, err := util.GetKeyAndValue(line)
		if len(key) < 1 || len(value) < 1 {
			continue
		}
		if nil != err {
			return nil
		}

		sdp.parseSessionAttribute(key, value)
	}

	if len(sdp.Attributes) < 1 {
		return nil
	}

	sdp.body = data

	return
}

func IsSDP() {

}
