package rtsplayer

import (
	"errors"
	"strconv"
	"strings"

	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// RtspResponseLayerType RTSP Response를 분석하기 위한 레이어 구조체를 정의.
var RtspResponseLayerType gopacket.LayerType

func init() {
	RtspResponseLayerType = gopacket.RegisterLayerType(
		util.LayerType_RtspResponse,
		gopacket.LayerTypeMetadata{
			Name:    "RTSPResponse",
			Decoder: gopacket.DecodeFunc(decodeRtspResponse),
		},
	)
}

type RtspResponseLayer struct {
	CSeq     int               // CSeq
	Version  string            // RTSP Version
	Status   int               // RTSP return status
	Reason   string            // RTSP response msg
	Messages map[string]string // return options
	body     []byte
	trailer  []byte // case SDP 등 처리
}

// NewRtspResponsePacket function. RTSP Response 에 해당하는 패킷인지 판별하여 패킷을 생성한다.
// RTSP Response packet이 아닌 경우 nil을 반환한다.
func NewRtspResponsePacket(data []byte) gopacket.Packet {
	return gopacket.NewPacket(
		data,
		RtspResponseLayerType,
		gopacket.Default,
	)
}

func ProbeResponse(packet *gopacket.Packet, ethPacket *layers.Ethernet, ipLayer *gopacket.Layer, contexts *RtspContextMap) error {
	if nil == ipLayer {
		return errors.New("input packet is nil")
	}

	ipPacket, _ := (*ipLayer).(*layers.IPv4)
	if (ipPacket.Protocol & layers.IPProtocolTCP) != layers.IPProtocolTCP {
		return errors.New("not ipv4 packet")
	}

	serverIp := ipPacket.SrcIP.String()
	clientIp := ipPacket.DstIP.String()

	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
	if nil == tcpLayer {
		return errors.New("not tcp packet")
	}

	tcpPacket, ok := tcpLayer.(*layers.TCP)
	if !ok || nil == tcpPacket {
		return errors.New("not tcp packet")
	}

	payload := tcpPacket.LayerPayload()
	if nil == payload || len(payload) < 1 {
		return errors.New("has no payload")
	}

	resPacket := NewRtspResponsePacket(payload)
	if nil == resPacket {
		return errors.New("not rtsp response packet")
	}

	rtspResponseLayer := resPacket.Layer(util.LayerType_RtspResponse)
	if nil == rtspResponseLayer {
		return errors.New("not rtsp response layer")
	}

	res, ok := rtspResponseLayer.(*RtspResponseLayer)
	if !ok {
		return errors.New("not rtsp response layer")
	}

	serverPort := tcpPacket.SrcPort.String()
	clientPort := tcpPacket.DstPort.String()
	mapid := getRtspContextId(serverIp, serverPort, clientIp, clientPort)

	var context *RtspContext
	if context, ok = (*contexts)[mapid]; !ok {
		return errors.New("rtsp context doesn't exists")
	}

	if context.lastReqCSeq != res.CSeq {
		return errors.New("invalid CSeq")
	}

	for fieldName := range res.Messages {
		switch fieldName {
		case MsgField_Public:
			val := res.Messages[fieldName]
			context.SupportedMethod = getPublics(val)
		}
	}

	if context.lastReqMethod == RequestMethodType_Describe && nil != context.Auth {
		context.Auth.Authorized = res.Status >= 200 && res.Status < 300
	}

	return nil
}

// LayerType함수. gopacket.Layer interface의 implementation. 패킷의 LayerType을 반환
func (l RtspResponseLayer) LayerType() gopacket.LayerType {
	return RtspResponseLayerType
}

// LayerType함수. gopacket.Layer interface의 implementation. 패킷의 전체 byte 데이터를 반환.
func (l RtspResponseLayer) LayerContents() []byte {
	return append(l.body, l.trailer...)
}

// LayerPayload함수. gopacket.Layer interface의 implementation. 패킷 payload byte 데이터를 반환.
func (l RtspResponseLayer) LayerPayload() []byte {
	return l.body
}

// LayerPayload함수. gopacket.Layer interface의 implementation. 다음 레이어 분석을 위한 나머지 byte 데이터를 반환.
func (l RtspResponseLayer) RestOfData() []byte {
	return l.trailer
}

// decodeRtspRequest 함수. rtsp request 에 해당하는 데이터인지를 판별한다.
func decodeRtspResponse(data []byte, p gopacket.PacketBuilder) error {
	res := parseResponse(data)
	if nil == res {
		return errors.New("not rtsp request")
	}

	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(res)

	return p.NextDecoder(gopacket.LayerTypePayload)
}

func parseResponse(data []byte) *RtspResponseLayer {
	lines, lines2 := splitBytesToString(data)
	if len(lines) < 1 {
		return nil
	}

	if len(lines2) < 1 {

	}

	// first line : response
	strs := strings.Split(lines[0], " ")
	if len(strs) != 3 {
		return nil
	}

	code, err := strconv.Atoi(strs[1])
	if nil != err {
		return nil
	}

	res := RtspResponseLayer{
		Version: strs[0],
		Status:  code,
		Reason:  strs[2],
	}

	for idx, line := range lines {
		if idx == 0 {
			continue
		}
		if k, v, e := parseMessage(line); nil != e {
			continue
		} else {
			switch k {
			case MsgField_CSeq:
				res.CSeq, _ = strconv.Atoi(v)
			}
			if nil == res.Messages {
				res.Messages = make(map[string]string)
			}
			res.Messages[k] = v
		}
	}

	return &res
}

func getPublics(public string) []RequestMethodType {
	ret := make([]RequestMethodType, 0)
	methods := strings.Split(public, ",")
	for _, method := range methods {
		ret = append(ret, getMethodType(strings.Trim(method, " ")))
	}
	return ret
}
