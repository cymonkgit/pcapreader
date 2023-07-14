package rtsplayer

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cymonkgit/pcapreader/sdplayer"
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
		case MsgField_Session:
			val := res.Messages[fieldName]
			if sessionId, timeoutSec, err := getSession(val); nil != err {
				if nil != err {
					// todo : log error here
					continue
				}
			} else {
				context.SessionId, _ = strconv.Atoi(sessionId)
				context.SessionTimeoutSec, _ = strconv.Atoi(timeoutSec)
			}
		case MsgField_Transport:
			val := res.Messages[fieldName]
			if _, _, lowerTransport, unicast, parameters, err := getTrasportOption(val); nil != err {
				// todo : log error here
				continue
			} else {
				if lowerTransport == "" || lowerTransport == "UDP" {
					context.Protocol = TransferProtocol_UDP
				} else if lowerTransport == "TCP" {
					context.Protocol = TransferProtocol_TCP
				}
				context.Unicast = unicast
				if v, ok := parameters["client_port"]; ok {
					context.CilenttPort = v
				}
				if v, ok := parameters["server_port"]; ok {
					context.ServerPort = v
				}
				if v, ok := parameters["SSRC"]; ok {
					context.SSRC = v
				}
			}
		}
	}

	if context.lastReqMethod == RequestMethodType_Describe && nil != context.Auth {
		context.Auth.Authorized = res.Status >= 200 && res.Status < 300
		if context.Auth.Authorized {
			fmt.Println("Authorized")
		}
	}

	sdpLayer := resPacket.Layer(util.LayerType_Sdp)
	if nil != sdpLayer {
		if sdp, ok := sdpLayer.(*sdplayer.SessionLayer); ok {
			context.SDP = sdp.LayerContents()
		}
	}

	return nil
}

func (l RtspResponseLayer) GetMessageValue(_key string) string {
	key := strings.ToLower(_key)
	if nil == l.Messages {
		return ""
	}

	if val, ok := l.Messages[key]; ok {
		return val
	}
	return ""
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
	return l.trailer
}

func (l RtspResponseLayer) NextLayerType() gopacket.LayerType {
	if len(l.trailer) > 0 {
		if l.GetMessageValue(MsgField_ContentType) == "application/sdp" {
			return sdplayer.SdpLayerType
		}
	}

	return gopacket.LayerTypePayload
}

// decodeRtspRequest 함수. rtsp request 에 해당하는 데이터인지를 판별한다.
func decodeRtspResponse(data []byte, p gopacket.PacketBuilder) error {
	res := parseResponse(data)
	if nil == res {
		return errors.New("not rtsp request")
	}

	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(res)

	// todo : optionize for debug
	// if nil != res.trailer && len(res.trailer) > 0 {
	// 	fmt.Println("")
	// }
	return p.NextDecoder(res.NextLayerType())
}

func parseResponse(data []byte) *RtspResponseLayer {
	indices := util.SplitByteIndices(data, "\r\n\r\n")

	if len(indices) < 1 {
		return nil
	}

	var body, trailer []byte
	body = data[:indices[0]]
	if len(indices) >= 2 {
		trailer = data[indices[0]+4 : indices[1]]
	} else { // if len(data)+4 < len(data) {
		trailer = data[indices[0]+4:]
	}

	bodyStr := string(body)

	lines := strings.Split(bodyStr, "\r\n")
	if len(lines) < 1 {
		return nil
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
		body:    body,
		trailer: trailer,
	}

	for idx, line := range lines {
		if idx == 0 {
			continue
		}
		if k, v, e := parseMessage(line); nil != e {
			continue
		} else {
			switch strings.ToLower(k) {
			case MsgField_CSeq:
				res.CSeq, _ = strconv.Atoi(v)
			}
			if nil == res.Messages {
				res.Messages = make(map[string]string)
			}
			res.Messages[strings.ToLower(k)] = v
		}
	}

	return &res
}

// getPublics retrieve public supported methods of server from Message with 'Public'
func getPublics(public string) []RequestMethodType {
	ret := make([]RequestMethodType, 0)
	methods := strings.Split(public, ",")
	for _, method := range methods {
		ret = append(ret, getMethodType(strings.Trim(method, " ")))
	}
	return ret
}

func getSession(session string) (sessionId, timeoutSec string, err error) {
	strs := strings.Split(session, ";")
	if len(strs) < 1 {
		err = errors.New("invalid session values")
		return
	}
	sessionId = strings.Trim(strs[0], " ")
	if len(strs) > 1 {
		k, v, e := util.GetKeyAndValue(strings.Trim(strs[1], " "))
		if nil != e {
			err = e
			return
		}
		if k != "timeout" {
			err = errors.New("invalid session values")
			return
		}
		timeoutSec = v
	}

	return
}

// getTrasportOption retrieve trasport options from 'Transport' message
func getTrasportOption(transport string) (protocol, profile, lowerTransport string, unicast bool, parameters map[string]string, err error) {
	// Transport: RTP/AVP;unicast;destination=172.168.11.33;source=172.168.11.148;client_port=49276-49277;server_port=13068-13069;ssrc=6EFF3234;mode="PLAY"
	strs := strings.Split(transport, ";")
	if len(strs) < 2 {
		err = errors.New("invalid transport values")
		return
	}
	spec := strings.Split(strings.Trim(strs[0], " "), "/")
	if len(spec) < 2 {
		err = errors.New("invalid transport values")
		return
	}
	protocol = spec[0]
	profile = spec[1]
	if len(spec) > 2 {
		lowerTransport = spec[2]
	}

	if strs[1] == "unicast" {
		unicast = true
	} else {
		unicast = false
	}

	parameters = make(map[string]string)
	for _, kv := range strs[2:] {
		k, v, e := util.GetKeyAndValue(strings.Trim(kv, " "))
		if nil != e {
			err = e
			return
		}
		parameters[k] = v
	}

	return
}

type KeyAndVlue struct {
	Key   string
	Value string
}

type ResponseData struct {
	StatusCode int
	CSeq       int
	Messages   []KeyAndVlue
}

// BuildResponse make RTSP response packet data payload with status code, CSeq and rest of messages (key: value)
func BuildResponse(res ResponseData) ([]byte, error) {
	msg := GetRtspStatusMsg(res.StatusCode)
	if len(msg) < 1 {
		return nil, errors.New("invalid status code")
	}

	lines := make([]string, 0)
	// response status
	lines = append(lines, fmt.Sprintf("%v %v %v", "RTSP/1.0", strconv.Itoa(res.StatusCode), msg))
	lines = append(lines, fmt.Sprintf("CSeq: %v", res.CSeq))

	if nil != res.Messages {
		for _, knv := range res.Messages {
			lines = append(lines, fmt.Sprintf("%v: %v", knv.Key, knv.Value))
		}
	}

	return buildTextProtoPacket(lines), nil
}
