// package rtsplayer is RTSP parser layer for gopacket
package rtsplayer

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type RequestMethodType int

// definitions of RTSP request method types
const RequestMethodType_Unknown = -1

const (
	RequestMethodType_Describe = 0 + iota
	RequestMethodType_Announce
	RequestMethodType_GetParameter
	RequestMethodType_Options
	RequestMethodType_Pause
	RequestMethodType_Play
	RequestMethodType_Record
	RequestMethodType_Redirect
	RequestMethodType_Setup
	RequestMethodType_SetParameter
	RequestMethodType_Teardown
)

// definitions of RTSP request method types
const (
	RequestMethod_Describe     = "DESCRIBE"
	RequestMethod_Announce     = "ANNOUNCE"
	RequestMethod_GetParameter = "GET_PARAMETER"
	RequestMethod_Options      = "OPTIONS"
	RequestMethod_Pause        = "PAUSE"
	RequestMethod_Play         = "PLAY"
	RequestMethod_Record       = "RECORD"
	RequestMethod_Redirect     = "REDIRECT"
	RequestMethod_Setup        = "SETUP"
	RequestMethod_SetParameter = "SET_PARAMETER"
	RequestMethod_Teardown     = "TEARDOWN"
)

var (
	// definitions of RTSP request method types
	methods = []string{
		RequestMethod_Describe,
		RequestMethod_Announce,
		RequestMethod_GetParameter,
		RequestMethod_Options,
		RequestMethod_Pause,
		RequestMethod_Play,
		RequestMethod_Record,
		RequestMethod_Redirect,
		RequestMethod_Setup,
		RequestMethod_SetParameter,
		RequestMethod_Teardown,
	}
)

// RtspRequestLayerType RTSP Request를 분석하기 위한 레이어 구조체를 정의.
var RtspRequestLayerType gopacket.LayerType

func init() {
	RtspRequestLayerType = gopacket.RegisterLayerType(
		util.LayerType_RtspRequest,
		gopacket.LayerTypeMetadata{
			Name:    "RTSPRequest",
			Decoder: gopacket.DecodeFunc(decodeRtspRequest),
		},
	)
}

func getMethodType(method string) RequestMethodType {
	for idx, m := range methods {
		if method == m {
			return RequestMethodType(idx)
		}
	}

	return RequestMethodType_Unknown
}

// GetMethodTypeText retrieve supported method type text of method type
func GetMethodTypeText(t RequestMethodType) string {
	if int(t) >= 0 && int(t) <= len(methods)-1 {
		return methods[t]
	}

	return ""
}

// RTSP request parser layer
type RtspRequestLayer struct {
	Method   string            // OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
	Uri      string            // RTSP uri
	Version  string            // RTSP version
	CSeq     int               // CSeq
	Messages map[string]string // RTSP packet general messages
	rtspBody []byte
}

// NewRtspRequestPacket function. RTSP request 에 해당하는 패킷인지 판별하여 패킷을 생성한다.
func NewRtspRequestPacket(data []byte) gopacket.Packet {
	return gopacket.NewPacket(
		data,
		RtspRequestLayerType,
		gopacket.Default,
	)
}

// ProbeRequest returns
func ProbeRequest(packet *gopacket.Packet, ethPacket *layers.Ethernet, ipLayer *gopacket.Layer, contexts *RtspContextMap) error {
	if nil == ipLayer {
		return errors.New("input packet is nil")
	}

	ipPacket, _ := (*ipLayer).(*layers.IPv4)
	if (ipPacket.Protocol & layers.IPProtocolTCP) != layers.IPProtocolTCP {
		return errors.New("no ipv4 packet")
	}

	clientIp := ipPacket.SrcIP.String()
	serverIp := ipPacket.DstIP.String()

	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
	if nil == tcpLayer {
		return errors.New("no tcp packet")
	}

	tcpPacket, ok := tcpLayer.(*layers.TCP)
	if !ok || nil == tcpPacket {
		return errors.New("no tcp packet")
	}

	payload := tcpPacket.LayerPayload()
	if nil == payload || len(payload) < 1 {
		return errors.New("has no payload")
	}

	reqPacket := NewRtspRequestPacket(payload)
	if nil == reqPacket {
		return errors.New("no rtsp request packet")
	}

	rtspRequestLayer := reqPacket.Layer(util.LayerType_RtspRequest)
	if nil == rtspRequestLayer {
		return errors.New("no rtsp request layer")
	}

	req, ok := rtspRequestLayer.(*RtspRequestLayer)
	if !ok {
		return errors.New("no rtsp request layer")
	}

	clientPort := tcpPacket.SrcPort.String()
	serverPort := tcpPacket.DstPort.String()
	mapid := getRtspContextId(serverIp, serverPort, clientIp, clientPort)
	clientAddress := getAddress(clientIp, clientPort)
	serverAddress := getAddress(serverIp, serverPort)

	switch req.Method {
	case "OPTIONS":
		timestamp := (*packet).Metadata().CaptureInfo.Timestamp
		probeOptions(mapid, serverAddress, clientAddress, req, timestamp, contexts)
	case "DESCRIBE":
		probeDescribe(mapid, req, contexts)
	case "SETUP":
		// probeSetup(srcIp, srcPort, dstIp, dstPort)
	}

	if context, ok := (*contexts)[mapid]; ok {
		context.lastReqMethod = getMethodType(req.Method)
		context.lastReqCSeq = req.CSeq
	}

	return nil
}

// probeOptions function. probe 중 "OPTIONS" request에 대한 요청 처리. 신규 scenario가 생성될 수 있다.
func probeOptions(mapId, serverAddress, clientAddress string, req *RtspRequestLayer, timestamp time.Time, contexts *RtspContextMap) error {
	_, ok := (*contexts)[mapId]

	u, _ := url.Parse(req.Uri)

	if !ok {
		(*contexts)[mapId] = &RtspContext{
			ClientAddress:       clientAddress,
			ServerAddress:       serverAddress,
			Url:                 req.Uri,
			Path:                u.Path,
			firstRtspPacketTime: timestamp,
		}
		if val := req.GetMessageValueByType(MsgFieldType_UserAgent); len(val) > 0 {
			(*contexts)[mapId].UserAgent = val
		}
		return nil
	} else {
		return errors.New("OPTIONS already received")
	}
}

// probeDescribe function
func probeDescribe(mapId string, req *RtspRequestLayer, contexts *RtspContextMap) error {
	if context, ok := (*contexts)[mapId]; ok {
		if val := req.GetMessageValueByType(MsgFieldType_Authorization); len(val) > 0 {
			auth, err := parseAuthorization(val)
			if nil != err {
				return err
			}
			context.Auth = &auth
		}
		if val := req.GetMessageValueByType(MsgFieldType_Accept); len(val) > 0 {
			context.Accept = val
		}
	} else {
		return errors.New("OPTIONS not processed")
	}
	return nil
}

// LayerType function implements gopacket.Layer.LayerType() interface function
func (l RtspRequestLayer) LayerType() gopacket.LayerType {
	return RtspRequestLayerType
}

// LayerContents function implements gopacket.Layer.LayerContents() interface function
func (l RtspRequestLayer) LayerContents() []byte {
	return l.rtspBody
}

// LayerPayload function implements gopacket.Layer.LayerPayload() interface function
func (l RtspRequestLayer) LayerPayload() []byte {
	return l.rtspBody
}

// RestOfData function implements gopacket.Layer.RestOfData() interface function
func (l RtspRequestLayer) RestOfData() []byte {
	return nil
}

// RestOfData function retrieves message value of specific message type
func (l RtspRequestLayer) GetMessageValueByType(msgType int) string {
	for k := range l.Messages {
		if msgType > UnknownType && GetMessageFieldType(k) == msgType {
			return l.Messages[k]
		}
	}

	return ""
}

// decodeRtspRequest function check is lower layer's payload is RTSP request or not.
func decodeRtspRequest(data []byte, p gopacket.PacketBuilder) error {
	req := ParseRequest(data)
	if nil == req {
		return errors.New("no rtsp request")
	}

	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(req)

	return p.NextDecoder(gopacket.LayerTypePayload)
}

func ParseRequestInfo(s string) (method, uri, version string, err error) {
	reqs := strings.Split(s, " ")
	if len(reqs) < 3 {
		err = errors.New("invalid request")
		return
	}

	switch reqs[0] {
	case "OPTIONS":
		fallthrough
	case "DESCRIBE":
		fallthrough
	case "SETUP":
		fallthrough
	case "PLAY":
		fallthrough
	case "PAUSE":
		fallthrough
	case "TEARDOWN":
		method = reqs[0]
	default:
		err = errors.New("invalid request method " + method)
		return
	}

	uri = reqs[1]
	version = reqs[2]

	return
}

// ParseRequest function check is lower layer's payload is RTSP request or not.
func ParseRequest(data []byte) (req *RtspRequestLayer) {
	var method string
	indices := util.SplitByteIndices(data, "\r\n\r\n")

	if len(indices) < 1 {
		return nil
	}

	body := data[:indices[0]]
	bodyStr := string(body)

	lines := strings.Split(bodyStr, "\r\n")
	if len(lines) < 1 {
		return nil
	}

	method, uri, version, err := ParseRequestInfo(lines[0])
	if nil != err {
		return
	}

	request := RtspRequestLayer{
		Method:   method,
		Uri:      uri,
		Version:  version,
		Messages: make(map[string]string),
		rtspBody: body,
	}

	for idx, line := range lines {
		if idx == 0 {
			continue
		}
		if k, v, e := parseMessage(line); nil != e {
			continue
		} else {
			switch GetMessageFieldType(k) {
			case MsgFieldType_CSeq:
				request.CSeq, _ = strconv.Atoi(v)
			}
			request.Messages[strings.ToLower(k)] = v
		}
	}

	return &request
}
