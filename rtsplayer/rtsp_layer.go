package rtsplayer

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cymonkgit/pcapreader/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// RTP 전송 타입
type TransferType int

const (
	TransferProtocol_UDP = iota
	TransferProtocol_TCP
)

const (
	Continue                      = 100
	OK                            = 200
	Created                       = 201
	LowOnStorageSpace             = 250
	MultipleChoices               = 300
	MovedPermanently              = 301
	MovedTemporarily              = 302
	SeeOther                      = 303
	UseProxy                      = 305
	BadRequest                    = 400
	Unauthorized                  = 401
	PaymentRequired               = 402
	Forbidden                     = 403
	NotFound                      = 404
	MethodNotAllowed              = 405
	NotAcceptable                 = 406
	ProxyAuthenticationRequired   = 407
	RequestTimeout                = 408
	Gone                          = 410
	LengthRequired                = 411
	PreconditionFailed            = 412
	RequestEntityTooLarge         = 413
	RequestURITooLong             = 414
	UnsupportedMediaType          = 415
	Invalidparameter              = 451
	IllegalConferenceIdentifier   = 452
	NotEnoughBandwidth            = 453
	SessionNotFound               = 454
	MethodNotValidInThisState     = 455
	HeaderFieldNotValid           = 456
	InvalidRange                  = 457
	ParameterIsReadOnly           = 458
	AggregateOperationNotAllowed  = 459
	OnlyAggregateOperationAllowed = 460
	UnsupportedTransport          = 461
	DestinationUnreachable        = 462
	InternalServerError           = 500
	NotImplemented                = 501
	BadGateway                    = 502
	ServiceUnavailable            = 503
	GatewayTimeout                = 504
	RTSPVersionNotSupported       = 505
	OptionNotsupport              = 551
)

var (
	rtspStatus map[int]string = map[int]string{
		Continue:                      "Continue",
		OK:                            "OK",
		Created:                       "Created",
		LowOnStorageSpace:             "LowOnStorageSpace",
		MultipleChoices:               "MultipleChoices",
		MovedPermanently:              "MovedPermanently",
		MovedTemporarily:              "MovedTemporarily",
		SeeOther:                      "SeeOther",
		UseProxy:                      "UseProxy",
		BadRequest:                    "BadRequest",
		Unauthorized:                  "Unauthorized",
		PaymentRequired:               "PaymentRequired",
		Forbidden:                     "Forbidden",
		NotFound:                      "NotFound",
		MethodNotAllowed:              "MethodNotAllowed",
		NotAcceptable:                 "NotAcceptable",
		ProxyAuthenticationRequired:   "ProxyAuthenticationRequired",
		RequestTimeout:                "RequestTimeout",
		Gone:                          "Gone",
		LengthRequired:                "LengthRequired",
		PreconditionFailed:            "PreconditionFailed",
		RequestEntityTooLarge:         "RequestEntityTooLarge",
		RequestURITooLong:             "RequestURITooLong",
		UnsupportedMediaType:          "UnsupportedMediaType",
		Invalidparameter:              "Invalidparameter",
		IllegalConferenceIdentifier:   "IllegalConferenceIdentifier",
		NotEnoughBandwidth:            "NotEnoughBandwidth",
		SessionNotFound:               "SessionNotFound",
		MethodNotValidInThisState:     "MethodNotValidInThisState",
		HeaderFieldNotValid:           "HeaderFieldNotValid",
		InvalidRange:                  "InvalidRange",
		ParameterIsReadOnly:           "ParameterIsReadOnly",
		AggregateOperationNotAllowed:  "AggregateOperationNotAllowed",
		OnlyAggregateOperationAllowed: "OnlyAggregateOperationAllowed",
		UnsupportedTransport:          "UnsupportedTransport",
		DestinationUnreachable:        "DestinationUnreachable",
		InternalServerError:           "InternalServerError",
		NotImplemented:                "NotImplemented",
		BadGateway:                    "BadGateway",
		ServiceUnavailable:            "ServiceUnavailable",
		GatewayTimeout:                "GatewayTimeout",
		RTSPVersionNotSupported:       "RTSPVersionNotSupported",
		OptionNotsupport:              "OptionNotsupport",
	}
)

func GetRtspStatusMsg(statusCode int) string {
	if msg, ok := rtspStatus[statusCode]; ok {
		return msg
	} else {
		return ""
	}
}

func GetRtspStatusCode(msg string) int {
	for code := range rtspStatus {
		if _msg, ok := rtspStatus[code]; ok && _msg == msg {
			return code
		}
	}

	return -1
}

type DigestAuthorization struct {
	User     string
	Realm    string
	Nonce    string
	Uri      string
	Response string
}

// Check functions authorize disgest authority of request auth values
func (da *DigestAuthorization) Check(auth string) bool {
	if a, err := parseAuthorization(auth); nil != err {
		return false
	} else {
		return reflect.DeepEqual(*da, a)
	}
}

// WWW-Authenticate: Digest realm="RealHUB Streaming Server", nonce="c6bcddac12782de4b0b1f357e3932f37"\r\n
func (da *DigestAuthorization) GetAuthResponseVaue() string {
	return fmt.Sprintf("Digest realm=\"%v\", nonce=\"%v\"", da.Realm, da.Nonce)
}

// parseAuthorization parse authorization from request messages
func parseAuthorization(auth string) (digest DigestAuthorization, err error) {
	_auth := strings.Trim(auth, " ")
	index := strings.Index(_auth, " ")
	if index < 0 || index >= len(_auth) {
		err = errors.New("failed to get authorization type")
		return
	}

	authType := _auth[:index]
	if authType != "Digest" {
		err = errors.New("unsupported authorization type")
		return
	}
	_auth = _auth[index+1:]

	if kvset, er := util.GetKeyAndValueSet(_auth); nil != er {
		err = er
		return
	} else {
		for key := range kvset {
			switch key {
			case "username":
				digest.User = strings.Trim(kvset[key], "\"")
			case "realm":
				digest.Realm = strings.Trim(kvset[key], "\"")
			case "nonce":
				digest.Nonce = strings.Trim(kvset[key], "\"")
			case "uri":
				digest.Uri = strings.Trim(kvset[key], "\"")
			case "response":
				digest.Response = strings.Trim(kvset[key], "\"")
			}
		}
	}

	return
}

// RtspContext is context of 1 RTSP client-server communication
type RtspContext struct {
	ClientAddress     string               // from ethernet/ip packet layer
	ServerAddress     string               // from ethernet/ip packet layer
	Url               string               // from OPTIONS
	Path              string               // from Url
	UserAgent         string               // from OPTIONS, DESCRIBE ...
	SupportedMethod   []RequestMethodType  // from OPTIONS
	Auth              *DigestAuthorization // from DESCRIBE
	Authorized        bool                 // from Auth
	Accept            string               // from DESCRIBE
	Protocol          TransferType         // from SETUP
	Unicast           bool                 // from SETUP
	SessionId         int                  // from SETUP request
	SessionTimeoutSec int                  // from SETUP request
	ServerPort        string               // from SETUP request
	CilentPort        string               // from SETUP request
	SSRC              string               // SSID. from SETUP reply
	SDP               []byte               // SDP, from DESCRIBE response

	// additional info for RTP-Info
	UseRtpInfo bool
	RtpUrl     string
	RtpSeq     int
	RtpTime    int

	//  user options
	SkipAuthorization bool

	// internal
	lastReqMethod        RequestMethodType
	lastReqCSeq          int
	firstRtspPacketIndex int
	playRequestDone      bool
	serverHost           string
	serverPorts          []int
	clientHost           string
	clientPorts          []int
}

type RtspContextMap map[string]*RtspContext

func (c *RtspContext) GetBPFFilter() (filter string, err error) {
	// TCP
	if c.Protocol == TransferProtocol_TCP {
		// e.g "(src host 172.168.11.148 && src port 554) || (dst host 172.168.11.148 && dst port 554)"
		ip, port, er := GetIpPort(c.ServerAddress)
		if nil != er {
			err = er
			return
		}
		filter = fmt.Sprintf("(tcp && src host %v && src port %v) || (tcp && dst host %v && dst port %v)", ip, port, ip, port)
		return
	} else if c.Protocol == TransferProtocol_UDP {
		serverIp, rtspPort, er := GetIpPort(c.ServerAddress)
		if nil != er {
			err = er
			return
		}
		clientIp, _, er := GetIpPort(c.ClientAddress)
		if nil != er {
			err = er
			return
		}
		clientPorts := strings.Split(c.CilentPort, "-")
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

func (c *RtspContext) String() string {
	getSupported := func(SupportedMethod []RequestMethodType) (support string) {
		for i, method := range SupportedMethod {
			if i != 0 {
				support += ", "
			}
			support += GetMethodTypeText(method)
		}
		return
	}
	var transfer string
	if c.Protocol == TransferProtocol_UDP {
		transfer = "(UDP)"
	} else {
		transfer = "(TCP)"
	}
	strs := []string{
		fmt.Sprintln("client address:", c.ClientAddress),
		fmt.Sprintln("server address:", c.ServerAddress),
		fmt.Sprintln(""),
		fmt.Sprintln("url:", c.Url),
		fmt.Sprintln("Auth:", c.Auth, "authorized:", c.Authorized),
		fmt.Sprintln("user agent:", c.UserAgent),
		fmt.Sprintln("supported:", getSupported(c.SupportedMethod)),
		fmt.Sprintln("accept:", c.Accept),
		fmt.Sprintln("transfer type:", c.Protocol, transfer),
		fmt.Sprintln("session id:", c.SessionId),
		fmt.Sprintln("session timeout:", c.SessionTimeoutSec),
		fmt.Sprintln("ssrc:", c.SSRC),
	}
	if nil != c.Auth {
		strs = append(strs, fmt.Sprintf("authority: authorized(%v), username(%v), realm(%v) ...", c.Authorized, c.Auth.User, c.Auth.Realm))
	} else {
		strs = append(strs, fmt.Sprintln("authority: not use"))
	}

	return strings.Join(strs[:], "")
}

func (c *RtspContext) UpdatePlayTransportInfo() {
	switch c.Protocol {
	case TransferProtocol_TCP:
		if host, port, err := GetIpPort(c.ClientAddress); nil == err {
			portNum, _ := strconv.Atoi(port)
			c.clientHost = host
			c.clientPorts = []int{portNum}
		}
	case TransferProtocol_UDP:
		if host, _, err := GetIpPort(c.ClientAddress); nil == err {
			c.clientHost = host
			strs := strings.Split(c.CilentPort, "-")
			if len(strs) != 2 {
				return
			}
			start, _ := strconv.Atoi(strs[0])
			end, _ := strconv.Atoi(strs[1])
			c.clientPorts = []int{start, end}
		} else {
			fmt.Println(err)
		}
		if host, _, err := GetIpPort(c.ServerAddress); nil == err {
			c.serverHost = host
			strs := strings.Split(c.ServerPort, "-")
			if len(strs) != 2 {
				return
			}
			start, _ := strconv.Atoi(strs[0])
			end, _ := strconv.Atoi(strs[1])
			c.serverPorts = []int{start, end}
		} else {
			fmt.Println(err)
		}
	}
}

// general messages
const UnknownType = -1

const (
	MsgField_UserAgent        = "User-Agent"
	MsgField_Authorization    = "Authorization"
	MsgField_Accept           = "Accept"
	MsgField_Public           = "Public"
	MsgField_ContentBase      = "Content-Base"
	MsgField_ContentType      = "Content-Type"
	MsgField_ContentLength    = "Content-Length"
	MsgField_Range            = "Range"
	MsgField_Session          = "Session"
	MsgField_CSeq             = "CSeq"
	MsgField_Transport        = "Transport"
	MsgField_WWW_Authenticate = "WWW-Authenticate"
	MsgField_Date             = "Date"
	MsgField_RtpInfo          = "RTP-Info"

	ContentType_SDP = "application/sdp"

	Unknown_Text = "Unknown"

	TransportProtocol_RTP     = "RTP"
	TransportProfile_AVP      = "AVP"
	TransportLowerProfile_TCP = "TCP"
	TransportLowerProfile_UDP = "UDP"

	TransportOption_ClientPort = "client_port"

	RFC1123GMT = "Mon, 02 Jan 2006 15:04:05 GMT"
)

const (
	MsgFieldType_UserAgent = iota
	MsgFieldType_Authorization
	MsgFieldType_Accept
	MsgFieldType_Public
	MsgFieldType_ContentBase
	MsgFieldType_ContentType
	MsgFieldType_ContentLength
	MsgFieldType_Range
	MsgFieldType_Session
	MsgFieldType_CSeq
	MsgFieldType_Transport
	MsgFieldType_Authenticate
	MsgFieldType_Date
	MsgFieldType_RtpInfo
)

var (
	msgFields = map[int]string{
		MsgFieldType_UserAgent:     MsgField_UserAgent,
		MsgFieldType_Authorization: MsgField_Authorization,
		MsgFieldType_Accept:        MsgField_Accept,
		MsgFieldType_Public:        MsgField_Public,
		MsgFieldType_ContentBase:   MsgField_ContentBase,
		MsgFieldType_ContentType:   MsgField_ContentType,
		MsgFieldType_ContentLength: MsgField_ContentLength,
		MsgFieldType_Range:         MsgField_Range,
		MsgFieldType_Session:       MsgField_Session,
		MsgFieldType_CSeq:          MsgField_CSeq,
		MsgFieldType_Transport:     MsgField_Transport,
		MsgFieldType_Authenticate:  MsgField_WWW_Authenticate,
		MsgFieldType_Date:          MsgField_Date,
		MsgFieldType_RtpInfo:       MsgField_RtpInfo,
	}
)

// GetMessageFieldText
func GetMessageFieldText(typ int) string {
	if val, ok := msgFields[typ]; ok {
		return val
	}
	return Unknown_Text
}

// GetMessageFieldType
func GetMessageFieldType(text string) int {
	for typ := range msgFields {
		if strings.EqualFold(text, msgFields[typ]) {
			return typ
		}
	}

	return UnknownType
}

func getAddress(ip, port string) string {
	if strings.Contains(port, "(") {
		port = port[:strings.Index(port, "(")]
	}
	return ip + ":" + port
}

func GetIpPort(addr string) (ip, port string, err error) {
	strs := strings.Split(addr, ":")
	if len(strs) != 2 {
		err = errors.New("invalid address")
		return
	}

	ip = strs[0]
	port = strings.ReplaceAll(strs[1], "(rtsp)", "")

	return
}

func getRtspContextId(serverIp, serverPort, clientIp, clientPort string) string {
	return getAddress(serverIp, serverPort) + "-" + getAddress(clientIp, clientPort)
}

func Probe(fileName string) (*RtspContextMap, error) {
	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	rtspCtxMap := make(RtspContextMap)

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
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
		if err = ProbeRequest(&packet, ethPacket, &ipLayer, &rtspCtxMap); nil == err {
			continue
		}
		if err = ProbeResponse(&packet, ethPacket, &ipLayer, &rtspCtxMap); nil == err {
			continue
		}
		// if err = ProbeResponse()
	}

	return &rtspCtxMap, nil
}

func parseMessage(option string) (key, val string, err error) {
	index := strings.Index(option, ":")
	if index < 0 || index >= len(option) {
		err = errors.New("invalid request option string")
		return
	}

	key = option[0:index]
	val = strings.Trim(option[index+1:], " \r\n")

	return
}

type BytePacket struct {
	Index   int
	Payload []byte
	Delay   time.Duration
}

func DemuxRtsp(fileName string, ctx RtspContext) error {
	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return err
	}
	defer handle.Close()

	// set BPF filter
	bpfFilter, err := ctx.GetBPFFilter()
	if nil != err {
		return err
	}
	err = handle.SetBPFFilter(bpfFilter)
	if nil != err {
		return err
	}

	// ctx.ClientAddress
	// handle.SetBPFFilter()

	return nil
}

// buildTextProtoPacket make textprotocol lines to packet data (HTML...). each lines ended with '\r\n' and packet ends with '\r\n\r\n'
func buildTextProtoPacket(lines []string) []byte {
	ret := strings.Join(lines, "\r\n") + "\r\n\r\n"
	return []byte(ret)
}
