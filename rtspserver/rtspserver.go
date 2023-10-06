// package rtsp server is simple rtsp server for pcap reader
package rtspserver

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cymonkgit/pcapreader/demuxer"
	"github.com/cymonkgit/pcapreader/rtsplayer"
	"github.com/cymonkgit/pcapreader/util"
	// "github.com/labstack/gommon/log"
)

type UDPPair struct {
	Conns   []*net.UDPConn
	Remotes []*net.UDPAddr
	Port    int
}

// key : rtsp context key, value : rtsp path
type RtspSources map[string]string

type Server struct {
	UdpPair  *UDPPair
	Sessions *sync.Map

	Started      bool
	PcapFilename string

	SessionTimeout time.Duration

	RtspUser string
	RtspPwd  string
}

// rtsp server configuration
type ServerConfig struct {
	TimeOutSecond int
}

type RtspSession struct {
	Sock        *net.Conn
	Server      *Server
	PeerIp      net.Addr
	Uri         string
	Authorized  bool
	UserAgent   string
	RtpOverUdp  bool
	Profile     string
	LowProfile  string
	Unicast     bool
	ClientPorts [2]int

	InterleavedChannel chan *util.BytePacket

	CreateTime        time.Time
	ConnectedTime     time.Time
	FirstTransferTime time.Time
	LastTransferTime  time.Time
	TransferSpeed     float64

	PauseDurSum    time.Duration
	PauseStartTime time.Time

	LastRequestTime time.Time

	Scheme     string
	StartTime  time.Time
	EndTime    time.Time
	Speed      float64
	ClockRates []uint32

	ctx    context.Context
	cancel context.CancelFunc
}

var (
	rtspServer   Server
	pcapFilename string
)

func init() {
	rtspServer = Server{
		Sessions:       &sync.Map{},
		SessionTimeout: time.Second * 30,
	}
}

func StartServer(rtspCtx *rtsplayer.RtspContext, fileName string, quit *chan os.Signal) {
	go func() {
		defer func() {
			*quit <- nil
		}()

		pcapFilename = fileName

		if err := rtspServer.Start(rtspCtx); err != nil {
			fmt.Println("start RTSP server error:", err)
		}
	}()
}

func (s *Server) Start(rtspCtx *rtsplayer.RtspContext) error {
	_, rtspPort, err := rtsplayer.GetIpPort(rtspCtx.ServerAddress)
	if nil != err {
		return fmt.Errorf("[rtspserver] fail to parse rtsp context server address. err: %v", err.Error())
	}
	rtspPort = ":" + rtspPort
	rtspServer.SessionTimeout = time.Duration(rtspCtx.SessionTimeoutSec) * time.Second

	fmt.Println("starting RTSP server at port", rtspPort)

	l, err := net.Listen("tcp", rtspPort)
	if nil != err {
		return fmt.Errorf("[rtspserver] fail to bind address; err: %v", err)
	}
	s.Started = true
	defer func() {
		l.Close()
		s.Started = false
	}()

	if rtsplayer.TransferProtocol_UDP == rtspCtx.Protocol {
		// todo : to be implemented
		// s.UdpPair = &UDPPair{}
		// if err = s.UdpPair.ListenUDPs(net.ParseIP("0.0.0.0"), 0); err != nil {
		// 	return err
		// }
		// defer s.UdpPair.Close()
	}

	log.Println("[rtspserver] start on port ", rtspPort)

	// accept connect routine
	for {
		conn, err := l.Accept()
		if nil != err {
			log.Printf("[rtspserver] failed to accept; err: %v", err)
			continue
		} else {
			log.Printf("[rtspserver][%v] connection request", conn.RemoteAddr())
		}
		go s.DoRtsp(conn, rtspCtx)
	}
}

func (s *Server) DoRtsp(conn net.Conn, rtspCtx *rtsplayer.RtspContext) {
	peerIp := conn.RemoteAddr()
	logTag := fmt.Sprintf("[rtspserver][%v][%v]", peerIp, rtspCtx.Url)
	defer func() {
		r := recover()
		if nil != r {
			debug.PrintStack()
			fmt.Printf("[rtspserver] %v DoRtsp recovered %v\n", logTag, r)
		}
	}()

	fmt.Printf("%v rtsp connection request from %v\n", logTag, peerIp)
	var session *RtspSession

	session = &RtspSession{
		Sock:               &conn,
		Server:             s,
		PeerIp:             peerIp,
		ConnectedTime:      time.Now(),
		ClockRates:         make([]uint32, 0),
		InterleavedChannel: make(chan *util.BytePacket, 1000),
	}

	// log.Infoln(logTag, "rtsp client of", client.MediaId, client.PeerIp.String(), "added")
	s.Sessions.Store(conn, session)

	defer func() {
		s.Sessions.Delete(conn)
		// log.Infoln(logTag, "rtsp client of", client.MediaId, client.PeerIp.String(), "removed")
		conn.Close()
		log.Println(logTag, "rtsp connection closed (defer)")
	}()

	// set connection
	conn.SetWriteDeadline(time.Time{})
	conn.SetReadDeadline(time.Time{})
	conn.SetDeadline(time.Time{})
	reader := bufio.NewReader(conn)
	// var err error

	ctx, cancel := context.WithCancel(context.Background())
	session.ctx = ctx
	session.cancel = cancel

	requestChannel := make(chan *rtsplayer.RtspRequestLayer)
	stopReadRequest := false
	defer func() {
		stopReadRequest = true
	}()

	// todo : go
	go s.readRequest(&stopReadRequest, reader, &conn, requestChannel, &cancel)

	// sequenceNumber := uint16(1)
	sendCnt := 0
	lastPacketTime := time.Time{}
SENDERLOOP:
	for {
		select {
		case <-ctx.Done():
			fmt.Println("context done")
			break SENDERLOOP
		case req := <-requestChannel:
			if res, err := s.dispatchRequest(req, session, rtspCtx); nil != err {
				fmt.Println("failed to dispatch request. err:", err.Error())
				// send 500 internal
				res, _ = rtsplayer.BuildResponse(rtsplayer.ResponseData{StatusCode: rtsplayer.InternalServerError, CSeq: req.CSeq})
				if _, err := conn.Write(res); nil != err {
					fmt.Println("failed to send response to client. err:", err.Error())
				}
			} else if nil != res {
				if _, err := conn.Write(res); nil != err {
					fmt.Println("failed to send response to client. err:", err.Error())
				}
			}
			// todo : remove
			fmt.Println(req)
		case ip := <-session.InterleavedChannel:

			var dur time.Duration
			if lastPacketTime.IsZero() {
				dur = 0
			} else {
				dur = ip.Time.Sub(lastPacketTime)
			}

			lastPacketTime = ip.Time
			if dur != time.Duration(0) {
				time.Sleep(dur)
			}

			if rtspCtx.Protocol == rtsplayer.TransferProtocol_TCP {
				if _, err := conn.Write(ip.Payload); nil != err {
					break SENDERLOOP
				} else {
					sendCnt++
				}
			} else {
				// todo: UDP transfer to be implemented
			}
		}
	}
}

func (s *Server) readRequest(stopReadRequest *bool, reader *bufio.Reader, conn *net.Conn, requestChannel chan *rtsplayer.RtspRequestLayer, cancel *context.CancelFunc) {
	defer func() {
		r := recover()
		if nil != r {
			debug.PrintStack()
			log.Println("readRequest recovered:", r)
		}
	}()

	for {
		if *stopReadRequest {
			log.Printf("rtsp ReadRequest exit")
			break
		}
		req, err := readRequestWithTimeout(reader, conn, 500*time.Millisecond)
		if err != nil {
			if err.Error() != "EOF" && !strings.Contains(err.Error(), "i/o timeout") {
				(*cancel)()
				log.Println("read request error. err:", err.Error())
				return
			} else {
				// log.Debugln(logTag, "read request EOF")
				time.Sleep(time.Millisecond)
			}
		} else {
			if nil != req {
				log.Printf("request received")
				requestChannel <- req
				time.Sleep(time.Millisecond * 1)
			}
		}
	}
}

func (s *Server) dispatchRequest(req *rtsplayer.RtspRequestLayer, client *RtspSession, rtspContext *rtsplayer.RtspContext) (response []byte, err error) {
	fmt.Println("request received.", req.Method)

	switch req.Method {
	case rtsplayer.RequestMethod_Options:
		return s.doOptions(req, client, rtspContext)
	case rtsplayer.RequestMethod_Describe:
		return s.doDescribe(req, client, rtspContext)
	case rtsplayer.RequestMethod_Setup:
		return s.doSetup(req, client, rtspContext)
	case rtsplayer.RequestMethod_Play:
		return s.doPlay(req, client, rtspContext)
	case rtsplayer.RequestMethod_Pause:
		return s.doPause(req, client, rtspContext)
	}

	return nil, errors.New("invalid request method")
}

// checkPath check request's uri and rtspContext's uri
func checkPath(req *rtsplayer.RtspRequestLayer, rtspContext *rtsplayer.RtspContext) (rd *rtsplayer.ResponseData) {

	u, er := url.Parse(req.Uri)
	if nil != er {
		rd = &rtsplayer.ResponseData{StatusCode: rtsplayer.BadRequest, CSeq: req.CSeq}
		return
	}

	u2, er := url.Parse(rtspContext.Url)
	if nil != er {
		rd = &rtsplayer.ResponseData{StatusCode: rtsplayer.NotFound, CSeq: req.CSeq}
	}

	if u.Path != u2.Path {
		rd = &rtsplayer.ResponseData{StatusCode: rtsplayer.NotFound, CSeq: req.CSeq}
	}

	return
}

// doOptions 'OPTIONS' request handler
func (s *Server) doOptions(req *rtsplayer.RtspRequestLayer, client *RtspSession, rtspContext *rtsplayer.RtspContext) (response []byte, err error) {
	if rd := checkPath(req, rtspContext); nil != rd {
		response, err = rtsplayer.BuildResponse(*rd)
		if nil == err {
			fmt.Printf("rtsp response for %v build. code:%v\n", req.Method, rtsplayer.NotFound)
		} else {
			response, err = rtsplayer.BuildResponse(rtsplayer.ResponseData{StatusCode: 500, CSeq: req.CSeq})
		}
		return
	}

	client.Uri = req.Uri

	messages := make([]rtsplayer.KeyAndVlue, 0)

	// Public : from rtspContext
	supported := ""
	for i, method := range rtspContext.SupportedMethod {
		supported += rtsplayer.GetMethodTypeText(method)
		if i != len(rtspContext.SupportedMethod)-1 {
			supported += ", "
		}
	}

	if len(supported) > 0 {
		messages = append(messages, rtsplayer.KeyAndVlue{Key: "Public", Value: supported})
	}

	response, err = rtsplayer.BuildResponse(rtsplayer.ResponseData{StatusCode: rtsplayer.OK, CSeq: req.CSeq, Messages: messages})
	return
}

func checkAuthority(req *rtsplayer.RtspRequestLayer, rtspContext *rtsplayer.RtspContext) bool {
	authorized := false
	if nil != rtspContext.Auth && !rtspContext.SkipAuthorization {
		if auth := req.GetMessageValueByType(rtsplayer.MsgFieldType_Authorization); len(auth) > 0 {
			if rtspContext.Auth.Check(auth) {
				authorized = true
			}
		}
	} else if nil == rtspContext.Auth || rtspContext.SkipAuthorization {
		authorized = true
	}

	return authorized
}

func doUnauthorized(req *rtsplayer.RtspRequestLayer, rtspContext *rtsplayer.RtspContext) (response []byte, err error) {
	rd := rtsplayer.ResponseData{
		StatusCode: rtsplayer.Unauthorized,
		CSeq:       req.CSeq,
		Messages: []rtsplayer.KeyAndVlue{
			{
				Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Authenticate),
				Value: rtspContext.Auth.GetAuthResponseVaue(),
			},
		},
	}
	response, err = rtsplayer.BuildResponse(rd)
	return
}

// doOptions 'DESCRIBE' request handler
func (s *Server) doDescribe(req *rtsplayer.RtspRequestLayer, client *RtspSession, rtspContext *rtsplayer.RtspContext) (response []byte, err error) {
	authorized := checkAuthority(req, rtspContext)
	if !authorized {
		return doUnauthorized(req, rtspContext)
	}

	var knv []rtsplayer.KeyAndVlue
	if !rtspContext.SkipAuthorization && nil != rtspContext.Auth {
		knv = []rtsplayer.KeyAndVlue{
			{
				Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Authenticate),
				Value: rtspContext.Auth.GetAuthResponseVaue(),
			},
		}
	}

	knv = append(knv, []rtsplayer.KeyAndVlue{
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_ContentBase),
			Value: req.Uri,
		},
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_ContentType),
			Value: rtsplayer.ContentType_SDP,
		},
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_ContentLength),
			Value: strconv.Itoa(len(rtspContext.SDP)),
		},
	}...)

	rd := rtsplayer.ResponseData{
		StatusCode: rtsplayer.OK,
		CSeq:       req.CSeq,
		Messages:   knv,
		Appendent:  rtspContext.SDP,
	}
	response, err = rtsplayer.BuildResponse(rd)
	return
}

// doSetup 'SETUP' request handler
func (s *Server) doSetup(req *rtsplayer.RtspRequestLayer, client *RtspSession, rtspContext *rtsplayer.RtspContext) (response []byte, err error) {
	authorized := checkAuthority(req, rtspContext)
	if !authorized {
		return doUnauthorized(req, rtspContext)
	}

	// example 1 : UDP
	// User-Agent: LibVLC/3.0.18 (LIVE555 Streaming Media v2016.11.28)\r\n
	// Transport: RTP/AVP;unicast;client_port=49276-49277
	// example 2 : TCP
	// Transport: RTP/AVP/TCP;unicast;interleaved=0-1
	userAgent := req.GetMessageValueByType(rtsplayer.MsgFieldType_UserAgent)
	transportReq := req.GetMessageValueByType(rtsplayer.MsgFieldType_Transport)
	client.UserAgent = userAgent

	transport, profile, lowerTransport, unicast, params, err := rtsplayer.GetTrasportOption(transportReq)
	if nil != err {
		return
	}
	supportedTransport := true
	// only support RTP
	// todo : UDP support to be implemented
	if transport != rtsplayer.TransportProtocol_RTP || profile != rtsplayer.TransportProfile_AVP ||
		unicast != rtspContext.Unicast {
		supportedTransport = false
	}

	// todo : support crsoss transfer serer - client transport type
	if (lowerTransport == rtsplayer.TransportLowerProfile_UDP && rtspContext.Protocol != rtsplayer.TransferProtocol_UDP) ||
		(lowerTransport == rtsplayer.TransportLowerProfile_TCP && rtspContext.Protocol != rtsplayer.TransferProtocol_TCP) {
		supportedTransport = false
	}

	// client port // map[string]string
	if lowerTransport == rtsplayer.TransportLowerProfile_UDP {
		if val, ok := params[rtsplayer.TransportOption_ClientPort]; ok {
			ports := strings.Split(val, "-")
			if len(ports) >= 1 {
				client.ClientPorts[0], _ = strconv.Atoi(ports[0])
			}
			if len(ports) >= 2 && len(ports[1]) > 0 {
				client.ClientPorts[1], _ = strconv.Atoi(ports[1])
			}
		} else {
			supportedTransport = false
		}
	}

	if !supportedTransport {
		rd := rtsplayer.ResponseData{
			StatusCode: rtsplayer.UnsupportedTransport,
			CSeq:       req.CSeq,
		}
		response, err = rtsplayer.BuildResponse(rd)
		return
	}

	// response example 1 : UDP
	// Session: 1804446769; timeout=60
	// Transport: RTP/AVP;unicast;destination=172.168.11.33;source=172.168.11.148;client_port=49276-49277;server_port=13068-13069;ssrc=6EFF3234;mode="PLAY"
	// response example 2 : TCP
	// Transport: RTP/AVP/TCP;unicast;interleaved=0-1
	// Session: 240583037

	var knv []rtsplayer.KeyAndVlue
	if !rtspContext.SkipAuthorization && nil != rtspContext.Auth {
		knv = []rtsplayer.KeyAndVlue{
			{
				Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Authenticate),
				Value: rtspContext.Auth.GetAuthResponseVaue(),
			},
		}
	}

	knv = append(knv, []rtsplayer.KeyAndVlue{
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Session),
			Value: fmt.Sprintf("%v; timeout=%v", rtspContext.SessionId, rtspServer.SessionTimeout.Seconds()),
		},
		// todo : UDP port pair info to be implemented
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Transport),
			Value: transportReq,
		},
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Date),
			Value: time.Now().UTC().Format(rtsplayer.RFC1123GMT),
		},
	}...)

	rd := rtsplayer.ResponseData{
		StatusCode: rtsplayer.OK,
		CSeq:       req.CSeq,
		Messages:   knv,
	}
	response, err = rtsplayer.BuildResponse(rd)

	return
}

func (s *Server) doPlay(req *rtsplayer.RtspRequestLayer, session *RtspSession, rtspContext *rtsplayer.RtspContext) (response []byte, err error) {
	authorized := checkAuthority(req, rtspContext)
	if !authorized {
		return doUnauthorized(req, rtspContext)
	}

	// userAgent := req.GetMessageValueByType(rtsplayer.MsgFieldType_UserAgent)
	sessionId := req.GetMessageValueByType(rtsplayer.MsgFieldType_Session)

	sessionIdNum, err := strconv.Atoi(sessionId)

	if sessionIdNum != rtspContext.SessionId {
		return nil, errors.New("invadlid seesionID:" + sessionId)
	}

	/*
		response example:
		CSeq: 5\r\n
		Date: Tue, Sep 19 2023 04:40:23 GMT\r\n
		Range: npt=0.000-\r\n
		Session: 240583037
		RTP-Info: url=rtsp://192.168.100.100:8554/stream/1/track1;seq=1231;rtptime=4718616\r\n
		\r\n
	*/

	knv := []rtsplayer.KeyAndVlue{
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Date),
			Value: time.Now().Format(rtsplayer.RFC1123GMT),
		},
		// todo : UDP port pair info to be implemented
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Range),
			Value: "npt=0.000-",
		},
		{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_Session),
			Value: fmt.Sprintf("%v", rtspContext.SessionId),
		},
	}

	if rtspContext.UseRtpInfo {
		knv = append(knv, rtsplayer.KeyAndVlue{
			Key:   rtsplayer.GetMessageFieldText(rtsplayer.MsgFieldType_RtpInfo),
			Value: fmt.Sprintf("url=%v;seq=%v;rtptime=%v", rtspContext.RtpUrl, fmt.Sprintln(rtspContext.RtpSeq), rtspContext.RtpTime),
		})
	}

	rd := rtsplayer.ResponseData{
		StatusCode: rtsplayer.OK,
		CSeq:       req.CSeq,
		Messages:   knv,
	}
	response, err = rtsplayer.BuildResponse(rd)

	if nil != err {
		return nil, err
	}

	go demuxRoutine(pcapFilename, session, rtspContext)

	return response, nil
}

func (s *Server) doPause(req *rtsplayer.RtspRequestLayer, client *RtspSession, rtspContext *rtsplayer.RtspContext) (response []byte, err error) {
	return nil, nil
}

// readRequestWithTimeout read textprotocol packets from net.Conn and bufio. duration is timeout for peek from net.Conn
func readRequestWithTimeout(b *bufio.Reader, conn *net.Conn, duration time.Duration) (req *rtsplayer.RtspRequestLayer, err error) {
	// peek first line (end with '\r\n') and wait until timeout reached
	for {
		(*conn).SetReadDeadline(time.Now().Add(duration))
		// peek
		peek, er := b.Peek(4)
		if len(peek) < 1 || nil != er {
			return nil, er
		}

		// skip rtcp request
		if isrtcp, rtcpLen := IsRtcpRequest(peek); isrtcp && rtcpLen > 0 {
			// consume RTCP bytes
			b.Discard(rtcpLen)
		} else {
			break
		}

		if b.Buffered() > 0 {
			continue
		}
	}

	tp := newTextprotoReader(b)
	// read first line (end with '\r\n')
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}

	defer func() {
		tp.R = nil // remove textproto reader
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	fmt.Println(s)
	lines := make([]string, 1)
	lines[0] = s

	// read rest of lines until receive '\r\n\r\n'
	for {
		s, e := tp.ReadContinuedLine()
		if nil != e {
			break
		}
		lines = append(lines, s)
	}

	// rebuild packet to parse request with rtsplayer packet parser
	body := strings.Join(lines, "\r\n") + "\r\n\r\n"
	// for debugging . todo : remove
	fmt.Println("----------------------")
	fmt.Print(body)
	fmt.Println("----------------------")

	req = rtsplayer.ParseRequest([]byte(body))
	if nil == req {
		return nil, errors.New("malformed RTSP request")
	}

	return
}

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	return textproto.NewReader(br)
}

// RTP/AVP/TCP Transmission Method
func IsRtcpRequest(in []byte) (bool, int) {
	if len(in) >= 4 {
		if in[0] == 0x24 {
			return true, int(binary.BigEndian.Uint16(in[2:]))
		}
	}
	return false, 0
}

func demuxRoutine(filename string, session *RtspSession, rtspctx *rtsplayer.RtspContext) {
	dmx, err := demuxer.Open(filename, rtspctx)
	if nil != err {
		return
	}
	defer dmx.Close()

	ctx, _ := context.WithCancel(session.ctx)

DEMUXLOOP:
	for {
		packet, err := dmx.ReadPacket()
		if nil != err {
			return
		}

		session.InterleavedChannel <- packet
		select {
		case <-ctx.Done():
			break DEMUXLOOP
		default:
		}
	}
}

func readRtpPacket() {

}
