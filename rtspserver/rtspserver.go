package rtspserver

// import (
// 	"bufio"
// 	"context"
// 	"encoding/binary"
// 	"fmt"
// 	"io"
// 	"net"
// 	"net/url"
// 	"runtime/debug"
// 	"strconv"
// 	"strings"
// 	"sync"
// 	"time"

// 	"github.com/cymonkgit/pcapreader/rtsplayer"
// 	"github.com/labstack/gommon/log"
// )

// type UDPPair struct {
// 	Conns   []*net.UDPConn
// 	Remotes []*net.UDPAddr
// 	Port    int
// }

// type Server struct {
// 	Sessions *sync.Map
// 	UdpPair  *UDPPair

// 	RtspClients *sync.Map

// 	Started bool

// 	// Started    fmp4.TAtomBool
// 	// TlsStarted fmp4.TAtomBool

// 	SessionTimeout time.Duration
// 	// cron           *cron.Cron

// 	RtspUser string
// 	RtspPwd  string
// }

// type RtspClient struct {
// 	Sock       *net.Conn
// 	Server     *Server
// 	PeerIp     net.Addr
// 	Uri        string
// 	Authorized bool

// 	CreateTime        time.Time
// 	ConnectedTime     time.Time
// 	FirstTransferTime time.Time
// 	LastTransferTime  time.Time
// 	TransferSpeed     float64

// 	PauseDurSum    time.Duration
// 	PauseStartTime time.Time

// 	LastRequestTime time.Time

// 	Scheme     string
// 	StartTime  time.Time
// 	EndTime    time.Time
// 	Speed      float64
// 	ClockRates []uint32

// 	ctx    context.Context
// 	cancel context.CancelFunc
// }

// type ServerInerface interface {
// 	AddHandler(path string, handler *RTSPHandler) error
// 	RemoveHandler(path string, handler *RTSPHandler) error
// 	AddUDPPort(path string)
// 	ListenAndServe(addr string) error
// }

// type RTSPHandler interface {
// 	HandleOptions(request *rtsplayer.RtspRequestLayer) ([]byte, error)
// 	HandleDescribe(request *rtsplayer.RtspRequestLayer) ([]byte, error)
// 	HandleSetup(request *rtsplayer.RtspRequestLayer) ([]byte, error)
// 	HandleSetupTCP(request *rtsplayer.RtspRequestLayer) ([]byte, error)
// 	HandleSetupUDP(request *rtsplayer.RtspRequestLayer) ([]byte, error)
// 	HandlePlay(request *rtsplayer.RtspRequestLayer) ([]byte, error)
// 	HandleTeardown(request *rtsplayer.RtspRequestLayer) ([]byte, error)
// }

// type RtspServerSession struct {
// 	Key             string
// 	InterleavedMode bool
// 	SSRC            uint32 // todo : consider multi channel
// }

// func (s *Server) ListenAndServe(addr string) error {
// 	l, err := net.Listen("tcp", addr)
// 	if nil != err {
// 		return fmt.Errorf("[rtspserver] fail to bind address; err: %v", err)
// 	}
// 	s.Started = true
// 	defer func() {
// 		l.Close()
// 		s.Started = false
// 	}()

// 	// todo : check here for UDP transmitter
// 	// s.UdpPair = &UDPPair{}
// 	// if err = s.UdpPair.ListenUDPs(net.ParseIP("0.0.0.0"), 0); err != nil {
// 	// 	return err
// 	// }
// 	// defer s.UdpPair.Close()

// 	log.Info("[rtspserver] start on port ", addr)

// 	for {
// 		conn, err := l.Accept()
// 		if nil != err {
// 			log.Warnf("[rtspserver] failed to accept; err: %v", err)
// 			continue
// 		} else {
// 			log.Infof("[rtspserver][%v] connection request", conn.RemoteAddr())
// 		}
// 		go s.ConnHandler(conn)
// 	}
// }

// func (s *Server) ConnHandler(conn net.Conn) {
// 	peerIp := conn.RemoteAddr()
// 	logTag := fmt.Sprintf("[rtspserver][%v]", peerIp)
// 	defer func() {
// 		r := recover()
// 		if nil != r {
// 			debug.PrintStack()
// 			log.Error("[rtspserver]", logTag, " connhander recovered:", r)
// 		}
// 	}()

// 	log.Debugf("%v rtsp connection request from %v", logTag, peerIp)
// 	var client *RtspClient

// 	client = &RtspClient{
// 		Sock:          &conn,
// 		Server:        s,
// 		PeerIp:        peerIp,
// 		ConnectedTime: time.Now(),
// 		ClockRates:    make([]uint32, 0),
// 	}

// 	// log.Infoln(logTag, "rtsp client of", client.MediaId, client.PeerIp.String(), "added")
// 	s.RtspClients.Store(conn, client)

// 	defer func() {
// 		s.RtspClients.Delete(conn)
// 		// log.Infoln(logTag, "rtsp client of", client.MediaId, client.PeerIp.String(), "removed")
// 		conn.Close()
// 		log.Debugln(logTag, "rtsp connection closed (defer)")
// 	}()

// 	conn.SetWriteDeadline(time.Time{})
// 	conn.SetReadDeadline(time.Time{})
// 	conn.SetDeadline(time.Time{})
// 	reader := bufio.NewReader(conn)
// 	var err error

// 	ctx, cancel := context.WithCancel(context.Background())
// 	client.ctx = ctx
// 	client.cancel = cancel

// 	requestChannel := make(chan *rtsplayer.RtspRequestLayer)
// 	stopReadRequest := false
// 	defer func() {
// 		stopReadRequest = true
// 	}()

// 	go func() {
// 		defer func() {
// 			r := recover()
// 			if nil != r {
// 				debug.PrintStack()
// 				log.Errorln(logTag, "readRequest recovered:", r)
// 			}
// 		}()

// 		for {
// 			if stopReadRequest {
// 				log.Infoln(logTag, "rtsp ReadRequest exit")
// 				break
// 			}
// 			req, err := ReadRequestWithTimeout(reader, &conn, time.Duration(config.RtspServerReadTimeoutMs)*time.Millisecond)
// 			if err != nil {
// 				if strings.Contains(err.Error(), "malformed RTSP request") ||
// 					strings.Contains(err.Error(), "invalid method") ||
// 					strings.Contains(err.Error(), "malformed RTSP version") {
// 					//
// 					time.Sleep(time.Millisecond * 1)
// 					continue
// 				} else {
// 					if err.Error() != "EOF" && !strings.Contains(err.Error(), "i/o timeout") {
// 						cancel()
// 						log.Errorln(logTag, "read request error. err:", err.Error())
// 						return
// 					} else {
// 						// log.Debugln(logTag, "read request EOF")
// 						time.Sleep(time.Millisecond)
// 					}
// 				}
// 			} else {
// 				if nil != req {
// 					log.Traceln(logTag, "request received")
// 					requestChannel <- req
// 					time.Sleep(time.Millisecond * 1)
// 				}
// 			}
// 		}
// 	}()

// 	sequenceNumber := uint16(1)
// 	var session *RtspServerSession
// 	defer func() {
// 		if session != nil {
// 			s.DeleteSession(session.Key)
// 		}
// 	}()

// 	sendCnt := 0

// 	log.Infoln(logTag, "rtsp session handler start", logTag)
// 	lastIPReceive := time.Time{}
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			log.Infoln(logTag, "context done")
// 			return
// 		case req := <-requestChannel:
// 			client.LastRequestTime = time.Now()

// 			log.Traceln(logTag, "req channel. recv:", req.Method)
// 			res, err = s.HandleRequest(&logTag, req, client)

// 			if err != nil {
// 				log.Errorln(logTag, "handle request error. err:", err.Error())
// 				return
// 			}

// 			// session 이 없는 경우에만 session 초기화.
// 			if len(req.Header.Get("Session")) > 0 {
// 				sessionId := req.Header.Get("Session")
// 				// session 키 값이 같으면 생략
// 				if nil == session ||
// 					(session != nil && sessionId != session.Key) {
// 					if session = s.GetSession(sessionId); session != nil {
// 						InterleavedChannel = session.InterleavedChannel
// 						log.Infoln(logTag, "session, ich = ", InterleavedChannel)
// 					}
// 				}
// 			}

// 			res.ContentLength = int64(len(res.Body))
// 			err = res.Write(conn)
// 			if err != nil {
// 				log.Errorln(logTag, "write response error. err:", err.Error())
// 				return
// 			} else {
// 				log.Debugln(logTag, "write ", req.Method, "response. status code:", res.StatusCode, ", status:", res.Status)
// 			}
// 		case ip := <-InterleavedChannel:
// 			if lastIPReceive.IsZero() {
// 				log.Traceln(logTag, "interleaved channel received.")
// 				lastIPReceive = time.Now()
// 			} else {
// 				t := time.Now()
// 				log.Traceln(logTag, "interleaved channel received. delay: ", t.Sub(lastIPReceive), ", marker:", ip.Marker)
// 				lastIPReceive = t
// 			}
// 			// interleave ??
// 			/*
// 				S->C: $\000{2 byte length}{"length" bytes data, w/RTP header}
// 				S->C: $\000{2 byte length}{"length" bytes data, w/RTP header}
// 				S->C: $\001{2 byte length}{"length" bytes  RTCP packet}
// 			*/
// 			interleaveHeader := make([]byte, 4)
// 			interleaveHeader[0] = '$'
// 			interleaveHeader[1] = ip.Channel
// 			interleaveHeader[2] = 0
// 			interleaveHeader[3] = 0
// 			uin := make([]byte, 2)

// 			binary.BigEndian.PutUint16(uin, uint16(len(ip.Packet)+12))
// 			// TODO : pkt[1] = session -> channel
// 			interleaveHeader[2] = uin[0]
// 			interleaveHeader[3] = uin[1]

// 			// todo : expand payload type for other codec and stream type
// 			header := RTPHeader{
// 				Version:        2,
// 				Padding:        0,
// 				Extension:      0,
// 				CSRCCount:      0,
// 				Marker:         ip.Marker,
// 				PayloadType:    96,
// 				SequenceNumber: uint16(sequenceNumber),
// 				Timestamp:      ip.Timestamp,
// 				SSRC:           session.SSRC, // check
// 				CSRCS:          []uint32{},
// 			}

// 			sequenceNumber++

// 			// create packet
// 			buf, err := createRtpPacket(&header, ip)
// 			if err != nil {
// 				log.Errorln(logTag, "failed to create RTP packet. err:", err.Error())
// 				return
// 			}

// 			var written int
// 			bts := buf.Bytes()
// 			btss := fmt.Sprintf("%02X %02X %02X %02X", bts[0], bts[1], bts[2], bts[3])
// 			if ip.Marker == 1 {
// 				time.Sleep(time.Microsecond * 150)
// 				if enableTraceLog.Get() && !client.LastTransferTime.IsZero() {
// 					log.Debugln(logTag, "inter packet delay : ", time.Now().Sub(client.LastTransferTime))
// 				}
// 				client.LastTransferTime = time.Now()
// 				if sendCnt < 1 {
// 					client.StartTistCalc(ip.Timestamp, client.LastTransferTime)
// 				}

// 				// 1초에 한 번 전송률 계산
// 				if client.GetElapsedAfterLastTransferRateCheck(client.LastTransferTime) > time.Second {
// 					client.CalcTransferRate(ip.Timestamp)
// 				}
// 			}
// 			written, err = conn.Write(bts)
// 			if err != nil {
// 				log.Errorln(logTag, "connection write RTP packet error. err:", err.Error())
// 				return
// 			} else {
// 				if enableTraceLog.Get() {
// 					log.Debugln(logTag, "write. interleaved packet. written:", written, ", seq:", header.SequenceNumber, ", Timestamp:", header.Timestamp, ", marker:", header.Marker, ",", btss)
// 				}
// 			}

// 			if ip.Marker == 1 {
// 				sendCnt++
// 				// if sendCnt%100 == 1 {
// 				// 	log.Debugln(logTag, "send packet count:", sendCnt)
// 				// }
// 			} else {
// 				time.Sleep(time.Microsecond * 50)
// 			}

// 		default:
// 			time.Sleep(5 * time.Millisecond)
// 		}
// 	}
// }

// func ReadRequestWithTimeout(b *bufio.Reader, conn *net.Conn, duration time.Duration) (req *Request, err error) {
// 	for {
// 		(*conn).SetReadDeadline(time.Now().Add(duration))
// 		peek, er := b.Peek(4)
// 		if len(peek) < 1 || nil != er {
// 			return nil, er
// 		}

// 		if isrtcp, rtcpLen := IsRtcpRequest(peek); isrtcp && rtcpLen > 0 {
// 			// consume RTCP bytes
// 			b.Discard(rtcpLen)
// 		} else {
// 			break
// 		}

// 		if b.Buffered() > 0 {
// 			continue
// 		}
// 	}

// 	tp := newTextprotoReader(b)
// 	req = new(Request)
// 	// First line: GET /index.html HTTP/1.0
// 	var s string
// 	if s, err = tp.ReadLine(); err != nil {
// 		return nil, err
// 	}

// 	defer func() {
// 		putTextprotoReader(tp)
// 		if err == io.EOF {
// 			err = io.ErrUnexpectedEOF
// 		}
// 	}()

// 	var ok bool
// 	req.Method, req.RequestURI, req.Proto, ok = parseRequestLine(s)
// 	if !ok {
// 		return nil, &badStringError{"malformed RTSP request", s}
// 	}
// 	if !validMethod(req.Method) {
// 		return nil, &badStringError{"invalid method", req.Method}
// 	}
// 	rawurl := req.RequestURI
// 	if req.ProtoMajor, req.ProtoMinor, ok = ParseRTSPVersion(req.Proto); !ok {
// 		return nil, &badStringError{"malformed RTSP version", req.Proto}
// 	}

// 	// CONNECT requests are used two different ways, and neither uses a full URL:
// 	// The standard use is to tunnel HTTPS through an HTTP proxy.
// 	// It looks like "CONNECT www.google.com:443 HTTP/1.1", and the parameter is
// 	// just the authority section of a URL. This information should go in req.URL.Host.
// 	//
// 	// The net/rpc package also uses CONNECT, but there the parameter is a path
// 	// that starts with a slash. It can be parsed with the regular URL parser,
// 	// and the path will end up in req.URL.Path, where it needs to be in order for
// 	// RPC to work.
// 	justAuthority := req.Method == "CONNECT" && !strings.HasPrefix(rawurl, "/")
// 	if justAuthority {
// 		rawurl = "http://" + rawurl
// 	}

// 	if req.URL, err = url.ParseRequestURI(rawurl); err != nil {
// 		return nil, err
// 	}

// 	if justAuthority {
// 		// Strip the bogus "http://" back off.
// 		req.URL.Scheme = ""
// 	}

// 	// Subsequent lines: Key: value.
// 	mimeHeader, err := tp.ReadMIMEHeader()
// 	if err != nil {
// 		return nil, err
// 	}
// 	req.Header = Header(mimeHeader)

// 	contentLength, _ := strconv.Atoi(req.Header.Get("Content-Length"))
// 	if contentLength > 0 {
// 		req.Body = make([]byte, contentLength)
// 		if _, err = io.ReadFull(b, req.Body); err != nil {
// 			return nil, err
// 		}
// 	}

// 	return req, nil
// }
