package util

import (
	"fmt"
	"sync"
	"time"
)

// interleaved frame information
type InterleavedPacketInfo struct {
	Len       uint16
	Marker    uint8
	SeqNumber int
	SSRC      uint32
	PT        uint8
}

func (ri InterleavedPacketInfo) GetText() string {
	// return fmt.Sprintf("Seq:%v, marker: %v, Payload: %v, SSRC:%v", ri.SeqNumber, ri.Marker, ri.PT, ri.SSRC)
	return fmt.Sprintf("Seq:%v, marker: %v", ri.SeqNumber, ri.Marker)
}

// channel deliver data format
type BytePacket struct {
	Payload       []byte
	Time          time.Time
	CaptureLength int
	Reassembled   bool
	ILFI          []InterleavedPacketInfo
}

// interleaved packet queue
type BytePacketQueue struct {
	lock  sync.Locker
	queue []*BytePacket
}

func (q BytePacketQueue) GetLength() int {
	q.lock.Lock()
	defer q.lock.Unlock()

	return len(q.queue)
}

func (q *BytePacketQueue) Push(pkt *BytePacket) {
	q.lock.Lock()
	defer q.lock.Unlock()

	q.queue = append(q.queue, pkt)
}

func (q *BytePacketQueue) Pop() *BytePacket {
	q.lock.Lock()
	defer q.lock.Unlock()

	if len(q.queue) < 1 {
		return nil
	}

	pkt := q.queue[0]
	q.queue = q.queue[1:]

	return pkt
}

func (q *BytePacketQueue) Clear() {
	q.lock.Lock()
	defer q.lock.Unlock()

	q.queue = nil
}
