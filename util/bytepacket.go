package util

import (
	"sync"
	"time"
)

// channel deliver data format
type BytePacket struct {
	Payload []byte
	Time    time.Time
	SSRC    uint32
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
