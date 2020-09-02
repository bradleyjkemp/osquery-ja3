// Adapted from github.com/google/gopacket/examples/bidirectional/main.go
package ja3assembler

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

// key is used to map bidirectional streams to each other.
type key struct {
	net, transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k key) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

// timeout is the length of time to wait before flushing connections and
// bidirectional stream pairs.
const timeout = 5 * time.Minute

// bidirectionalStream stores each unidirectional side of a bidirectional stream.
//
// When a new stream comes in, if we don't have an opposite stream, a bidirectionalStream is
// created with 'a' set to the new stream.  If we DO have an opposite stream,
// 'b' is set to the new stream.
type bidirectionalStream struct {
	key            key                         // Key of the first stream, mostly for logging.
	a, b           *unidirectionalStream       // the two unidirectional streams.
	lastPacketSeen time.Time                   // last time we saw a packet from either stream.
	callback       func(ja3, ja3s, sni string) // called when both directions have finished parsing their handshake
}

// myFactory implements tcpassembly.StreamFactory
type assembler struct {
	sync.Mutex
	callback func(ja3, ja3s, sni string)
	// unmatchedStreams allows us to look upmaps keys to bidirectional stream pairs.
	unmatchedStreams map[key]*bidirectionalStream
}

// New handles creating a new tcpassembly.Stream.
func (f *assembler) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	f.Lock()
	defer f.Unlock()

	// Create a new stream.
	s := &unidirectionalStream{}

	netFlow.EndpointType()
	// Find the bidirectionalStream bidirectional struct for this stream, creating a new one if
	// one doesn't already exist in the map.
	k := key{netFlow, tcpFlow}
	bd := f.unmatchedStreams[k]
	if bd == nil {
		bd = &bidirectionalStream{a: s, key: k, callback: f.callback}
		// Register bidirectional with the reverse key, so the matching stream going
		// the other direction will find it.
		f.unmatchedStreams[key{netFlow.Reverse(), tcpFlow.Reverse()}] = bd
	} else {
		bd.b = s
		// Clear out the bidirectionalStream we're using from the map, just in case.
		delete(f.unmatchedStreams, k)
	}
	s.bidi = bd
	return s
}

// emptyStream is used to finish bidirectionalStream that only have one stream, in
// collectOldStreams.
var emptyStream = &unidirectionalStream{done: true}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout', and sets/finishes the 'b' stream inside them.  The 'a' stream may
// still receive packets after this.
func (f *assembler) collectOldStreams() {
	cutoff := time.Now().Add(-timeout)
	for k, bd := range f.unmatchedStreams {
		if bd.lastPacketSeen.Before(cutoff) {
			log.Printf("[%v] timing out old stream", bd.key)
			bd.b = emptyStream            // stub out b with an empty stream.
			delete(f.unmatchedStreams, k) // remove it from our map.
			bd.maybeFinish()              // if b was the last stream we were waiting for, finish up.
		}
	}
}

// maybeFinish will wait until both directions are complete, then print out
// stats.
func (bd *bidirectionalStream) maybeFinish() {
	if bd.b == nil {
		// Cannot be finished if haven't seen the b side yet
		return
	}
	if !bd.a.done || !bd.b.done {
		// We've seen both streams but one isn't finished processing yet
		return
	}

	// Both sides have finished so work out which was the client and which was the server
	var ja3, ja3s, sni string
	switch {
	case bd.a.succeeded && bd.b.succeeded:
		switch {
		case bd.a.ja3 != "" && bd.b.ja3s != "": // A = Client, B = Server
			ja3, ja3s, sni = bd.a.ja3, bd.b.ja3s, bd.a.sni

		case bd.a.ja3s != "" && bd.b.ja3 != "": // A = Server, B = Client
			ja3, ja3s, sni = bd.b.ja3, bd.a.ja3s, bd.b.sni

		default:
			panic("impossible ja3/ja3s combination")
		}

	case bd.a.succeeded && !bd.b.succeeded:
		ja3, ja3s, sni = bd.a.ja3, bd.a.ja3s, bd.a.sni

	case !bd.a.succeeded && bd.b.succeeded:
		ja3, ja3s, sni = bd.b.ja3, bd.b.ja3s, bd.b.sni

	case !bd.a.succeeded && !bd.b.succeeded:
		// Neither succeeded... guess this wasn't a TLS handshake after all
		return
	}

	bd.callback(ja3, ja3s, sni)
}
