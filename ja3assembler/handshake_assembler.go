package ja3assembler

import (
	"crypto/tls"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

const (
	recordHeaderLength    = 5
	handshakeHeaderLength = 4

	typeClientHello byte = 0x01
	typeServerHello byte = 0x02

	recordTypeHandshake = 0x16
)

// JA3PrinterFactory implements tcpassembly.StreamFactory interface
type JA3PrinterFactory struct {
	inProgress map[struct{}]JA3Printer
}

// New returns a new stream for a given TCP key
func (h *JA3PrinterFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	//fmt.Println("Creating new JA3Printer for", net.Src(), net.Dst())
	return &JA3Printer{}
}

type JA3Printer struct {
	finished           bool
	finishReason       string
	unparsedRecordData []byte
	rawHello           []byte
}

func (j *JA3Printer) stopProcessing(reason string, args ...interface{}) {
	j.finished = true
	j.finishReason = fmt.Sprintf(reason, args...)
	fmt.Println("Stopping processing because", j.finishReason)
}

func (j *JA3Printer) ReassemblyComplete() {
	j.finished = true
	j.unparsedRecordData = nil
	j.rawHello = nil
}

func (j *JA3Printer) Reassembled(reassembly []tcpassembly.Reassembly) {

}

// unidirectionalStream implements tcpassembly.Stream
type unidirectionalStream struct {
	bidi *bidirectionalStream // maps to my bidirectional twin.

	// TLS handshake data going to be parsed
	unparsedRecordData []byte
	rawHello           []byte

	// Calculated JA3(S) hashes. Only one should be populated
	ja3  string
	sni  string
	ja3s string

	succeeded  bool   // if true, one of ja3/ja3s must be set
	done       bool   // if true, we've seen the last packet we're going to for this stream.
	doneReason string // just some debugging to see why a stream stopped
}

// Reassembled handles reassembled TCP stream data.
func (s *unidirectionalStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	if s.done {
		return
	}

	for _, packet := range reassembly {
		if packet.Skip != 0 {
			// If any bytes have been missed then we have to give up trying to reconstruct the TLS handshake
			s.completeProcessing(false, "missing packets")
			return
		}
		s.unparsedRecordData = append(s.unparsedRecordData, packet.Bytes...)
	}

	// See if there's another record we can decode
	for len(s.unparsedRecordData) >= recordHeaderLength {
		recordHeader := s.unparsedRecordData[:5]
		// Check the record header is roughly valid
		headerVersion := uint16(recordHeader[1])<<8 | uint16(recordHeader[2])
		recordLength := int(recordHeader[3])<<8 | int(recordHeader[4])
		if headerVersion < tls.VersionTLS10 || headerVersion > tls.VersionTLS13 {
			// Invalid/unsupported record header
			s.completeProcessing(false, "unsupported record header %x", headerVersion)
			return
		}

		// If there's enough record data read "parse" it into the rawHello
		if len(s.unparsedRecordData) >= recordHeaderLength+recordLength {
			s.rawHello = append(s.rawHello, s.unparsedRecordData[recordHeaderLength:recordHeaderLength+recordLength]...)
			s.unparsedRecordData = s.unparsedRecordData[recordHeaderLength+recordLength:]
		} else {
			// Otherwise, break the loop
			break
		}
	}

	// Check if we've read enough of the handshake to decode it
	if len(s.rawHello) < handshakeHeaderLength {
		// Don't even have the handshake header yet
		return
	}

	helloType := s.rawHello[0]
	if helloType != typeClientHello && helloType != typeServerHello {
		// This is not an expected/supported handshake message
		s.completeProcessing(false, "unexpected handshake type")
		return
	}

	helloLength := int(s.rawHello[1])<<16 | int(s.rawHello[2])<<8 | int(s.rawHello[3])
	switch {
	case len(s.rawHello) < handshakeHeaderLength+helloLength:
		// Not enough rawHello data yet
		return
	case helloLength > 2<<16:
		// hello too large
		s.completeProcessing(false, "hello too large")
		return
	}

	// Have now decoded a single handshake message of either clientHello or serverHello type
	switch helloType {
	case typeClientHello:
		msg := &clientHelloMsg{}
		msg.unmarshal(s.rawHello[:handshakeHeaderLength+helloLength])
		s.sni = msg.serverName
		s.ja3 = calculateJA3(msg)
	case typeServerHello:
		msg := &serverHelloMsg{}
		msg.unmarshal(s.rawHello[:handshakeHeaderLength+helloLength])
		s.ja3s = calculateJA3S(msg)
	default:
		panic("unknown hello type")
	}
	s.completeProcessing(true, "success")
}

// ReassemblyComplete marks this stream as finished.
func (s *unidirectionalStream) ReassemblyComplete() {
	if s.done {
		// We already stopped processing this stream so there's no more completion to do
		return
	}

	s.completeProcessing(false, "ReassemblyComplete()")
}

func (s *unidirectionalStream) completeProcessing(success bool, reason string, args ...interface{}) {
	if s.done {
		panic("s.done already set")
	}

	s.succeeded = success
	s.done = true
	s.doneReason = fmt.Sprintf(reason, args...)
	s.unparsedRecordData = nil
	s.rawHello = nil
	s.bidi.maybeFinish()
}

//Assembler handles reassembling TCP streams.
func NewAssembler() *tcpassembly.Assembler {
	return tcpassembly.NewAssembler(tcpassembly.NewStreamPool(&assembler{unmatchedStreams: map[key]*bidirectionalStream{}}))
}
