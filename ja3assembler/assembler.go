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
type JA3PrinterFactory struct{}

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
	helloType          byte
	rawHelloLength     int
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
	if j.finished {
		//fmt.Println("skipping packet because already finished:", j.finishReason)
		return
	}
	fmt.Println("Reassembling", len(reassembly), "packet(s)")
	defer fmt.Println("Have", len(j.unparsedRecordData), "bytes of raw record, ", len(j.rawHello), "bytes of rawHello")

	for i, packet := range reassembly {
		fmt.Println("Packet", i, "has", len(packet.Bytes), "bytes")
		if packet.Skip != 0 {
			// If any bytes have been missed then we have to give up trying to reconstruct the TLS handshake
			j.stopProcessing("missing packets")
			return
		}
		j.unparsedRecordData = append(j.unparsedRecordData, packet.Bytes...)
	}

	// See if there's another record we can decode
	for len(j.unparsedRecordData) >= recordHeaderLength {
		recordHeader := j.unparsedRecordData[:5]
		// Check the record header is roughly valid
		headerVersion := uint16(recordHeader[1])<<8 | uint16(recordHeader[2])
		recordLength := int(recordHeader[3])<<8 | int(recordHeader[4])
		if headerVersion < tls.VersionTLS10 || headerVersion > tls.VersionTLS13 {
			// Invalid/unsupported record header
			j.stopProcessing("unsupported record header %x", headerVersion)
			return
		}

		// If there's enough record data read "parse" it into the rawHello
		if len(j.unparsedRecordData) >= recordHeaderLength+recordLength {
			j.rawHello = append(j.rawHello, j.unparsedRecordData[recordHeaderLength:recordHeaderLength+recordLength]...)
			j.unparsedRecordData = j.unparsedRecordData[recordHeaderLength+recordLength:]
		} else {
			// Otherwise, break the loop
			break
		}
	}

	// Check if we've read enough of the handshake to decode it
	if len(j.rawHello) < handshakeHeaderLength {
		// Don't even have the handshake header yet
		return
	}

	helloType := j.rawHello[0]
	if helloType != typeClientHello && helloType != typeServerHello {
		// This is not an expected/supported handshake message
		j.stopProcessing("unexpected handshake type")
		return
	}

	helloLength := int(j.rawHello[1])<<16 | int(j.rawHello[2])<<8 | int(j.rawHello[3])
	switch {
	case len(j.rawHello) < handshakeHeaderLength+helloLength:
		// Not enough rawHello data yet
		return
	case helloLength > 2<<16:
		// hello too large
		j.stopProcessing("hello too large")
		return
	}

	// Have now decoded a single handshake message of either clientHello or serverHello type
	switch helloType {
	case typeClientHello:
		msg := &clientHelloMsg{}
		msg.unmarshal(j.rawHello[:handshakeHeaderLength+helloLength])
		fmt.Println("Got client hello for SNI", msg.serverName, calculateJA3(msg))
	case typeServerHello:
		msg := &serverHelloMsg{}
		msg.unmarshal(j.rawHello[:handshakeHeaderLength+helloLength])
		fmt.Println("Got server hello", calculateJA3S(msg))
	}
	j.stopProcessing("success")
}

//Assembler handles reassembling TCP streams.
func NewAssembler() *tcpassembly.Assembler {
	return tcpassembly.NewAssembler(tcpassembly.NewStreamPool(&JA3PrinterFactory{}))
}
