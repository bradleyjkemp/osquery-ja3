package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bradleyjkemp/osquery-ja3/ja3assembler"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
)

const (
	eventRetentionPeriod = 24 * time.Hour
)

var (
	extensionFlags = flag.NewFlagSet("osquery-ja3", flag.ExitOnError)
	fSocket        = extensionFlags.String("socket", "flag-not-provided", "osqueryd socket to connect to")
	verbose        = extensionFlags.Bool("verbose", false, "enable verbose logging")
	_              = extensionFlags.Int("timeout", 0, "timeout")
	_              = extensionFlags.Int("interval", 0, "interval")
)

func main() {
	err := extensionFlags.Parse(os.Args[1:])

	server, err := osquery.NewExtensionManagerServer("tls_handshake_signatures", *fSocket)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}
	for _, iface := range ifaces {
		go logJA3Hashes(iface.Name)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("tls_handshake_signatures", []table.ColumnDefinition{
		table.IntegerColumn("time"),
		table.TextColumn("ja3"),
		table.TextColumn("ja3s"),
		table.TextColumn("sni"),
	}, generateEventsTable))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

func logJA3Hashes(iface string) {
	pcapHandle, err := pcap.OpenLive(iface, 1024, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer pcapHandle.Close()
	if *verbose {
		fmt.Println("Logging JA3(S) hashes on", iface)
		defer func() {
			fmt.Println("Stopped logging hashes on", iface)
		}()
	}

	err = pcapHandle.SetBPFFilter("tcp")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packets := packetSource.Packets()
	assembler := ja3assembler.NewAssembler(logHandshake)

	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				// Channel has closed
				return
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				//Unusable
				continue
			}
			transport := packet.TransportLayer()
			tcp, ok := transport.(*layers.TCP)
			if !ok {
				// This should never happen but we check so that this doesn't panic
				continue
			}
			assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
		}
	}
}
