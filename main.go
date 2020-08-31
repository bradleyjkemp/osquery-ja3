package main

import (
	"fmt"
	"log"

	"github.com/bradleyjkemp/osquery-ja3/ja3assembler"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	//if len(os.Args) != 2 {
	//	log.Fatalf(`Usage: %s SOCKET_PATH`, os.Args[0])
	//}
	//
	//server, err := osquery.NewExtensionManagerServer("dns_logs", os.Args[1])
	//if err != nil {
	//	log.Fatalf("Error creating extension: %s\n", err)
	//}

	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}
	for _, iface := range ifaces {
		go logJA3Hashes(iface.Name)
	}
	select {}

	//// Create and register a new table plugin with the server.
	//// table.NewPlugin requires the table plugin name,
	//// a slice of Columns and a Generate function.
	//server.RegisterPlugin(table.NewPlugin("ja3_hashes", []table.ColumnDefinition{
	//	table.IntegerColumn("timestamp"),
	//	table.TextColumn("type"),
	//	table.TextColumn("salt"),
	//	table.TextColumn("domain_fingerprint"),
	//	table.TextColumn("root_domain_fingerprint"),
	//}, dnsQueryLogGenerate))
	//if err := server.Run(); err != nil {
	//	log.Fatalln(err)
	//}
}

func logJA3Hashes(iface string) {
	pcapHandle, err := pcap.OpenLive(iface, 1024, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer pcapHandle.Close()
	fmt.Println("Logging JA3 hashes on", iface)
	defer func() { fmt.Println("Stopped logging hashes on", iface) }()

	err = pcapHandle.SetBPFFilter("tcp")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packets := packetSource.Packets()
	assembler := ja3assembler.NewAssembler()

	var packetCount int
	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				// Channel has closed
				return
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				//Unusable
				fmt.Println("Packet unusable")
				continue
			}
			transport := packet.TransportLayer()
			tcp, ok := transport.(*layers.TCP)
			if !ok {
				fmt.Println("Packet not TCP")
				continue
			}
			assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
			packetCount++
		}
	}
}
