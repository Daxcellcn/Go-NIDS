package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	maxPayloadSize   = 1000              // Example threshold for large payload
	networkInterface = "en0"             // Network interface to capture packets from
	logFile          = "nids_alerts.log" // Log file to store alerts
)

// Packet analyzer with a mutex to ensure thread safety for logging
type PacketAnalyzer struct {
	mu      sync.Mutex
	logFile *os.File
}

// Analyze packets for anomalies
func (pa *PacketAnalyzer) analyzePacket(packet gopacket.Packet) {
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		if len(payload) > 0 {
			payloadStr := string(payload)
			if len(payloadStr) > maxPayloadSize {
				pa.alert("Large payload detected!", payloadStr)
			}
		}
	}
}

// Alert and log messages
func (pa *PacketAnalyzer) alert(message, details string) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	alertMessage := fmt.Sprintf("%s\nDetails: %s\n\n", message, details)
	fmt.Print(alertMessage)
	if _, err := pa.logFile.WriteString(alertMessage); err != nil {
		log.Printf("Failed to write alert to log file: %v", err)
	}
}

// Initialize PacketAnalyzer and log file
func newPacketAnalyzer() (*PacketAnalyzer, error) {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &PacketAnalyzer{logFile: file}, nil
}

func main() {
	// Initialize PacketAnalyzer
	analyzer, err := newPacketAnalyzer()
	if err != nil {
		log.Fatal(err)
	}
	defer analyzer.logFile.Close()

	// Open the network device for packet capture
	handle, err := pcap.OpenLive(networkInterface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Starting packet capture...")

	var wg sync.WaitGroup
	packetChannel := make(chan gopacket.Packet, 1000) // Buffered channel for packets

	// Start packet processing in a separate goroutine
	go func() {
		for packet := range packetChannel {
			wg.Add(1)
			go func(pkt gopacket.Packet) {
				defer wg.Done()
				analyzer.analyzePacket(pkt)
			}(packet)
		}
	}()

	// Capture packets and send them to the channel
	for packet := range packetSource.Packets() {
		packetChannel <- packet
	}

	// Close the channel and wait for all goroutines to finish
	close(packetChannel)
	wg.Wait()
}
