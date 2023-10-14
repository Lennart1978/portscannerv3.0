package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// Portscanner struct holds the details for a port scanning operation
type Portscanner struct {
	Host         string  // Target host
	Port         int     // Current port to scan
	startPort    int     // Starting port to scan
	endPort      int     // Ending port to scan
	ports_open   int     // Number of open ports found
	totalPorts   int     // Total number of ports to scan
	portsScanned int     // Number of ports scanned so far
	portso       []int   // List of open ports
	scanningPort int     // actual port
	progress     float64 // Scanning progress percentage
	target       string  // Target host and port as a string
	mutex        sync.Mutex
}

// String returns the target host and current port as a string
func (p *Portscanner) String() string {
	return p.Host + ":" + strconv.Itoa(p.Port)
}

// Greet prints a welcome message
func (p *Portscanner) Greet() {
	fmt.Println("\033[34m✨Welcome to Lennart's Portscanner V3.5✨")
	fmt.Println("\033[34m⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛")
	fmt.Println("\033[0m")
}

// Scan performs a TCP scan on the current port and returns true if the port is open
func (p *Portscanner) Scan() bool {
	target := p.Host + ":" + strconv.Itoa(p.scanningPort)
	conn, err := net.DialTimeout("tcp", target, time.Millisecond*30)

	if err != nil {
		return false // Port is closed or another error occurred
	}
	defer conn.Close() // Ensure the connection is closed after the scan

	return true // Port is open
}

func (p *Portscanner) ScanPort(port int) bool {
	target := p.Host + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", target, time.Millisecond*200)

	if err != nil {
		return false // Port is closed or another error occurred
	}
	defer conn.Close() // Ensure the connection is closed after the scan

	return true // Port is open

}

// Print prints the current port if it is open
func (p *Portscanner) Print() {
	fmt.Printf("\033[1;42m --> Port: %d is open ! ", p.Port)
	fmt.Println("\033[0m")
}

// Pprogress updates and prints the scanning progress
func (p *Portscanner) Pprogress() {
	p.progress = float64(p.portsScanned) / float64(p.totalPorts) * 100
	fmt.Printf("\rProgress: %.2f%%⚡", p.progress) // Overwrite line
}

// Reset resets all fields of the Portscanner struct
func (p *Portscanner) Reset() {
	p.portsScanned = 0
	p.progress = 0
	p.portso = nil
	p.ports_open = 0
	p.portsScanned = 0
	p.scanningPort = 0
	p.Port = 0
	p.totalPorts = 0
	p.target = ""
	p.Host = ""
	p.startPort = 0
	p.endPort = 0
	p.progress = 0
}
