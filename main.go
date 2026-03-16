package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"unicode/utf16"

	"github.com/Azure/go-ntlmssp" // Cross-platform NTLM including Mac
)

var (
	listenAddr  = flag.String("listen", ":1433", "Address to listen on")
	remoteAddr  = flag.String("remote", "", "Remote SQL Server address (host:port)")
	verbose     = flag.Bool("v", false, "Verbose logging")
)

func main() {
	flag.Parse()

	if *remoteAddr == "" {
		log.Fatal("Must specify -remote flag with SQL Server address")
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *listenAddr, err)
	}
	defer ln.Close()

	log.Printf("SQL NTLM Relay listening on %s, proxying to %s", *listenAddr, *remoteAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	remoteConn, err := net.Dial("tcp", *remoteAddr)
	if err != nil {
		log.Printf("Failed to connect to remote %s: %v", *remoteAddr, err)
		return
	}
	defer remoteConn.Close()

	if *verbose {
		log.Printf("Connected to remote server %s", *remoteAddr)
	}

	// Phase 1: Handle pre-login with both sides
	clientPreLogin, err := readTDSPacket(clientConn)
	if err != nil {
		log.Printf("Failed to read client pre-login: %v", err)
		return
	}

	if *verbose {
		log.Printf("Received client pre-login (%d bytes)", len(clientPreLogin))
	}

	// Forward pre-login to server
	if _, err := remoteConn.Write(clientPreLogin); err != nil {
		log.Printf("Failed to send pre-login to server: %v", err)
		return
	}

	// Read server's pre-login response
	serverPreLogin, err := readTDSPacket(remoteConn)
	if err != nil {
		log.Printf("Failed to read server pre-login: %v", err)
		return
	}

	if *verbose {
		log.Printf("Received server pre-login response (%d bytes)", len(serverPreLogin))
	}

	// Forward to client
	if _, err := clientConn.Write(serverPreLogin); err != nil {
		log.Printf("Failed to send pre-login to client: %v", err)
		return
	}

	// Phase 2: Read client's login packet to extract credentials
	loginPacket, err := readTDSPacket(clientConn)
	if err != nil {
		log.Printf("Failed to read client login: %v", err)
		return
	}

	credentials, err := parseLoginPacket(loginPacket)
	if err != nil {
		log.Printf("Failed to parse login packet: %v", err)
		return
	}

	log.Printf("Received credentials: %s\\%s", credentials.Domain, credentials.Username)

	// Phase 3: Perform NTLM authentication with remote server
	if err := performNTLMAuth(remoteConn, credentials); err != nil {
		log.Printf("NTLM authentication failed: %v", err)
		return
	}

	log.Printf("NTLM authentication successful for %s\\%s", credentials.Domain, credentials.Username)

	// Phase 4: Send login success to client
	if err := sendLoginAck(clientConn); err != nil {
		log.Printf("Failed to send login ack: %v", err)
		return
	}

	// Phase 5: Relay all subsequent traffic
	log.Printf("Starting bidirectional relay")
	go relay(remoteConn, clientConn, "server->client")
	relay(clientConn, remoteConn, "client->server")
}

type Credentials struct {
	Domain   string
	Username string
	Password string
}

func parseLoginPacket(data []byte) (*Credentials, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet too short")
	}

	// Check if it's a TDS login packet (type 0x10)
	if data[0] != 0x10 {
		return nil, fmt.Errorf("not a login packet, type=%02x", data[0])
	}

	// Skip TDS header (8 bytes)
	loginData := data[8:]

	// Login packet structure has offsets at fixed positions
	// See TDS specification for LOGIN7 structure
	if len(loginData) < 86 {
		return nil, fmt.Errorf("login data too short")
	}

	// Offset and length fields are at these positions (2 bytes each):
	// Hostname: offset 28, length 30
	// Username: offset 40, length 42
	// Password: offset 46, length 48
	// AppName: offset 52, length 54
	// ServerName: offset 58, length 60
	readField := func(offsetPos, lengthPos int) (string, error) {
		if len(loginData) < lengthPos+2 {
			return "", nil
		}
		offset := binary.LittleEndian.Uint16(loginData[offsetPos : offsetPos+2])
		length := binary.LittleEndian.Uint16(loginData[lengthPos : lengthPos+2])

		// Length is in characters, each char is 2 bytes (UTF-16LE)
		end := int(offset) + int(length)*2
		if end > len(loginData) {
			return "", nil
		}
		field := decodeUTF16LE(loginData[offset:end])
		return field, nil
	}

	username, err := readField(40, 42)
	if err != nil {
		return nil, err
	}
	password, err := readField(46, 48)
	if err != nil {
		return nil, err
	}

	// Parse domain\username format
	domain := ""
	user := username
	if parts := strings.SplitN(username, "\\", 2); len(parts) == 2 {
		domain = parts[0]
		user = parts[1]
	}

	return &Credentials{
		Domain:   domain,
		Username: user,
		Password: password,
	}, nil
}

func decodeUTF16LE(data []byte) string {
	result := make([]uint16, len(data)/2)
	for i := range result {
		result[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}
	return strings.ReplaceAll(string(utf16.Decode(result)), "\x00", "")
}

func readTDSPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// TDS packet length is at offset 2-3 (big endian)
	length := int(binary.BigEndian.Uint16(header[2:4]))

	// Allocate full packet
	packet := make([]byte, length)
	copy(packet, header)

	// Read remaining data
	if _, err := io.ReadFull(conn, packet[8:]); err != nil {
		return nil, err
	}

	return packet, nil
}

func performNTLMAuth(conn net.Conn, creds *Credentials) error {
	// Send NTLM Type 1 (Negotiate)
	negotiate, err := ntlmssp.NewNegotiateMessage(creds.Domain, "")
	if err != nil {
		return fmt.Errorf("failed to create negotiate message: %w", err)
	}

	// Build TDS login packet with NTLM Type 1
	loginWithNTLM1 := buildNTLMLoginPacket(negotiate)
	if _, err := conn.Write(loginWithNTLM1); err != nil {
		return fmt.Errorf("failed to send negotiate: %w", err)
	}

	if *verbose {
		log.Printf("Sent NTLM Type 1 (%d bytes)", len(negotiate))
	}

	// Read NTLM Type 2 (Challenge) from server
	type2Packet, err := readTDSPacket(conn)
	if err != nil {
		return fmt.Errorf("failed to read challenge: %w", err)
	}

	// Extract Type 2 message from the packet
	type2Msg, err := extractSSPI(type2Packet)
	if err != nil {
		return fmt.Errorf("failed to extract challenge: %w", err)
	}

	if *verbose {
		log.Printf("Received NTLM Type 2 (%d bytes)", len(type2Msg))
	}

	// Create NTLM Type 3 (Authenticate)
	authenticate, err := ntlmssp.ProcessChallenge(type2Msg, creds.Username, creds.Password, true)
	if err != nil {
		return fmt.Errorf("failed to process challenge: %w", err)
	}

	// Send NTLM Type 3
	loginWithNTLM3 := buildNTLMLoginPacket(authenticate)
	if _, err := conn.Write(loginWithNTLM3); err != nil {
		return fmt.Errorf("failed to send authenticate: %w", err)
	}

	if *verbose {
		log.Printf("Sent NTLM Type 3 (%d bytes)", len(authenticate))
	}

	// Read the response
	response, err := readTDSPacket(conn)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	// Check if it's a login ack (type 0x04) or error (0x02)
	if response[0] == 0x02 {
		return fmt.Errorf("authentication rejected by server")
	}

	return nil
}

func buildNTLMLoginPacket(sspi []byte) []byte {
	// Build a minimal TDS login packet with SSPI data
	// This is a simplified version - real implementation needs proper offsets

	// Fixed header for login packet
	packet := make([]byte, 0)

	// TDS Header
	packet = append(packet, 0x10)                 // Type: TDS7 Login
	packet = append(packet, 0x01)                 // Status: End of message
	packet = append(packet, 0x00, 0x00)           // Length (will be filled)
	packet = append(packet, 0x00, 0x00)           // SPID
	packet = append(packet, 0x00)                 // Packet ID
	packet = append(packet, 0x00)                 // Window

	// Build login7 structure
	login := make([]byte, 86+4) // Base size + SSPI field
	binary.LittleEndian.PutUint32(login[0:4], uint32(0x71000001)) // Length

	// Set SSPI offset and length (offset 78, length 80)
	sspiOffset := uint16(len(login) - 4) // Offset to SSPI data
	binary.LittleEndian.PutUint16(login[78:80], sspiOffset)
	binary.LittleEndian.PutUint16(login[80:82], uint16(len(sspi)))

	// Append SSPI data
	login = append(login, sspi...)

	// Update total length
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)+len(login)))

	return append(packet, login...)
}

func extractSSPI(packet []byte) ([]byte, error) {
	if len(packet) < 8 {
		return nil, fmt.Errorf("packet too short")
	}

	// Skip header
	data := packet[8:]

	// Look for SSPI data based on offset in the packet
	// For a challenge response, SSPI data starts after some header bytes
	// This is simplified - actual parsing depends on token type

	// Check packet type
	if packet[0] == 0x04 { // Tabular Result
		// Parse tokens to find SSPI
		pos := 0
		for pos < len(data) {
			if pos >= len(data) {
				break
			}
			token := data[pos]
			pos++

			switch token {
			case 0xFD: // SSPI token
				if pos+1 >= len(data) {
					return nil, fmt.Errorf("malformed SSPI token")
				}
				length := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
				pos += 2
				if pos+length > len(data) {
					return nil, fmt.Errorf("SSPI data truncated")
				}
				return data[pos : pos+length], nil
			case 0xAA: // Done token
				break
			}
		}
	}

	return nil, fmt.Errorf("no SSPI data found in packet")
}

func sendLoginAck(conn net.Conn) error {
	// Send a login success packet to the client
	// This is a simplified TDS login ack

	packet := []byte{
		0x04,                   // Type: Tabular Result
		0x01,                   // Status: End of message
		0x00, 0x0B,             // Length
		0x00, 0x00,             // SPID
		0x00,                   // Packet ID
		0x00,                   // Window
		0xAA,                   // Environment change token
		0x01, 0x00,             // Length
		0x00,                   // Type
		0x00,                   // Done
	}

	_, err := conn.Write(packet)
	return err
}

func relay(dst, src net.Conn, direction string) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if err != io.EOF && *verbose {
				log.Printf("%s relay error: %v", direction, err)
			}
			return
		}

		if _, err := dst.Write(buf[:n]); err != nil {
			if *verbose {
				log.Printf("%s write error: %v", direction, err)
			}
			return
		}

		if *verbose {
			log.Printf("%s: relayed %d bytes", direction, n)
		}
	}
}
