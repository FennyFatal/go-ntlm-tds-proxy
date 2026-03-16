package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
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

	// Listen on both IPv4 and IPv6 explicitly
	ln4, err := net.Listen("tcp4", *listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen (IPv4) on %s: %v", *listenAddr, err)
	}
	defer ln4.Close()

	ln6, err := net.Listen("tcp6", *listenAddr)
	if err != nil {
		log.Printf("Warning: could not listen on IPv6 %s: %v", *listenAddr, err)
		ln6 = nil
	} else {
		defer ln6.Close()
	}

	log.Printf("SQL NTLM Relay listening on %s (IPv4+IPv6), proxying to %s", *listenAddr, *remoteAddr)

	accept := func(ln net.Listener, tag string) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("[%s] Accept error: %v", tag, err)
				return
			}
			log.Printf("New connection from %s (%s)", conn.RemoteAddr(), tag)
			go handleConnection(conn)
		}
	}

	if ln6 != nil {
		go accept(ln6, "IPv6")
	}
	accept(ln4, "IPv4")
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	log.Printf("Dialing remote %s...", *remoteAddr)
	rawRemote, err := net.DialTimeout("tcp", *remoteAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to remote %s: %v", *remoteAddr, err)
		return
	}
	defer rawRemote.Close()

	if *verbose {
		log.Printf("Connected to remote server %s", *remoteAddr)
	}

	// Phase 1: Handle pre-login with both sides
	clientPreLogin, err := readTDSPacket(clientConn, "client-prelogin")
	if err != nil {
		log.Printf("Failed to read client pre-login: %v", err)
		return
	}

	if *verbose {
		log.Printf("Received client pre-login (%d bytes)", len(clientPreLogin))
	}

	// Forward client pre-login to server UNMODIFIED (server needs to see encryption support)
	if _, err := rawRemote.Write(clientPreLogin); err != nil {
		log.Printf("Failed to send pre-login to server: %v", err)
		return
	}

	// Read server's pre-login response
	serverPreLogin, err := readTDSPacket(rawRemote, "server-prelogin")
	if err != nil {
		log.Printf("Failed to read server pre-login: %v", err)
		return
	}

	if *verbose {
		log.Printf("Received server pre-login response (%d bytes)", len(serverPreLogin))
	}

	// Check server's encryption preference and establish TLS if needed
	serverEncrypt := getEncryptionByte(serverPreLogin)
	var serverConn net.Conn = rawRemote

	if serverEncrypt != 0x02 { // Anything other than ENCRYPT_NOT_SUP
		if *verbose {
			log.Printf("Server encryption=0x%02x, performing TLS handshake", serverEncrypt)
		}

		hsConn := &tdsHandshakeConn{conn: rawRemote}
		tlsConn := tls.Client(hsConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake with server failed: %v", err)
			return
		}
		hsConn.passthrough = true
		serverConn = tlsConn
		log.Printf("TLS established with server")
	}

	// Tell client encryption is not supported so it stays plaintext with us
	disableEncryption(serverPreLogin)
	if _, err := clientConn.Write(serverPreLogin); err != nil {
		log.Printf("Failed to send pre-login to client: %v", err)
		return
	}

	// Phase 2: Read client's login packet to extract credentials (plaintext)
	loginPacket, err := readTDSPacket(clientConn, "client-login")
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

	// Phase 3: Perform NTLM authentication with remote server (over TLS if applicable)
	if err := performNTLMAuth(serverConn, credentials); err != nil {
		log.Printf("NTLM authentication failed: %v", err)
		return
	}

	log.Printf("NTLM authentication successful for %s\\%s", credentials.Domain, credentials.Username)

	// Phase 4: Send login success to client
	if err := sendLoginAck(clientConn); err != nil {
		log.Printf("Failed to send login ack: %v", err)
		return
	}

	// Phase 5: Relay all subsequent traffic (plaintext client <-> TLS server)
	log.Printf("Starting bidirectional relay")
	go relay(serverConn, clientConn, "server->client")
	relay(clientConn, serverConn, "client->server")
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
	// Hostname: ibHostName=36, cchHostName=38
	// Username: ibUserName=40, cchUserName=42
	// Password: ibPassword=44, cchPassword=46
	// AppName: ibAppName=48, cchAppName=50
	// ServerName: ibServerName=52, cchServerName=54
	readRawField := func(offsetPos, lengthPos int) ([]byte, error) {
		if len(loginData) < lengthPos+2 {
			return nil, nil
		}
		offset := binary.LittleEndian.Uint16(loginData[offsetPos : offsetPos+2])
		length := binary.LittleEndian.Uint16(loginData[lengthPos : lengthPos+2])

		// Length is in characters, each char is 2 bytes (UTF-16LE)
		end := int(offset) + int(length)*2
		if end > len(loginData) {
			return nil, nil
		}
		return loginData[offset:end], nil
	}

	usernameRaw, err := readRawField(40, 42)
	if err != nil {
		return nil, err
	}
	username := decodeUTF16LE(usernameRaw)

	passwordRaw, err := readRawField(44, 46)
	if err != nil {
		return nil, err
	}
	// Decode TDS LOGIN7 password obfuscation before UTF-16LE decoding
	for i := range passwordRaw {
		b := passwordRaw[i] ^ 0xA5
		passwordRaw[i] = (b << 4) | (b >> 4)
	}
	password := decodeUTF16LE(passwordRaw)

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

// getEncryptionByte reads the ENCRYPTION option value from a PRELOGIN packet.
func getEncryptionByte(packet []byte) byte {
	if len(packet) < 8 {
		return 0x02
	}
	data := packet[8:]
	pos := 0
	for pos < len(data) {
		optType := data[pos]
		if optType == 0xFF {
			break
		}
		if pos+5 > len(data) {
			break
		}
		offset := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		if optType == 0x01 && offset < len(data) {
			return data[offset]
		}
		pos += 5
	}
	return 0x02
}

// tdsHandshakeConn wraps a net.Conn to add/strip TDS headers around TLS records
// during the TLS handshake phase. TDS embeds TLS within PRELOGIN (0x12) packets
// for the handshake; after completion, set passthrough=true for direct access.
type tdsHandshakeConn struct {
	conn        net.Conn
	readBuf     []byte
	passthrough bool
}

func (c *tdsHandshakeConn) Read(b []byte) (int, error) {
	// Drain buffered data first (from previous partial TDS payload read)
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	if c.passthrough {
		return c.conn.Read(b)
	}

	// Read and strip TDS header
	header := make([]byte, 8)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return 0, err
	}

	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 8 {
		return 0, fmt.Errorf("tdsHandshakeConn: invalid TDS length %d", length)
	}

	payload := make([]byte, length-8)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return 0, err
	}

	n := copy(b, payload)
	if n < len(payload) {
		c.readBuf = payload[n:]
	}
	return n, nil
}

func (c *tdsHandshakeConn) Write(b []byte) (int, error) {
	if c.passthrough {
		return c.conn.Write(b)
	}

	// Wrap in TDS PRELOGIN packet
	packet := make([]byte, 8+len(b))
	packet[0] = 0x12 // PRELOGIN
	packet[1] = 0x01 // EOM
	binary.BigEndian.PutUint16(packet[2:4], uint16(8+len(b)))
	copy(packet[8:], b)

	_, err := c.conn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *tdsHandshakeConn) Close() error                       { return c.conn.Close() }
func (c *tdsHandshakeConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *tdsHandshakeConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *tdsHandshakeConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *tdsHandshakeConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *tdsHandshakeConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// disableEncryption patches the ENCRYPTION option in a TDS PRELOGIN packet
// to ENCRYPT_NOT_SUP (0x02), preventing TLS negotiation that the relay can't handle.
func disableEncryption(packet []byte) {
	if len(packet) < 8 {
		return
	}
	data := packet[8:] // skip TDS header
	pos := 0
	for pos < len(data) {
		optType := data[pos]
		if optType == 0xFF { // terminator
			break
		}
		if pos+5 > len(data) {
			break
		}
		offset := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		// length at data[pos+3:pos+5]

		if optType == 0x01 { // ENCRYPTION option
			if offset < len(data) {
				if *verbose {
					log.Printf("Patching ENCRYPTION option from 0x%02x to 0x02 (ENCRYPT_NOT_SUP)", data[offset])
				}
				data[offset] = 0x02 // ENCRYPT_NOT_SUP
			}
			return
		}
		pos += 5
	}
}

func readTDSPacket(conn net.Conn, label string) ([]byte, error) {
	if *verbose {
		log.Printf("[%s] waiting for TDS packet...", label)
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	pktType := header[0]
	length := int(binary.BigEndian.Uint16(header[2:4]))

	if *verbose {
		log.Printf("[%s] header: type=0x%02x status=0x%02x length=%d", label, pktType, header[1], length)
		log.Printf("[%s] raw header: %s", label, hex.EncodeToString(header))
	}

	if length < 8 {
		return nil, fmt.Errorf("invalid TDS packet length %d (< 8)", length)
	}

	// Allocate full packet
	packet := make([]byte, length)
	copy(packet, header)

	// Read remaining data
	if _, err := io.ReadFull(conn, packet[8:]); err != nil {
		return nil, fmt.Errorf("reading body (%d bytes): %w", length-8, err)
	}

	if *verbose {
		log.Printf("[%s] read complete: %d bytes total", label, length)
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
	type2Packet, err := readTDSPacket(conn, "server-ntlm-type2")
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

	// Send NTLM Type 3 as SSPI message (type 0x11, not LOGIN7)
	sspiPacket := buildSSPIPacket(authenticate)
	if _, err := conn.Write(sspiPacket); err != nil {
		return fmt.Errorf("failed to send authenticate: %w", err)
	}

	if *verbose {
		log.Printf("Sent NTLM Type 3 (%d bytes)", len(authenticate))
	}

	// Read the response
	response, err := readTDSPacket(conn, "server-auth-response")
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
	// Build a TDS LOGIN7 packet with SSPI data for NTLM Type 1 (Negotiate)
	const fixedSize = 86

	login := make([]byte, fixedSize)

	// TDS Version at offset 4 (TDS 7.4)
	binary.LittleEndian.PutUint32(login[4:8], 0x74000004)

	// PacketSize at offset 8
	binary.LittleEndian.PutUint32(login[8:12], 4096)

	// OptionFlags2 at offset 25: set fIntSecurity (0x80) for NTLM/SSPI
	login[25] = 0x80

	// Point all variable-length field offsets to the start of the variable data
	// area (right after the fixed header). All lengths are 0 (empty fields).
	// Offsets: ibHostName=36, ibUserName=40, ibPassword=44, ibAppName=48,
	//          ibServerName=52, ibExtension=56, ibCltIntName=60,
	//          ibLanguage=64, ibDatabase=68, ibAtchDBFile=82
	for _, off := range []int{36, 40, 44, 48, 52, 56, 60, 64, 68, 82} {
		binary.LittleEndian.PutUint16(login[off:off+2], uint16(fixedSize))
	}

	// SSPI offset and length (ibSSPI at 78, cbSSPI at 80)
	binary.LittleEndian.PutUint16(login[78:80], uint16(fixedSize))
	binary.LittleEndian.PutUint16(login[80:82], uint16(len(sspi)))

	// Append SSPI data to login record
	login = append(login, sspi...)

	// Set LOGIN7 total length at offset 0
	binary.LittleEndian.PutUint32(login[0:4], uint32(len(login)))

	// Build TDS packet header
	packet := make([]byte, 8)
	packet[0] = 0x10 // Type: TDS7 Login
	packet[1] = 0x01 // Status: End of message
	binary.BigEndian.PutUint16(packet[2:4], uint16(8+len(login)))

	return append(packet, login...)
}

// buildSSPIPacket wraps an NTLM Type 3 (Authenticate) message in a TDS SSPI
// packet (type 0x11). This is distinct from the LOGIN7 used for Type 1.
func buildSSPIPacket(sspi []byte) []byte {
	packet := make([]byte, 8+len(sspi))
	packet[0] = 0x11 // Type: SSPI Message
	packet[1] = 0x01 // Status: End of message
	binary.BigEndian.PutUint16(packet[2:4], uint16(8+len(sspi)))
	copy(packet[8:], sspi)
	return packet
}

func extractSSPI(packet []byte) ([]byte, error) {
	if len(packet) < 8 {
		return nil, fmt.Errorf("packet too short")
	}

	// Skip TDS header
	data := packet[8:]

	// Check packet type - server login response is Tabular Result (0x04)
	if packet[0] != 0x04 {
		return nil, fmt.Errorf("unexpected packet type 0x%02x, expected 0x04", packet[0])
	}

	// Parse TDS tokens to find SSPI (0xED)
	pos := 0
	for pos < len(data) {
		token := data[pos]
		pos++

		switch token {
		case 0xED: // SSPI token
			if pos+2 > len(data) {
				return nil, fmt.Errorf("malformed SSPI token")
			}
			length := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			pos += 2
			if pos+length > len(data) {
				return nil, fmt.Errorf("SSPI data truncated")
			}
			return data[pos : pos+length], nil
		case 0xFD, 0xFE, 0xFF: // DONE / DONEPROC / DONEINPROC
			// Reached end-of-message tokens without finding SSPI
			return nil, fmt.Errorf("no SSPI data found (reached DONE token)")
		default:
			// Skip unknown tokens by reading their 2-byte length prefix
			if pos+2 > len(data) {
				return nil, fmt.Errorf("unexpected end of data at token 0x%02x", token)
			}
			tlen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			pos += 2 + tlen
		}
	}

	return nil, fmt.Errorf("no SSPI data found in packet")
}

func sendLoginAck(conn net.Conn) error {
	// Build TDS response body with LOGINACK + DONE tokens
	var body []byte

	// LOGINACK token (0xAD)
	ackData := []byte{
		0x01,                   // Interface: SQL_TSQL
		0x71, 0x00, 0x00, 0x01, // TDS Version 7.1
	}
	// Program name "Relay" as length-prefixed UTF-16LE
	progName := utf16LEEncode("Relay")
	ackData = append(ackData, byte(len(progName)/2)) // length in chars
	ackData = append(ackData, progName...)
	// Program version (major.minor.buildHi.buildLo)
	ackData = append(ackData, 0x01, 0x00, 0x00, 0x00)

	body = append(body, 0xAD) // LOGINACK token type
	lenBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBytes, uint16(len(ackData)))
	body = append(body, lenBytes...)
	body = append(body, ackData...)

	// DONE token (0xFD)
	body = append(body,
		0xFD,
		0x00, 0x00, // Status: DONE_FINAL
		0x00, 0x00, // CurCmd
		0x00, 0x00, 0x00, 0x00, // DoneRowCount (4 bytes for TDS 7.1)
	)

	// Build TDS packet header
	packet := make([]byte, 8)
	packet[0] = 0x04 // Type: Tabular Result
	packet[1] = 0x01 // Status: End of message
	binary.BigEndian.PutUint16(packet[2:4], uint16(8+len(body)))

	packet = append(packet, body...)
	_, err := conn.Write(packet)
	return err
}

func utf16LEEncode(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
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
