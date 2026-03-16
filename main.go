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
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/Azure/go-ntlmssp" // Cross-platform NTLM including Mac
)

var (
	listenAddr  = flag.String("listen", ":1433", "Address to listen on")
	remoteAddr  = flag.String("remote", "", "Remote SQL Server address (host:port)")
	verbose     = flag.Bool("v", false, "Verbose logging")
	connCounter uint64
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
			go handleConnection(conn)
		}
	}

	if ln6 != nil {
		go accept(ln6, "IPv6")
	}
	accept(ln4, "IPv4")
}

func handleConnection(clientConn net.Conn) {
	connID := atomic.AddUint64(&connCounter, 1)
	tag := fmt.Sprintf("conn#%d", connID)
	defer clientConn.Close()

	log.Printf("[%s] New connection from %s, dialing remote %s...", tag, clientConn.RemoteAddr(), *remoteAddr)
	rawRemote, err := net.DialTimeout("tcp", *remoteAddr, 10*time.Second)
	if err != nil {
		log.Printf("[%s] Failed to connect to remote %s: %v", tag, *remoteAddr, err)
		return
	}
	defer rawRemote.Close()

	if *verbose {
		log.Printf("[%s] Connected to remote server %s", tag, *remoteAddr)
	}

	// Phase 1: Handle pre-login with both sides
	clientPreLogin, err := readTDSPacket(clientConn, tag+"/client-prelogin")
	if err != nil {
		log.Printf("[%s] Failed to read client pre-login: %v", tag, err)
		return
	}

	if *verbose {
		log.Printf("[%s] Received client pre-login (%d bytes)", tag, len(clientPreLogin))
	}

	// Disable MARS in client's PRELOGIN before forwarding to server.
	// If MARS is enabled on the server but not the client (because we sit in between),
	// the server would use SMUX framing that the client doesn't expect.
	// By disabling it on both sides, we avoid any framing mismatch.
	disableMARS(clientPreLogin)

	if _, err := rawRemote.Write(clientPreLogin); err != nil {
		log.Printf("[%s] Failed to send pre-login to server: %v", tag, err)
		return
	}

	// Read server's pre-login response
	serverPreLogin, err := readTDSPacket(rawRemote, tag+"/server-prelogin")
	if err != nil {
		log.Printf("[%s] Failed to read server pre-login: %v", tag, err)
		return
	}

	if *verbose {
		log.Printf("[%s] Received server pre-login response (%d bytes)", tag, len(serverPreLogin))
	}

	// Check server's encryption preference and establish TLS if needed
	serverEncrypt := getEncryptionByte(serverPreLogin)
	var serverConn net.Conn = rawRemote

	if serverEncrypt != 0x02 { // Anything other than ENCRYPT_NOT_SUP
		if *verbose {
			log.Printf("[%s] Server encryption=0x%02x, performing TLS handshake", tag, serverEncrypt)
		}

		hsConn := &tdsHandshakeConn{conn: rawRemote}
		tlsConn := tls.Client(hsConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[%s] TLS handshake with server failed: %v", tag, err)
			return
		}
		hsConn.passthrough = true
		serverConn = tlsConn
		log.Printf("[%s] TLS established with server", tag)
	}

	// Tell client encryption and MARS are not supported so it stays plaintext
	// and doesn't expect SMUX framing
	disableEncryption(serverPreLogin)
	disableMARS(serverPreLogin)
	if _, err := clientConn.Write(serverPreLogin); err != nil {
		log.Printf("[%s] Failed to send pre-login to client: %v", tag, err)
		return
	}

	// Phase 2: Read client's login packet to extract credentials (plaintext)
	loginPacket, err := readTDSPacket(clientConn, tag+"/client-login")
	if err != nil {
		log.Printf("[%s] Failed to read client login: %v", tag, err)
		return
	}

	credentials, err := parseLoginPacket(loginPacket)
	if err != nil {
		log.Printf("[%s] Failed to parse login packet: %v", tag, err)
		return
	}

	log.Printf("[%s] Received credentials: %s\\%s", tag, credentials.Domain, credentials.Username)

	// Phase 3: Perform NTLM authentication with remote server (over TLS if applicable)
	authResponse, err := performNTLMAuth(serverConn, credentials, loginPacket, tag)
	if err != nil {
		log.Printf("[%s] NTLM authentication failed: %v", tag, err)
		return
	}

	log.Printf("[%s] NTLM authentication successful for %s\\%s", tag, credentials.Domain, credentials.Username)

	// Phase 4: Forward the server's real login response to the client
	// (contains correct TDS version, env changes, collation, etc.)
	if _, err := clientConn.Write(authResponse); err != nil {
		log.Printf("[%s] Failed to forward login response to client: %v", tag, err)
		return
	}

	// Phase 5: Relay all subsequent traffic (plaintext client <-> TLS server)
	log.Printf("[%s] Starting bidirectional relay", tag)
	var closing atomic.Bool
	done := make(chan struct{})
	go func() {
		relay(clientConn, serverConn, tag+"/server->client", &closing)
		closing.Store(true)
		clientConn.Close()
		close(done)
	}()
	relay(serverConn, clientConn, tag+"/client->server", &closing)
	closing.Store(true)
	serverConn.Close()
	<-done
	log.Printf("[%s] Connection closed", tag)
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

	// Username: ibUserName=40, cchUserName=42
	// Password: ibPassword=44, cchPassword=46
	readRawField := func(offsetPos, lengthPos int) ([]byte, error) {
		if len(loginData) < lengthPos+2 {
			return nil, fmt.Errorf("login data too short for field at %d", lengthPos)
		}
		offset := binary.LittleEndian.Uint16(loginData[offsetPos : offsetPos+2])
		length := binary.LittleEndian.Uint16(loginData[lengthPos : lengthPos+2])

		// Length is in characters, each char is 2 bytes (UTF-16LE)
		end := int(offset) + int(length)*2
		if end > len(loginData) {
			return nil, fmt.Errorf("field extends past end of login data")
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

// disableMARS patches the MARS option in a TDS PRELOGIN packet to disabled (0x00).
// MARS (Multiple Active Result Sets) causes the server to use SMUX framing for all
// post-login data, which breaks the relay since the client doesn't expect it.
func disableMARS(packet []byte) {
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

		if optType == 0x04 { // MARS option
			if offset < len(data) {
				if *verbose && data[offset] != 0x00 {
					log.Printf("Patching MARS option from 0x%02x to 0x00 (disabled)", data[offset])
				}
				data[offset] = 0x00 // MARS disabled
			}
			return
		}
		pos += 5
	}
}

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

// performNTLMAuth performs NTLM authentication with the server and returns
// the server's final auth response (LOGINACK + env changes) to forward to the client.
func performNTLMAuth(conn net.Conn, creds *Credentials, loginPacket []byte, tag string) ([]byte, error) {
	// Send NTLM Type 1 (Negotiate)
	negotiate, err := ntlmssp.NewNegotiateMessage(creds.Domain, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create negotiate message: %w", err)
	}

	// Build TDS login packet with NTLM Type 1, modifying client's original LOGIN7
	loginWithNTLM1 := buildNTLMLoginPacket(negotiate, loginPacket)
	if _, err := conn.Write(loginWithNTLM1); err != nil {
		return nil, fmt.Errorf("failed to send negotiate: %w", err)
	}

	if *verbose {
		log.Printf("[%s] Sent NTLM Type 1 (%d bytes)", tag, len(negotiate))
	}

	// Read NTLM Type 2 (Challenge) from server
	type2Packet, err := readTDSPacket(conn, tag+"/server-ntlm-type2")
	if err != nil {
		return nil, fmt.Errorf("failed to read challenge: %w", err)
	}

	// Extract Type 2 message from the packet
	type2Msg, err := extractSSPI(type2Packet)
	if err != nil {
		return nil, fmt.Errorf("failed to extract challenge: %w", err)
	}

	if *verbose {
		log.Printf("[%s] Received NTLM Type 2 (%d bytes)", tag, len(type2Msg))
	}

	// Create NTLM Type 3 (Authenticate)
	authenticate, err := ntlmssp.ProcessChallenge(type2Msg, creds.Username, creds.Password, true)
	if err != nil {
		return nil, fmt.Errorf("failed to process challenge: %w", err)
	}

	// Send NTLM Type 3 as SSPI message (type 0x11, not LOGIN7)
	sspiPacket := buildSSPIPacket(authenticate)
	if _, err := conn.Write(sspiPacket); err != nil {
		return nil, fmt.Errorf("failed to send authenticate: %w", err)
	}

	if *verbose {
		log.Printf("[%s] Sent NTLM Type 3 (%d bytes)", tag, len(authenticate))
	}

	// Read ALL packets of the server's auth response until EOM
	// (LOGINACK + env changes + DONE may span multiple TDS packets)
	var fullResponse []byte
	for {
		packet, err := readTDSPacket(conn, tag+"/server-auth-response")
		if err != nil {
			return nil, fmt.Errorf("failed to read auth response: %w", err)
		}

		// First packet must be a tabular result (0x04)
		if len(fullResponse) == 0 && packet[0] != 0x04 {
			return nil, fmt.Errorf("authentication rejected by server (packet type 0x%02x)", packet[0])
		}

		fullResponse = append(fullResponse, packet...)

		// Check EOM flag (status byte, bit 0)
		if packet[1]&0x01 != 0 {
			break
		}
	}

	if *verbose {
		log.Printf("[%s] Auth response: %d bytes total", tag, len(fullResponse))
	}

	return fullResponse, nil
}

func buildNTLMLoginPacket(sspi []byte, originalPacket []byte) []byte {
	// Modify the client's original LOGIN7 packet in place to use NTLM SSPI
	// instead of rebuilding from scratch. This preserves the exact header
	// structure for whatever TDS version the client is using.

	// Copy the original packet so we don't modify the input
	login := make([]byte, len(originalPacket))
	copy(login, originalPacket)

	// Skip TDS header (8 bytes), work with LOGIN7 data
	loginData := login[8:]

	if len(loginData) < 86 {
		return nil
	}

	// Clear username and password by zeroing their character counts
	// cchUserName at offset 42, cchPassword at offset 46
	binary.LittleEndian.PutUint16(loginData[42:44], 0)
	binary.LittleEndian.PutUint16(loginData[46:48], 0)

	// Set fIntSecurity flag (bit 7 of OptionFlags2 at offset 25)
	loginData[25] |= 0x80

	// Get the current end of data (ibChangePassword points to end)
	oldEnd := binary.LittleEndian.Uint16(loginData[86:88])

	// Append SSPI after existing data
	newLogin := make([]byte, len(login)+len(sspi))
	copy(newLogin, login)
	copy(newLogin[len(login):], sspi)
	newLoginData := newLogin[8:]

	// Update SSPI offset (ibSSPI at 78) and length (cbSSPI at 80)
	binary.LittleEndian.PutUint16(newLoginData[78:80], uint16(oldEnd))
	binary.LittleEndian.PutUint16(newLoginData[80:82], uint16(len(sspi)))

	// Update ibAtchDBFile (82) and ibChangePassword (86) to account for SSPI
	binary.LittleEndian.PutUint16(newLoginData[82:84], uint16(oldEnd)+uint16(len(sspi)))
	binary.LittleEndian.PutUint16(newLoginData[86:88], uint16(oldEnd)+uint16(len(sspi)))

	// Update LOGIN7 total length at offset 0
	newLoginLen := uint32(len(newLoginData))
	binary.LittleEndian.PutUint32(newLoginData[0:4], newLoginLen)

	// Update TDS packet length in header
	binary.BigEndian.PutUint16(newLogin[2:4], uint16(len(newLogin)))

	return newLogin
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

func relay(dst, src net.Conn, direction string, closing *atomic.Bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if *verbose {
				introspectRead(direction, buf[:n])
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				if closing.Load() {
					if *verbose {
						log.Printf("%s: closing (%v)", direction, writeErr)
					}
				} else {
					log.Printf("%s write error: %v", direction, writeErr)
				}
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				if *verbose {
					log.Printf("%s: EOF", direction)
				}
			} else if closing.Load() {
				// Expected error from the other direction shutting down
				if *verbose {
					log.Printf("%s: closing (%v)", direction, err)
				}
			} else {
				log.Printf("%s read error: %v", direction, err)
			}
			return
		}
	}
}

func introspectRead(direction string, data []byte) {
	log.Printf("%s: %d bytes total", direction, len(data))

	// Walk all TDS packets in this read
	offset := 0
	pktNum := 0
	for offset+8 <= len(data) {
		pktNum++
		pktType := data[offset]
		pktStatus := data[offset+1]
		pktLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		typeName := tdsPacketTypeName(pktType)

		statusFlags := ""
		if pktStatus&0x01 != 0 {
			statusFlags += "EOM "
		}
		if pktStatus&0x02 != 0 {
			statusFlags += "IGNORE "
		}
		if pktStatus&0x04 != 0 {
			statusFlags += "RESETCONN "
		}
		if pktStatus&0x08 != 0 {
			statusFlags += "RESETCONNSKIPTRAN "
		}
		if statusFlags == "" {
			statusFlags = "none"
		}

		log.Printf("%s:   pkt#%d @%d: type=0x%02x(%s) status=0x%02x(%s) len=%d",
			direction, pktNum, offset, pktType, typeName, pktStatus, statusFlags, pktLen)

		// Introspect tokens in TabularResult packets
		if pktType == 0x04 {
			end := offset + pktLen
			if end > len(data) {
				end = len(data)
			}
			if offset+8 < end {
				introspectTokens(direction, data[offset+8:end])
			}
		}

		if pktLen < 8 {
			log.Printf("%s:   pkt#%d: INVALID len=%d, stopping introspection", direction, pktNum, pktLen)
			break
		}
		offset += pktLen
	}

	if remainder := len(data) - offset; remainder > 0 {
		log.Printf("%s:   %d trailing bytes (partial next packet)", direction, remainder)
	}
}

func introspectTokens(direction string, data []byte) {
	pos := 0
	for pos < len(data) {
		token := data[pos]
		name := tdsTokenName(token)
		pos++

		switch {
		case token == 0x81: // COLMETADATA - complex variable-length, can't parse without full spec
			log.Printf("%s:     token %s (remaining %d bytes unparsed)", direction, name, len(data)-pos)
			return
		case token == 0xD1, token == 0xD3: // ROW / NBCROW - depends on COLMETADATA column defs
			log.Printf("%s:     token %s (remaining %d bytes unparsed)", direction, name, len(data)-pos)
			return
		case token == 0xAA: // ERROR token
			if pos+2 > len(data) {
				return
			}
			tlen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			pos += 2
			if pos+4 <= len(data) {
				errNum := binary.LittleEndian.Uint32(data[pos : pos+4])
				log.Printf("%s:     token %s: errno=%d", direction, name, errNum)
			}
			pos += tlen
		case token == 0xAB: // INFO token
			if pos+2 > len(data) {
				return
			}
			tlen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			pos += 2
			if pos+4 <= len(data) {
				infoNum := binary.LittleEndian.Uint32(data[pos : pos+4])
				log.Printf("%s:     token %s: msgno=%d", direction, name, infoNum)
			}
			pos += tlen
		case token == 0xAD: // LOGINACK
			if pos+2 > len(data) {
				return
			}
			tlen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			log.Printf("%s:     token %s", direction, name)
			pos += 2 + tlen
		case token == 0xE3: // ENVCHANGE
			if pos+2 > len(data) {
				return
			}
			tlen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			envType := byte(0)
			if pos+2 < len(data) {
				envType = data[pos+2]
			}
			log.Printf("%s:     token %s: type=%d", direction, name, envType)
			pos += 2 + tlen
		case token == 0xFD || token == 0xFE || token == 0xFF: // DONE tokens
			if pos+8 <= len(data) {
				status := binary.LittleEndian.Uint16(data[pos : pos+2])
				log.Printf("%s:     token %s: status=0x%04x", direction, name, status)
			}
			pos += 12 // status(2) + curcmd(2) + rowcount(8) for TDS 7.2+
		default:
			// Variable-length token: try to read 2-byte length and skip
			if pos+2 > len(data) {
				log.Printf("%s:     token %s (0x%02x) at end", direction, name, token)
				return
			}
			tlen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
			log.Printf("%s:     token %s (0x%02x) len=%d", direction, name, token, tlen)
			pos += 2 + tlen
		}

		if pos < 0 || pos > len(data) {
			return
		}
	}
}

func tdsPacketTypeName(t byte) string {
	switch t {
	case 0x01:
		return "SQLBatch"
	case 0x02:
		return "PreTDS7Login"
	case 0x03:
		return "RPC"
	case 0x04:
		return "TabularResult"
	case 0x06:
		return "Attention"
	case 0x07:
		return "BulkLoad"
	case 0x0E:
		return "TransMgr"
	case 0x10:
		return "Login7"
	case 0x11:
		return "SSPI"
	case 0x12:
		return "PreLogin"
	default:
		return "Unknown"
	}
}

func tdsTokenName(t byte) string {
	switch t {
	case 0x81:
		return "COLMETADATA"
	case 0xA4:
		return "ORDER"
	case 0xA5:
		return "ERROR_OLD"
	case 0xAA:
		return "ERROR"
	case 0xAB:
		return "INFO"
	case 0xAD:
		return "LOGINACK"
	case 0xD1:
		return "ROW"
	case 0xD3:
		return "NBCROW"
	case 0xE3:
		return "ENVCHANGE"
	case 0xE5:
		return "EED"
	case 0xED:
		return "SSPI"
	case 0xFD:
		return "DONE"
	case 0xFE:
		return "DONEPROC"
	case 0xFF:
		return "DONEINPROC"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", t)
	}
}
