package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
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
	relayCert   tls.Certificate
)

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "SQL Server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func main() {
	flag.Parse()

	if *remoteAddr == "" {
		log.Fatal("Must specify -remote flag with SQL Server address")
	}

	var err error
	relayCert, err = generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
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

	// Forward client's PRELOGIN to server as-is (MARS negotiation left intact)
	// disableMARS(clientPreLogin)

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
	var clientDataConn net.Conn = clientConn // the connection we read/write data from after handshake

	if serverEncrypt != 0x02 { // Anything other than ENCRYPT_NOT_SUP
		if *verbose {
			log.Printf("[%s] Server encryption=0x%02x, performing TLS handshake with server", tag, serverEncrypt)
		}

		// TLS handshake with server (client role, TDS-wrapped)
		serverHSConn := &tdsHandshakeConn{conn: rawRemote, writeType: 0x12}
		serverTLS := tls.Client(serverHSConn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := serverTLS.Handshake(); err != nil {
			log.Printf("[%s] TLS handshake with server failed: %v", tag, err)
			return
		}
		serverHSConn.passthrough = true
		serverConn = serverTLS
		log.Printf("[%s] TLS established with server", tag)

		// Forward server's PRELOGIN to client UNCHANGED (encryption stays enabled)
		if _, err := clientConn.Write(serverPreLogin); err != nil {
			log.Printf("[%s] Failed to send pre-login to client: %v", tag, err)
			return
		}

		// TLS handshake with client (server role, TDS-wrapped)
		// Client sends TLS in type 0x12, we respond with type 0x04
		clientHSConn := &tdsHandshakeConn{conn: clientConn, writeType: 0x04}
		clientTLS := tls.Server(clientHSConn, &tls.Config{
			Certificates: []tls.Certificate{relayCert},
		})
		if err := clientTLS.Handshake(); err != nil {
			log.Printf("[%s] TLS handshake with client failed: %v", tag, err)
			return
		}
		clientHSConn.passthrough = true
		clientDataConn = clientTLS
		log.Printf("[%s] TLS established with client (MITM)", tag)
	} else {
		// No encryption — forward PRELOGIN as-is, stay plaintext
		if _, err := clientConn.Write(serverPreLogin); err != nil {
			log.Printf("[%s] Failed to send pre-login to client: %v", tag, err)
			return
		}
	}

	// Phase 2: Read client's login packet (over TLS if encryption active)
	loginPacket, err := readTDSPacket(clientDataConn, tag+"/client-login")
	if err != nil {
		log.Printf("[%s] Failed to read client login: %v", tag, err)
		return
	}

	credentials, loginFields, err := parseLoginPacket(loginPacket)
	if err != nil {
		log.Printf("[%s] Failed to parse login packet: %v", tag, err)
		return
	}

	// Override credentials from environment if client sends "use_env" as a sentinel
	if credentials.Username == "use_env" || (credentials.Domain != "" && credentials.Domain+"\\"+credentials.Username == "use_env") {
		envUser := os.Getenv("NTLM_USERNAME")
		if envUser == "" {
			log.Printf("[%s] Username is 'use_env' but NTLM_USERNAME is not set", tag)
			return
		}
		if parts := strings.SplitN(envUser, "\\", 2); len(parts) == 2 {
			credentials.Domain = parts[0]
			credentials.Username = parts[1]
		} else {
			credentials.Username = envUser
		}
	}
	if credentials.Password == "use_env" {
		envPass := os.Getenv("NTLM_PASSWORD")
		if envPass == "" {
			log.Printf("[%s] Password is 'use_env' but NTLM_PASSWORD is not set", tag)
			return
		}
		credentials.Password = envPass
	}

	log.Printf("[%s] Received credentials: %s\\%s (database=%q)", tag, credentials.Domain, credentials.Username, decodeUTF16LE(loginFields.Database))

	// Phase 3: Perform NTLM authentication with remote server
	authResponse, err := performNTLMAuth(serverConn, credentials, loginPacket, tag)
	if err != nil {
		log.Printf("[%s] NTLM authentication failed: %v", tag, err)
		return
	}

	log.Printf("[%s] NTLM authentication successful for %s\\%s", tag, credentials.Domain, credentials.Username)

	// Phase 4: Forward the server's real login response to the client
	if _, err := clientDataConn.Write(authResponse); err != nil {
		log.Printf("[%s] Failed to forward login response to client: %v", tag, err)
		return
	}

	// Phase 5: Relay all subsequent traffic (client TLS <-> server TLS)
	log.Printf("[%s] Starting bidirectional relay", tag)
	var closing atomic.Bool
	done := make(chan struct{})
	go func() {
		relay(clientDataConn, serverConn, tag+"/server->client", &closing)
		closing.Store(true)
		clientConn.Close()
		close(done)
	}()
	relay(serverConn, clientDataConn, tag+"/client->server", &closing)
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

// LoginFields holds data from the client's LOGIN7 packet to forward in the
// NTLM LOGIN7 we send to the server.
type LoginFields struct {
	TDSVersion     uint32
	PacketSize     uint32
	ClientProgVer  uint32
	ClientPID      uint32
	ConnectionID   uint32
	OptionFlags1   byte
	OptionFlags2   byte // client's original flags (we'll OR in fIntSecurity)
	TypeFlags      byte
	OptionFlags3   byte
	ClientTimeZone uint32
	ClientLCID     uint32
	HostName       []byte
	AppName        []byte
	ServerName     []byte
	CltIntName     []byte
	Language       []byte
	Database       []byte
	ClientID       []byte // 6 bytes: MAC address / client identifier (offset 72-77)
}

func parseLoginPacket(data []byte) (*Credentials, *LoginFields, error) {
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("packet too short")
	}

	// Check if it's a TDS login packet (type 0x10)
	if data[0] != 0x10 {
		return nil, nil, fmt.Errorf("not a login packet, type=%02x", data[0])
	}

	// Skip TDS header (8 bytes)
	loginData := data[8:]

	// Login packet structure has offsets at fixed positions
	// See TDS specification for LOGIN7 structure
	if len(loginData) < 86 {
		return nil, nil, fmt.Errorf("login data too short")
	}

	// Offset and length fields are at these positions (2 bytes each):
	// Hostname: ibHostName=36, cchHostName=38
	// Username: ibUserName=40, cchUserName=42
	// Password: ibPassword=44, cchPassword=46
	// AppName: ibAppName=48, cchAppName=50
	// ServerName: ibServerName=52, cchServerName=54
	// ibExtension=56, cchExtension=58
	// ibCltIntName=60, cchCltIntName=62
	// ibLanguage=64, cchLanguage=66
	// ibDatabase=68, cchDatabase=70
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
		return nil, nil, err
	}
	username := decodeUTF16LE(usernameRaw)

	passwordRaw, err := readRawField(44, 46)
	if err != nil {
		return nil, nil, err
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

	// Extract fields to forward to server
	fields := &LoginFields{
		TDSVersion:     binary.LittleEndian.Uint32(loginData[4:8]),
		PacketSize:     binary.LittleEndian.Uint32(loginData[8:12]),
		ClientProgVer:  binary.LittleEndian.Uint32(loginData[12:16]),
		ClientPID:      binary.LittleEndian.Uint32(loginData[16:20]),
		ConnectionID:   binary.LittleEndian.Uint32(loginData[20:24]),
		OptionFlags1:   loginData[24],
		OptionFlags2:   loginData[25],
		TypeFlags:      loginData[26],
		OptionFlags3:   loginData[27],
		ClientTimeZone: binary.LittleEndian.Uint32(loginData[28:32]),
		ClientLCID:     binary.LittleEndian.Uint32(loginData[32:36]),
	}
	fields.HostName, _ = readRawField(36, 38)
	fields.AppName, _ = readRawField(48, 50)
	fields.ServerName, _ = readRawField(52, 54)
	fields.CltIntName, _ = readRawField(60, 62)
	fields.Language, _ = readRawField(64, 66)
	fields.Database, _ = readRawField(68, 70)

	// ClientID is a fixed 6-byte field at offset 72-77 (not offset/length pair)
	if len(loginData) >= 78 {
		fields.ClientID = make([]byte, 6)
		copy(fields.ClientID, loginData[72:78])
	}

	return &Credentials{
		Domain:   domain,
		Username: user,
		Password: password,
	}, fields, nil
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
	writeType   byte // TDS packet type for writes: 0x12 for client→server, 0x04 for server→client
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

	// Wrap in TDS packet (type depends on direction)
	pktType := c.writeType
	if pktType == 0 {
		pktType = 0x12 // default: PRELOGIN (client→server)
	}
	packet := make([]byte, 8+len(b))
	packet[0] = pktType
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
func performNTLMAuth(conn net.Conn, creds *Credentials, originalLogin []byte, tag string) ([]byte, error) {
	// Send NTLM Type 1 (Negotiate)
	negotiate, err := ntlmssp.NewNegotiateMessage(creds.Domain, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create negotiate message: %w", err)
	}

	// Build TDS login packet by modifying client's original LOGIN7 for NTLM
	loginWithNTLM1 := buildNTLMLoginPacket(originalLogin, negotiate)
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

func buildNTLMLoginPacket(originalPacket []byte, sspi []byte) []byte {
	// Modify the client's original LOGIN7 packet in-place for NTLM auth
	// Skip TDS header (8 bytes), work with LOGIN7 data
	original := originalPacket[8:]
	login := make([]byte, len(original))
	copy(login, original)

	// Get original length and find where variable data ends
	origLen := binary.LittleEndian.Uint32(login[0:4])

	// Modify OptionFlags2 to add fIntSecurity (0x80) for NTLM
	login[25] |= 0x80

	// Modify OptionFlags3: clear fExtension (0x02) and fUserInstance (0x10)
	// Keep fSparseColumnSort (0x04) if set
	login[27] &= 0x04

	// Clear username offset/length (offset 40-43)
	binary.LittleEndian.PutUint16(login[40:42], 0)
	binary.LittleEndian.PutUint16(login[42:44], 0)

	// Get password offset and length, then zero out the password data
	pwOffset := binary.LittleEndian.Uint16(login[44:46])
	pwLen := binary.LittleEndian.Uint16(login[46:48])
	if pwOffset > 0 && pwLen > 0 && int(pwOffset)+int(pwLen)*2 <= len(login) {
		// Zero out password data (length is in chars, each char is 2 bytes)
		for i := 0; i < int(pwLen)*2; i++ {
			login[int(pwOffset)+i] = 0
		}
	}
	// Clear password offset/length
	binary.LittleEndian.PutUint16(login[44:46], 0)
	binary.LittleEndian.PutUint16(login[46:48], 0)

	// Append SSPI data after the original variable data
	sspiOffset := uint16(origLen)
	binary.LittleEndian.PutUint16(login[78:80], sspiOffset)
	binary.LittleEndian.PutUint16(login[80:82], uint16(len(sspi)))

	// Append SSPI data to login
	login = append(login, sspi...)

	// Update total length at offset 0
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

	// Server sends TabularResult (0x04) for SSPI challenge - this is correct
	// No need to validate packet type here

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

		// Dump hex of packets with RESETCONN flag to see what's inside
		if pktStatus&0x04 != 0 || pktStatus&0x08 != 0 {
			end := offset + pktLen
			if end > len(data) {
				end = len(data)
			}
			payload := data[offset:end]
			log.Printf("%s:   RESETCONN packet hex: %s", direction, hex.EncodeToString(payload))
		}

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

		// Dump RPC packets (type 0x03) to see stored procedure calls
		if pktType == 0x03 {
			end := offset + pktLen
			if end > len(data) {
				end = len(data)
			}
			payload := data[offset+8 : end] // skip TDS header
			log.Printf("%s:   RPC payload hex: %s", direction, hex.EncodeToString(payload))
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
			// Dump full hex of error token data
			endPos := pos + 2 + tlen
			if endPos > len(data) {
				endPos = len(data)
			}
			log.Printf("%s:     token %s: hex=%s", direction, name, hex.EncodeToString(data[pos-1:endPos]))
			pos += 2
			if pos+6 <= len(data) {
				errNum := binary.LittleEndian.Uint32(data[pos : pos+4])
				state := data[pos+4]
				severity := data[pos+5]
				log.Printf("%s:     ERROR: number=%d state=%d severity=%d", direction, errNum, state, severity)
			}
			pos = endPos
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
