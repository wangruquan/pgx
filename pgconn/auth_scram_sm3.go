package pgconn

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/text/secure/precis"
)

const (
	scramSM3Name     = "SCRAM-SM3"
	scramSM3PlusName = "SCRAM-SM3-PLUS"
)

// Perform SCRAM-SM3 authentication.
func (c *PgConn) scramSM3Auth(serverAuthMechanisms []string) error {
	sc, err := newScramSM3Client(serverAuthMechanisms, c.config.Password)
	if err != nil {
		return err
	}

	serverHasPlus := slices.Contains(sc.serverAuthMechanisms, scramSM3PlusName)
	if c.config.ChannelBinding == "require" && !serverHasPlus {
		return errors.New("channel binding required but server does not support SCRAM-SM3-PLUS")
	}

	// If we have a TLS connection and channel binding is not disabled, attempt to
	// extract the server certificate hash for tls-server-end-point channel binding.
	if tlsConn, ok := c.conn.(*tls.Conn); ok && c.config.ChannelBinding != "disable" {
		certHash, err := getTLSCertificateHash(tlsConn)
		if err != nil && c.config.ChannelBinding == "require" {
			return fmt.Errorf("channel binding required but failed to get server certificate hash: %w", err)
		}

		// Upgrade to SCRAM-SM3-PLUS if we have binding data and the server supports it.
		if certHash != nil && serverHasPlus {
			sc.authMechanism = scramSM3PlusName
		}

		sc.channelBindingData = certHash
		sc.hasTLS = true
	}

	if c.config.ChannelBinding == "require" && sc.channelBindingData == nil {
		return errors.New("channel binding required but channel binding data is not available")
	}

	// Send client-first-message in a SASLInitialResponse
	saslInitialResponse := &pgproto3.SASLInitialResponse{
		AuthMechanism: sc.authMechanism,
		Data:          sc.clientFirstMessage(),
	}
	c.frontend.Send(saslInitialResponse)
	err = c.flushWithPotentialWriteReadDeadlock()
	if err != nil {
		return err
	}

	// Receive server-first-message payload in an AuthenticationSASLContinue.
	saslContinue, err := c.rxSASLContinue()
	if err != nil {
		return err
	}
	err = sc.recvServerFirstMessage(saslContinue.Data)
	if err != nil {
		return err
	}

	// Send client-final-message in a SASLResponse
	saslResponse := &pgproto3.SASLResponse{
		Data: []byte(sc.clientFinalMessage()),
	}
	c.frontend.Send(saslResponse)
	err = c.flushWithPotentialWriteReadDeadlock()
	if err != nil {
		return err
	}

	// Receive server-final-message payload in an AuthenticationSASLFinal.
	saslFinal, err := c.rxSASLFinal()
	if err != nil {
		return err
	}
	return sc.recvServerFinalMessage(saslFinal.Data)
}

type scramSM3Client struct {
	serverAuthMechanisms []string
	password             string
	clientNonce          []byte

	// authMechanism is the selected SASL mechanism for the client. Must be
	// either SCRAM-SM3 (default) or SCRAM-SM3-PLUS.
	authMechanism string

	// hasTLS indicates whether the connection is using TLS.
	hasTLS bool

	// channelBindingData is the hash of the server's TLS certificate.
	channelBindingData []byte

	clientFirstMessageBare []byte
	clientGS2Header        []byte

	serverFirstMessage   []byte
	clientAndServerNonce []byte
	salt                 []byte
	iterations           int

	saltedPassword []byte
	authMessage    []byte
}

func newScramSM3Client(serverAuthMechanisms []string, password string) (*scramSM3Client, error) {
	sc := &scramSM3Client{
		serverAuthMechanisms: serverAuthMechanisms,
		authMechanism:        scramSM3Name,
	}

	// Ensure the server supports SCRAM-SM3.
	if !slices.Contains(sc.serverAuthMechanisms, scramSM3Name) {
		return nil, errors.New("server does not support SCRAM-SM3")
	}

	// precis.OpaqueString is equivalent to SASLprep for password.
	var err error
	sc.password, err = precis.OpaqueString.String(password)
	if err != nil {
		sc.password = password
	}

	buf := make([]byte, clientNonceLen)
	_, err = rand.Read(buf)
	if err != nil {
		return nil, err
	}
	sc.clientNonce = make([]byte, base64.RawStdEncoding.EncodedLen(len(buf)))
	base64.RawStdEncoding.Encode(sc.clientNonce, buf)

	return sc, nil
}

func (sc *scramSM3Client) clientFirstMessage() []byte {
	sc.clientFirstMessageBare = fmt.Appendf(nil, "n=,r=%s", sc.clientNonce)

	if sc.authMechanism == scramSM3PlusName {
		sc.clientGS2Header = []byte("p=tls-server-end-point,,")
	} else if sc.hasTLS {
		sc.clientGS2Header = []byte("y,,")
	} else {
		sc.clientGS2Header = []byte("n,,")
	}

	return append(sc.clientGS2Header, sc.clientFirstMessageBare...)
}

func (sc *scramSM3Client) recvServerFirstMessage(serverFirstMessage []byte) error {
	sc.serverFirstMessage = serverFirstMessage
	buf := serverFirstMessage
	if !bytes.HasPrefix(buf, []byte("r=")) {
		return errors.New("invalid SCRAM-SM3 server-first-message received from server: did not include r=")
	}
	buf = buf[2:]

	idx := bytes.IndexByte(buf, ',')
	if idx == -1 {
		return errors.New("invalid SCRAM-SM3 server-first-message received from server: did not include s=")
	}
	sc.clientAndServerNonce = buf[:idx]
	buf = buf[idx+1:]

	if !bytes.HasPrefix(buf, []byte("s=")) {
		return errors.New("invalid SCRAM-SM3 server-first-message received from server: did not include s=")
	}
	buf = buf[2:]

	idx = bytes.IndexByte(buf, ',')
	if idx == -1 {
		return errors.New("invalid SCRAM-SM3 server-first-message received from server: did not include i=")
	}
	saltStr := buf[:idx]
	buf = buf[idx+1:]

	if !bytes.HasPrefix(buf, []byte("i=")) {
		return errors.New("invalid SCRAM-SM3 server-first-message received from server: did not include i=")
	}
	buf = buf[2:]
	iterationsStr := buf

	var err error
	sc.salt, err = base64.StdEncoding.DecodeString(string(saltStr))
	if err != nil {
		return fmt.Errorf("invalid SCRAM-SM3 salt received from server: %w", err)
	}

	sc.iterations, err = strconv.Atoi(string(iterationsStr))
	if err != nil || sc.iterations <= 0 {
		return fmt.Errorf("invalid SCRAM-SM3 iteration count received from server: %w", err)
	}

	if !bytes.HasPrefix(sc.clientAndServerNonce, sc.clientNonce) {
		return errors.New("invalid SCRAM-SM3 nonce: did not start with client nonce")
	}

	if len(sc.clientAndServerNonce) <= len(sc.clientNonce) {
		return errors.New("invalid SCRAM-SM3 nonce: did not include server nonce")
	}

	return nil
}

func (sc *scramSM3Client) clientFinalMessage() string {
	channelBindInput := sc.clientGS2Header
	if sc.authMechanism == scramSM3PlusName {
		channelBindInput = slices.Concat(sc.clientGS2Header, sc.channelBindingData)
	}
	channelBindingEncoded := base64.StdEncoding.EncodeToString(channelBindInput)
	clientFinalMessageWithoutProof := fmt.Appendf(nil, "c=%s,r=%s", channelBindingEncoded, sc.clientAndServerNonce)

	var err error
	sc.saltedPassword, err = pbkdf2.Key(newSM3, sc.password, sc.salt, sc.iterations, 32)
	if err != nil {
		panic(err)
	}
	sc.authMessage = bytes.Join([][]byte{sc.clientFirstMessageBare, sc.serverFirstMessage, clientFinalMessageWithoutProof}, []byte(","))

	clientProof := computeSM3ClientProof(sc.saltedPassword, sc.authMessage)

	return fmt.Sprintf("%s,p=%s", clientFinalMessageWithoutProof, clientProof)
}

func (sc *scramSM3Client) recvServerFinalMessage(serverFinalMessage []byte) error {
	if !bytes.HasPrefix(serverFinalMessage, []byte("v=")) {
		return errors.New("invalid SCRAM-SM3 server-final-message received from server")
	}

	serverSignature := serverFinalMessage[2:]

	if !hmac.Equal(serverSignature, computeSM3ServerSignature(sc.saltedPassword, sc.authMessage)) {
		return errors.New("invalid SCRAM-SM3 ServerSignature received from server")
	}

	return nil
}

func computeSM3HMAC(key, msg []byte) []byte {
	mac := hmac.New(newSM3, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func computeSM3ClientProof(saltedPassword, authMessage []byte) []byte {
	clientKey := computeSM3HMAC(saltedPassword, []byte("Client Key"))
	storedKey := sm3Sum(clientKey)
	clientSignature := computeSM3HMAC(storedKey[:], authMessage)

	clientProof := make([]byte, len(clientSignature))
	for i := range clientSignature {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}

	buf := make([]byte, base64.StdEncoding.EncodedLen(len(clientProof)))
	base64.StdEncoding.Encode(buf, clientProof)
	return buf
}

func computeSM3ServerSignature(saltedPassword, authMessage []byte) []byte {
	serverKey := computeSM3HMAC(saltedPassword, []byte("Server Key"))
	serverSignature := computeSM3HMAC(serverKey, authMessage)
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(serverSignature)))
	base64.StdEncoding.Encode(buf, serverSignature)
	return buf
}
