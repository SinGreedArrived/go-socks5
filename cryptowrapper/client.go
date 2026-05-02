package cryptowrapper

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

func WrapClient(conn net.Conn) (net.Conn, error) {
	shared, err := handshakeClient(conn)
	if err != nil {
		return nil, fmt.Errorf("handshakeClient: %w", err)
	}
	key := deriveKeys(shared)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return &EncryptedConn{
		Conn:       conn,
		aead:       aead,
		sendPrefix: []byte{0, 0, 0, 2},
		recvPrefix: []byte{0, 0, 0, 1},
	}, nil
}

func handshakeClient(conn net.Conn) ([]byte, error) {
	curve := ecdh.X25519()

	priv, _ := curve.GenerateKey(rand.Reader)
	pub := priv.PublicKey().Bytes()

	// отправляем публичный ключ
	if _, err := conn.Write(pub); err != nil {
		return nil, err
	}

	// читаем серверный ключ
	serverPubBytes := make([]byte, 32)
	if _, err := io.ReadFull(conn, serverPubBytes); err != nil {
		return nil, err
	}

	serverPub, _ := curve.NewPublicKey(serverPubBytes)

	shared, _ := priv.ECDH(serverPub)

	return shared, nil
}
