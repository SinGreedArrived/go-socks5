package cryptowrapper

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

func WrapServer(conn net.Conn) (net.Conn, error) {
	shared, err := handshakeServer(conn)
	if err != nil {
		return nil, fmt.Errorf("handshakeServer: %w", err)
	}
	key := deriveKeys(shared)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	return &EncryptedConn{
		Conn:       conn,
		aead:       aead,
		sendPrefix: []byte{0, 0, 0, 1},
		recvPrefix: []byte{0, 0, 0, 2},
	}, nil
}

func handshakeServer(conn net.Conn) ([]byte, error) {
	curve := ecdh.X25519()

	// читаем клиентский ключ
	clientPubBytes := make([]byte, 32)
	if _, err := io.ReadFull(conn, clientPubBytes); err != nil {
		return nil, err
	}

	clientPub, _ := curve.NewPublicKey(clientPubBytes)

	priv, _ := curve.GenerateKey(rand.Reader)
	pub := priv.PublicKey().Bytes()

	// отправляем свой ключ
	if _, err := conn.Write(pub); err != nil {
		return nil, err
	}

	shared, _ := priv.ECDH(clientPub)

	return shared, nil
}
