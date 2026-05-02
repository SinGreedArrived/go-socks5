package cryptowrapper

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"

	"golang.org/x/crypto/hkdf"
)

const (
	NonceSize = 12
)

func deriveKeys(shared []byte) (key []byte) {
	salt := make([]byte, 32) // можно нули или добавить рандом/обмен
	hkdf := hkdf.New(sha256.New, shared, salt, []byte("socks5-ecdh"))

	key = make([]byte, 32)
	io.ReadFull(hkdf, key)

	return key
}

type EncryptedConn struct {
	net.Conn
	aead cipher.AEAD

	sendNonce uint64
	recvNonce uint64

	sendPrefix []byte // 4 bytes
	recvPrefix []byte

	rbuf bytes.Buffer
}

func makeNonce(prefix []byte, counter uint64) []byte {
	nonce := make([]byte, NonceSize)
	copy(nonce[:4], prefix)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func (c *EncryptedConn) Write(p []byte) (int, error) {
	nonce := makeNonce(c.sendPrefix, c.sendNonce)
	c.sendNonce++

	ciphertext := c.aead.Seal(nil, nonce, p, nil)

	length := uint16(len(ciphertext))

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, length)
	buf.Write(ciphertext)

	_, err := c.Conn.Write(buf.Bytes())
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *EncryptedConn) Read(p []byte) (int, error) {
	if c.rbuf.Len() > 0 {
		return c.rbuf.Read(p)
	}

	var length uint16
	if err := binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return 0, err
	}

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, ciphertext); err != nil {
		return 0, err
	}

	nonce := makeNonce(c.recvPrefix, c.recvNonce)
	c.recvNonce++

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	c.rbuf.Write(plaintext)
	return c.rbuf.Read(p)
}
