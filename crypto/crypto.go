package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// The Argon2 key derivation function is used to turn passwords into encryption keys.

// Each file is divided into superblocks that end up being 256 bytes large in the encrypted,
// on-disk format. A superblock consists of an initialization vector (16 bytes) followed by 240
// bytes of ciphertext (15 AES blocks). Those 240 bytes of ciphertext are obtained by encrypting
// one byte for length followed by 239 bytes of actual plaintext data. Hence xela takes 7.11% more
// storage space than storing your files in plaintext.

type XelaDecrypter struct {
	b   cipher.Block
	cbc cipher.BlockMode
}

func NewXelaDecrypter(key []byte) (*XelaDecrypter, error) {
	if len(key) != 32 {
		return nil, errors.New("xela/crypto: incorrect size for the decryption key")
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &XelaDecrypter{b: b}, nil
}

// Decrypts the given cyphertext and places it into the plaintext pointer.
//
// May reuse/write to any current byte array pointed to by plaintext.
func (x *XelaDecrypter) Decrypt(plaintext []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%256 != 0 {
		return nil, errors.New("xela/crypto: malformed ciphertext - the length must be a multiple of 256")
	}

	blockCount := len(ciphertext) / 256

	plaintext = plaintext[:0]
	for blockIndex := 0; blockIndex < blockCount; blockIndex++ {
		if cap(plaintext)-len(plaintext) < 239 {
			// grow the plaintext slice whenever needed
			newPlaintext := make([]byte, len(plaintext)+239, max(len(plaintext)*2, len(plaintext)+239))
			copy(newPlaintext[:len(plaintext)], plaintext[:])
			plaintext = newPlaintext
		}

		superblockLength, err := x.DecryptSuperblock(
			plaintext[len(plaintext):len(plaintext)+239],
			ciphertext[blockIndex*256:(blockIndex+1)*256],
		)
		if err != nil {
			return nil, err
		}

		plaintext = plaintext[:len(plaintext)+superblockLength]
	}

	return plaintext, nil
}

// Decrypts one superblock and returns the length (number of bytes stored into plaintext).
//
// All superblocks are decrypted independently.
func (x *XelaDecrypter) DecryptSuperblock(plaintext, ciphertext []byte) (length int, err error) {
	if len(ciphertext) != 256 || len(plaintext) != 239 {
		return 0, errors.New("xela/crypto: incorrect size for plaintext or ciphertext parameter")
	}

	iv := ciphertext[:16]

	x.cbc, err = setCBCIV(x.b, x.cbc, iv)
	if err != nil {
		return
	}

	plaintextWithLength := [240]byte{}
	x.cbc.CryptBlocks(plaintextWithLength[:], ciphertext[16:])
	length = int(plaintextWithLength[239])
	copy(plaintext[:length], plaintextWithLength[:length])

	return
}

type XelaEncrypter struct {
	b   cipher.Block
	cbc cipher.BlockMode
}

func NewXelaEncrypter(key []byte) (*XelaEncrypter, error) {
	if len(key) != 32 {
		return nil, errors.New("xela/crypto: incorrect size for decryption key")
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &XelaEncrypter{b: b}, nil
}

// Encrypts the given plaintext. The passed ciphertext parameter may contain the current ciphertext
// to be used by this function in an effort to create a minimal-diff result. The passed ciphertext
// slice may also be written to.
func (x *XelaEncrypter) Encrypt(ciphertext []byte, plaintext []byte) ([]byte, error) {
	// TODO: optimize the diff for simplicity
	blocksNeeded := len(plaintext) / 239
	if len(plaintext)%239 != 0 {
		blocksNeeded += 1
	}
	ciphertext = make([]byte, 0, blocksNeeded*256)

	for blockIndex := 0; blockIndex < blocksNeeded; blockIndex++ {
		err := x.EncryptSuperblock(
			ciphertext[blockIndex*256:(blockIndex+1)*256],
			plaintext[blockIndex*239:min((blockIndex+1)*239, len(plaintext))],
		)
		if err != nil {
			return nil, err
		}
	}

	return ciphertext, nil
}

func (x *XelaEncrypter) EncryptSuperblock(ciphertext, plaintext []byte) (err error) {
	if len(ciphertext) != 256 {
		return errors.New("xela/crypto: incorrect size for ciphertext parameter")
	}

	iv := ciphertext[:16]
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	x.cbc, err = setCBCIV(x.b, x.cbc, iv)
	if err != nil {
		return err
	}

	plaintextWithLength := [240]byte{}
	copy(plaintextWithLength[:len(plaintext)], plaintext)
	plaintextWithLength[239] = byte(len(plaintext))
	x.cbc.CryptBlocks(ciphertext[16:], plaintextWithLength[:])

	return
}

func setCBCIV(b cipher.Block, cbc cipher.BlockMode, iv []byte) (updated cipher.BlockMode, err error) {
	if s, ok := cbc.(settableIV); ok {
		// set the IV using a more efficient method if available
		err = s.SetIV(iv)
		if err != nil {
			return
		}
		updated = cbc
	} else {
		updated = cipher.NewCBCEncrypter(b, iv)
	}
	return
}

type settableIV interface {
	SetIV(iv []byte) error
}
