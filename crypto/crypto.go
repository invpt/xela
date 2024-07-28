package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// The Argon2 key derivation function is used to turn passwords into encryption keys.

// Each file is divided into superblocks that end up being 256 bytes large in the encrypted,
// on-disk format. A superblock consists of an initialization vector (16 bytes) followed by 240
// bytes of ciphertext (15 AES blocks). Those 240 bytes of ciphertext are obtained by encrypting
// one byte for length followed by 239 bytes of actual plaintext data. Hence xela takes 7.11% more
// storage space than storing your files in plaintext.

func NewXelaDecrypter(key []byte) (*XelaDecrypter, error) {
	if len(key) != 32 {
		return nil, errors.New("xela/crypto: incorrect size for decryption key")
	}

	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &XelaDecrypter{b: b}, nil
}

type XelaDecrypter struct {
	b   cipher.Block
	cbc cipher.BlockMode
}

type settableIV interface {
	SetIV(iv []byte) error
}

// Decrypts one superblock.
//
// All superblocks are decrypted independently.
func (x *XelaDecrypter) DecryptSuperblock(src []byte, dst []byte) (err error) {
	if len(src) != 256 || len(dst) != 239 {
		return errors.New("xela/crypto: incorrect size for src or dst parameter")
	}

	iv := src[:16]
	if x.cbc == nil {
		x.cbc = cipher.NewCBCDecrypter(x.b, iv)
	} else {
		if s, ok := x.cbc.(settableIV); ok {
			// set the IV using a more efficient method if available
			err = s.SetIV(iv)
			if err != nil {
				return err
			}
		} else {
			x.cbc = cipher.NewCBCDecrypter(x.b, iv)
		}
	}

	x.cbc.CryptBlocks(src[16:], dst)

	return nil
}
