package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Length of the salt appended to every password
const saltLen int = 32

// Length of the encryption key
const keyLen uint32 = 32

// Length of the ciphertext of a superblock
const cphtxtLen int = 256

// Length of the interior of a superblock
const intrLen int = cphtxtLen - aes.BlockSize

// Length of the plaintext stored by a superblock
const ptxtLen int = intrLen - 1

// The Argon2 key derivation function is used to turn passwords into encryption keys.

type Key struct{ key []byte }
type Salt struct{ salt []byte }

func (s Salt) MarshalJSON() ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(s.salt)
	return json.Marshal(encoded)
}

func (s *Salt) UnmarshalJSON(b []byte) error {
	str := ""
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}

	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	s.salt = decoded

	return nil
}

func GenerateSalt() (Salt, error) {
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return Salt{}, err
	}

	return Salt{salt: salt}, nil
}

type KDFParameters struct {
	time    uint32
	memory  uint32
	threads uint8
}

// This type is just so we can marshal/unmarshal while having the fields be unexported
type jsonKDFParameters struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

func DefaultKDFParameters() KDFParameters {
	return KDFParameters{
		time:    1,
		memory:  64 * 1024,
		threads: 4,
	}
}

func (k KDFParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonKDFParameters{
		Time:    k.time,
		Memory:  k.memory,
		Threads: k.threads,
	})
}

func (k *KDFParameters) UnmarshalJSON(b []byte) error {
	l := jsonKDFParameters{}
	err := json.Unmarshal(b, &l)
	if err != nil {
		return err
	}

	k.time = l.Time
	k.memory = l.Memory
	k.threads = l.Threads

	return nil
}

func DeriveKey(password []byte, salt Salt, params KDFParameters) Key {
	return Key{key: argon2.IDKey(password, salt.salt, params.time, params.memory, params.threads, keyLen)}
}

// Each file is divided into superblocks that end up being 256 bytes large in the encrypted,
// on-disk format. A superblock consists of an initialization vector (16 bytes) followed by 240
// bytes of ciphertext (15 AES blocks). Those 240 bytes of ciphertext are obtained by encrypting
// one byte for length followed by 239 bytes of actual plaintext data. Hence xela takes 7.11% more
// storage space than storing your files in plaintext.

type Decrypter struct {
	b   cipher.Block
	cbc cipher.BlockMode
}

func NewDecrypter(key Key) (*Decrypter, error) {
	b, err := aes.NewCipher(key.key)
	if err != nil {
		return nil, err
	}

	return &Decrypter{b: b}, nil
}

func (x *Decrypter) DecryptFilename(ciphertextString string) (plaintext string, err error) {
	var ciphertext []byte
	ciphertext, err = base64.URLEncoding.DecodeString(ciphertextString)
	if err != nil {
		return
	}

	if len(ciphertext)%aes.BlockSize != 0 || len(ciphertext)/aes.BlockSize < 1 {
		return "", errors.New(fmt.Sprint(
			"xela/crypto: malformed filename ciphertext - the length must be a multiple of",
			aes.BlockSize,
			"and at least",
			aes.BlockSize,
			"bytes long",
		))
	}

	iv := ciphertext[:aes.BlockSize]
	x.cbc, err = setCBCIV(x.b, x.cbc, iv)
	if err != nil {
		return
	}

	plaintextBytes := make([]byte, len(ciphertext)-aes.BlockSize)
	x.cbc.CryptBlocks(plaintextBytes, ciphertext[aes.BlockSize:])

	nulIdx := len(plaintextBytes)
	for i, ch := range plaintextBytes {
		if ch == 0 {
			nulIdx = i
			break
		}
	}

	plaintext = string(plaintextBytes[:nulIdx])

	return
}

// Decrypts the given cyphertext and places it into the plaintext pointer.
//
// May reuse/write to the current byte array pointed to by plaintext.
func (x *Decrypter) DecryptFile(plaintext []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%cphtxtLen != 0 {
		return nil, errors.New(fmt.Sprint("xela/crypto: malformed ciphertext - the length must be a multiple of ", cphtxtLen))
	}

	blockCount := len(ciphertext) / cphtxtLen

	plaintext = plaintext[:0]
	for blockIndex := 0; blockIndex < blockCount; blockIndex++ {
		if cap(plaintext)-len(plaintext) < ptxtLen {
			// grow the plaintext slice whenever needed
			newPlaintext := make([]byte, len(plaintext)+ptxtLen, max(len(plaintext)*2, len(plaintext)+ptxtLen))
			copy(newPlaintext[:len(plaintext)], plaintext[:])
			plaintext = newPlaintext
		}

		superblockLength, err := x.DecryptFileSuperblock(
			plaintext[len(plaintext):len(plaintext)+ptxtLen],
			ciphertext[blockIndex*cphtxtLen:(blockIndex+1)*cphtxtLen],
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
func (x *Decrypter) DecryptFileSuperblock(plaintext, ciphertext []byte) (length int, err error) {
	if len(ciphertext) != cphtxtLen || len(plaintext) != ptxtLen {
		return 0, errors.New("xela/crypto: incorrect size for plaintext or ciphertext parameter")
	}

	iv := ciphertext[:aes.BlockSize]

	x.cbc, err = setCBCIV(x.b, x.cbc, iv)
	if err != nil {
		return
	}

	plaintextWithLength := [intrLen]byte{}
	x.cbc.CryptBlocks(plaintextWithLength[:], ciphertext[aes.BlockSize:])
	length = int(plaintextWithLength[intrLen-1])
	copy(plaintext[:length], plaintextWithLength[:length])

	return
}

type Encrypter struct {
	b   cipher.Block
	cbc cipher.BlockMode
}

func NewEncrypter(key Key) (*Encrypter, error) {
	b, err := aes.NewCipher(key.key)
	if err != nil {
		return nil, err
	}

	return &Encrypter{b: b}, nil
}

func (x *Encrypter) EncryptFilename(plaintext string) (ciphertextString string, err error) {
	plaintextBytesLen := len(plaintext) / aes.BlockSize * aes.BlockSize
	if len(plaintext)%aes.BlockSize != 0 {
		plaintextBytesLen += aes.BlockSize
	}

	plaintextBytes := make([]byte, plaintextBytesLen)
	for i := 0; i < len(plaintext); i++ {
		plaintextBytes[i] = plaintext[i]
	}

	ciphertext := make([]byte, plaintextBytesLen+aes.BlockSize)

	iv := ciphertext[:aes.BlockSize]
	_, err = rand.Read(iv)
	if err != nil {
		return
	}

	x.cbc, err = setCBCIV(x.b, x.cbc, iv)
	if err != nil {
		return
	}

	x.cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintextBytes)

	ciphertextString = base64.URLEncoding.EncodeToString(ciphertext)

	return
}

// Encrypts the given plaintext. The passed ciphertext parameter may contain the current ciphertext
// to be used by this function in an effort to create a minimal-diff result. The passed ciphertext
// slice may also be written to.
func (x *Encrypter) EncryptFile(ciphertext []byte, plaintext []byte) ([]byte, error) {
	// TODO: optimize the diff for simplicity
	blocksNeeded := len(plaintext) / ptxtLen
	if len(plaintext)%ptxtLen != 0 {
		blocksNeeded += 1
	}
	ciphertext = make([]byte, 0, blocksNeeded*cphtxtLen)

	for blockIndex := 0; blockIndex < blocksNeeded; blockIndex++ {
		err := x.EncryptFileSuperblock(
			ciphertext[blockIndex*cphtxtLen:(blockIndex+1)*cphtxtLen],
			plaintext[blockIndex*ptxtLen:min((blockIndex+1)*ptxtLen, len(plaintext))],
		)
		if err != nil {
			return nil, err
		}
	}

	return ciphertext, nil
}

func (x *Encrypter) EncryptFileSuperblock(ciphertext, plaintext []byte) (err error) {
	if len(ciphertext) != cphtxtLen {
		return errors.New("xela/crypto: incorrect size for ciphertext parameter")
	}

	iv := ciphertext[:aes.BlockSize]
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	x.cbc, err = setCBCIV(x.b, x.cbc, iv)
	if err != nil {
		return err
	}

	plaintextWithLength := [intrLen]byte{}
	copy(plaintextWithLength[:len(plaintext)], plaintext)
	plaintextWithLength[intrLen-1] = byte(len(plaintext))
	x.cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintextWithLength[:])

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
