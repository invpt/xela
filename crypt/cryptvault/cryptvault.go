package cryptvault

import (
	"encoding/json"
	"errors"

	"fixpt.org/xela/crypt"
	"fixpt.org/xela/vault"
)

var _ vault.Vault[ItemRef[vault.UnitItemRef]] = &CryptVault[vault.UnitItemRef]{}

type CryptVault[InnerRef vault.ItemRef] struct {
	inner vault.Vault[InnerRef]
	enc   *crypt.Encrypter
	dec   *crypt.Decrypter
}

type ItemRef[InnerRef vault.ItemRef] struct {
	inner InnerRef
	name  string
}

type cryptInfo struct {
	Salt          crypt.Salt          `json:"salt"`
	KDFParameters crypt.KDFParameters `json:"kdf_parameters"`
}

func Create[InnerRef vault.ItemRef](inner vault.Vault[InnerRef], password []byte) (*CryptVault[InnerRef], error) {
	salt, err := crypt.GenerateSalt()
	if err != nil {
		return nil, err
	}

	kdfParameters := crypt.DefaultKDFParameters()

	cryptJsonBytes, err := json.Marshal(cryptInfo{
		Salt:          salt,
		KDFParameters: kdfParameters,
	})
	if err != nil {
		return nil, err
	}

	cryptJsonRef, err := inner.Create(inner.Root(), "crypt.json", vault.ItemKindFile)
	if err != nil {
		return nil, err
	}

	err = inner.Write(cryptJsonRef, cryptJsonBytes)
	if err != nil {
		return nil, err
	}

	return open(inner, password, salt, kdfParameters)
}

func Open[InnerRef vault.ItemRef](inner vault.Vault[InnerRef], password []byte) (*CryptVault[InnerRef], error) {
	cryptJsonRef, err := inner.Ref(inner.Root(), "crypt.json")
	if err != nil {
		return nil, err
	}

	cryptJsonBytes, err := inner.Read(cryptJsonRef)
	if err != nil {
		return nil, err
	}

	var info cryptInfo
	json.Unmarshal(cryptJsonBytes, &info)

	return open(inner, password, info.Salt, info.KDFParameters)
}

func open[InnerRef vault.ItemRef](
	inner vault.Vault[InnerRef],
	password []byte,
	salt crypt.Salt,
	kdfParameters crypt.KDFParameters,
) (*CryptVault[InnerRef], error) {
	key := crypt.DeriveKey(password, salt, kdfParameters)

	enc, err := crypt.NewEncrypter(key)
	if err != nil {
		return nil, err
	}

	dec, err := crypt.NewDecrypter(key)
	if err != nil {
		return nil, err
	}

	return &CryptVault[InnerRef]{
		inner: inner,
		enc:   enc,
		dec:   dec,
	}, nil
}

func (v *CryptVault[InnerRef]) Root() ItemRef[InnerRef] {
	return ItemRef[InnerRef]{
		inner: v.inner.Root(),
		name:  "",
	}
}

func (v *CryptVault[InnerRef]) List(where ItemRef[InnerRef]) ([]ItemRef[InnerRef], error) {
	repoItems, err := v.inner.List(where.inner)
	if err != nil {
		return nil, err
	}

	items := make([]ItemRef[InnerRef], 0, len(repoItems))
	for _, repoItem := range repoItems {
		item, err := v.decryptInnerRef(repoItem)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, nil
}

func (v *CryptVault[InnerRef]) Ref(where ItemRef[InnerRef], name string) (ItemRef[InnerRef], error) {
	return ItemRef[InnerRef]{}, errors.New("xela/crypto: TODO: implement Ref")
}

func (v *CryptVault[InnerRef]) Create(where ItemRef[InnerRef], name string, kind vault.ItemKind) (ItemRef[InnerRef], error) {
	encryptedName, err := v.enc.EncryptFilename(name)
	if err != nil {
		return ItemRef[InnerRef]{}, err
	}

	repoItem, err := v.inner.Create(where.inner, encryptedName, kind)
	if err != nil {
		return ItemRef[InnerRef]{}, err
	}

	return v.decryptInnerRef(repoItem)
}

func (v *CryptVault[InnerRef]) decryptInnerRef(innerRef InnerRef) (ItemRef[InnerRef], error) {
	Name := innerRef.Name()

	decryptedName, err := v.dec.DecryptFilename(Name)
	if err != nil {
		return ItemRef[InnerRef]{}, err
	}

	return ItemRef[InnerRef]{
		inner: innerRef,
		name:  decryptedName,
	}, nil
}

func (v *CryptVault[InnerRef]) Read(file ItemRef[InnerRef]) ([]byte, error) {
	ciphertext, err := v.inner.Read(file.inner)
	if err != nil {
		return nil, err
	}

	return v.dec.DecryptFile(nil, ciphertext)
}

func (v *CryptVault[InnerRef]) Write(file ItemRef[InnerRef], data []byte) error {
	ciphertext, err := v.enc.EncryptFile(nil, data)
	if err != nil {
		return err
	}

	return v.inner.Write(file.inner, ciphertext)
}

func (v *CryptVault[InnerRef]) Delete(item ItemRef[InnerRef]) error {
	return v.inner.Delete(item.inner)
}
