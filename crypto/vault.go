package crypto

import (
	"encoding/json"
	"errors"

	"fixpt.org/xela/core"
)

var _ core.Vault[ItemRef[core.UnitItemRef]] = &Vault[core.UnitItemRef]{}

type Vault[InnerRef core.ItemRef] struct {
	inner core.Vault[InnerRef]
	enc   *XelaEncrypter
	dec   *XelaDecrypter
}

type ItemRef[InnerRef core.ItemRef] struct {
	inner InnerRef
	name  string
}

func OpenVault[InnerRef core.ItemRef](inner core.Vault[InnerRef], password []byte) (*Vault[InnerRef], error) {
	cryptJsonRef, err := inner.Ref(inner.Root(), "crypt.json")
	if err != nil {
		return nil, err
	}

	cryptJsonBytes, err := inner.Read(cryptJsonRef)
	if err != nil {
		return nil, err
	}

	var crypt struct {
		Salt          Salt          `json:"salt"`
		KDFParameters KDFParameters `json:"kdf_parameters"`
	}
	json.Unmarshal(cryptJsonBytes, &crypt)

	key := DeriveKey(password, crypt.Salt, crypt.KDFParameters)

	enc, err := NewXelaEncrypter(key)
	if err != nil {
		return nil, err
	}

	dec, err := NewXelaDecrypter(key)
	if err != nil {
		return nil, err
	}

	return &Vault[InnerRef]{
		inner: inner,
		enc:   enc,
		dec:   dec,
	}, nil
}

func (v *Vault[InnerRef]) Root() ItemRef[InnerRef] {
	return ItemRef[InnerRef]{
		inner: v.inner.Root(),
		name:  "",
	}
}

func (v *Vault[InnerRef]) List(where ItemRef[InnerRef]) ([]ItemRef[InnerRef], error) {
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

func (v *Vault[InnerRef]) Ref(where ItemRef[InnerRef], name string) (ItemRef[InnerRef], error) {
	return ItemRef[InnerRef]{}, errors.New("xela/crypto: TODO: implement Ref")
}

func (v *Vault[InnerRef]) Create(where ItemRef[InnerRef], name string, kind core.ItemKind) (ItemRef[InnerRef], error) {
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

func (v *Vault[InnerRef]) decryptInnerRef(innerRef InnerRef) (ItemRef[InnerRef], error) {
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

func (v *Vault[InnerRef]) Read(file ItemRef[InnerRef]) ([]byte, error) {
	ciphertext, err := v.inner.Read(file.inner)
	if err != nil {
		return nil, err
	}

	return v.dec.DecryptFile(nil, ciphertext)
}

func (v *Vault[InnerRef]) Write(file ItemRef[InnerRef], data []byte) error {
	ciphertext, err := v.enc.EncryptFile(nil, data)
	if err != nil {
		return err
	}

	return v.inner.Write(file.inner, ciphertext)
}

func (v *Vault[InnerRef]) Delete(item ItemRef[InnerRef]) error {
	return v.inner.Delete(item.inner)
}
