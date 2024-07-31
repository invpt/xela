package vault

import (
	"encoding/json"
	"path/filepath"

	"fixpt.org/xela/crypto"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"
)

func hi() {
	_ = dotgit.New(osfs.New(".git"))
	git.Clone(nil, osfs.New("."), nil)
}

type VaultDatabase struct {
	repos *repoDatabase
}

type Vault struct {
	repos *repoDatabase
	root  repoItemRef
	dec   *crypto.XelaDecrypter
	enc   *crypto.XelaEncrypter
}

type VaultRef struct {
	root repoItemRef
}

func (v VaultRef) Name() string {
	return v.root.Name()
}

type ItemRef struct {
	repoItemRef
	name string
}

type ItemKind int

const (
	ItemKindFile ItemKind = iota
	ItemKindDir
)

func (i ItemRef) Name() string {
	return i.name
}

func (i ItemRef) Kind() ItemKind {
	return i.repoItemRef.kind
}

func Open(basePath string) *VaultDatabase {
	return &VaultDatabase{repos: openRepoDatabase(basePath)}
}

func (db *VaultDatabase) ListVaults() ([]VaultRef, error) {
	repos, err := db.repos.ListRepos()
	if err != nil {
		return nil, err
	}

	vaults := make([]VaultRef, 0, len(repos))
	for _, repo := range repos {
		vaults = append(vaults, VaultRef{root: repo})
	}

	return vaults, nil
}

func (db *VaultDatabase) OpenVault(vault VaultRef, password []byte) (*Vault, error) {
	cryptJsonRef, err := db.repos.Ref(vault.root, "crypt.json")
	if err != nil {
		return nil, err
	}

	cryptJsonBytes, err := db.repos.Read(cryptJsonRef)
	if err != nil {
		return nil, err
	}

	var crypt struct {
		Salt          crypto.Salt          `json:"salt"`
		KDFParameters crypto.KDFParameters `json:"kdf_parameters"`
	}
	json.Unmarshal(cryptJsonBytes, &crypt)

	key := crypto.DeriveKey(password, crypt.Salt, crypt.KDFParameters)

	enc, err := crypto.NewXelaEncrypter(key)
	if err != nil {
		return nil, err
	}

	dec, err := crypto.NewXelaDecrypter(key)
	if err != nil {
		return nil, err
	}

	return &Vault{
		repos: db.repos,
		root:  vault.root,
		enc:   enc,
		dec:   dec,
	}, nil
}

func (v *Vault) Name() string {
	return v.root.Name()
}

func (v *Vault) Root() ItemRef {
	return ItemRef{
		repoItemRef: v.root,
		name:        v.root.Name(),
	}
}

func (v *Vault) ListItems(where ItemRef) ([]ItemRef, error) {
	repoItems, err := v.repos.ListItems(where.repoItemRef)
	if err != nil {
		return nil, err
	}

	items := make([]ItemRef, 0, len(repoItems))
	for _, repoItem := range repoItems {
		item, err := v.decryptRepoItemRef(repoItem)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, nil
}

func (v *Vault) Create(where ItemRef, name string, kind ItemKind) (ItemRef, error) {
	encryptedName, err := v.enc.EncryptFilename(name)
	if err != nil {
		return ItemRef{}, err
	}

	repoItem, err := v.repos.Create(v.root, encryptedName, kind)
	if err != nil {
		return ItemRef{}, err
	}

	return v.decryptRepoItemRef(repoItem)
}

func (v *Vault) decryptRepoItemRef(repoItem repoItemRef) (ItemRef, error) {
	_, encryptedName := filepath.Split(repoItem.path)

	decryptedName, err := v.dec.DecryptFilename(encryptedName)
	if err != nil {
		return ItemRef{}, err
	}

	return ItemRef{
		repoItemRef: repoItem,
		name:        decryptedName,
	}, nil
}

func (v *Vault) Read(file ItemRef) ([]byte, error) {
	ciphertext, err := v.repos.Read(file.repoItemRef)
	if err != nil {
		return nil, err
	}

	return v.dec.DecryptFile(nil, ciphertext)
}

func (v *Vault) Write(file ItemRef, data []byte) error {
	ciphertext, err := v.enc.EncryptFile(nil, data)
	if err != nil {
		return err
	}

	return v.repos.Write(file.repoItemRef, ciphertext)
}

func (v *Vault) Delete(item ItemRef) error {
	return v.repos.Delete(item.repoItemRef)
}
