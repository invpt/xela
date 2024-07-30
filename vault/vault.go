package vault

import (
	"encoding/json"
	"path"

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
	repo  repoRef
	dec   *crypto.XelaDecrypter
	enc   *crypto.XelaEncrypter
}

type VaultRef struct {
	repoRef
}

func (v VaultRef) Name() string {
	return v.name
}

type ItemRef struct {
	path string
	kind ItemKind
}

type ItemKind int

const (
	ItemKindFile ItemKind = iota
	ItemKindDir
)

func (i ItemRef) Name() string {
	return path.Base(i.path)
}

func (i ItemRef) Kind() ItemKind {
	return i.kind
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
		vaults = append(vaults, VaultRef{repoRef: repo})
	}

	return vaults, nil
}

func (db *VaultDatabase) OpenVault(vault VaultRef, password []byte) (*Vault, error) {
	cryptJsonRef, err := db.repos.Ref(vault.repoRef, "crypt.json")
	if err != nil {
		return nil, err
	}

	cryptJsonBytes, err := db.repos.Read(vault.repoRef, cryptJsonRef)
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
		repo:  vault.repoRef,
		enc:   enc,
		dec:   dec,
	}, nil
}
