package vault

import (
	"errors"
	"os"
	"path"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"
)

func hi() {
	_ = dotgit.New(osfs.New(".git"))
	git.Clone(nil, osfs.New("."), nil)
}

type VaultDatabase struct {
	basePath string
}

type VaultRef struct {
	name string
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
	return &VaultDatabase{basePath: basePath}
}

func (db *VaultDatabase) ListVaults() ([]VaultRef, error) {
	entries, err := os.ReadDir(db.basePath)
	if err != nil {
		return nil, err
	}

	repos := make([]VaultRef, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsDir() {
			repos = append(repos, VaultRef{name: entry.Name()})
		}
	}

	return repos, nil
}

func (db *VaultDatabase) ListItems(vault VaultRef, dirs ...ItemRef) ([]ItemRef, error) {
	if len(dirs) > 1 {
		return nil, errors.New("xela/vault: cannot list items in multiple dirs")
	}

	dirPath := ""
	if len(dirs) != 0 {
		if dirs[0].kind != ItemKindDir {
			return nil, errors.New("xela/vault: cannot list items in non-dir item")
		}

		dirPath = dirs[0].path
	}

	searchPath := path.Join(db.basePath, vault.name, dirPath)
	entries, err := os.ReadDir(searchPath)
	if err != nil {
		return nil, err
	}

	items := make([]ItemRef, 0, len(entries))
	for _, entry := range entries {
		path := path.Join(dirPath, entry.Name())
		if entry.Type().IsRegular() {
			items = append(items, ItemRef{path: path, kind: ItemKindFile})
		} else if entry.Type().IsDir() {
			items = append(items, ItemRef{path: path, kind: ItemKindDir})
		}
	}

	return items, nil
}
