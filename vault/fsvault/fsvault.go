package fsvault

import (
	"errors"
	"os"
	"path/filepath"

	"fixpt.org/xela/vault"
)

var _ vault.Vault[ItemRef] = &FSVault{}

type FSVault struct {
	basePath string
}

type ItemRef struct {
	path string
	kind vault.ItemKind
}

func (r ItemRef) Name() string {
	return filepath.Base(r.path)
}

func (r ItemRef) Kind() vault.ItemKind {
	return r.kind
}

var ErrNotExist error = os.ErrNotExist

func Create(basePath string) *FSVault {
	os.MkdirAll(basePath, 0)
	return Open(basePath)
}

func Open(basePath string) *FSVault {
	return &FSVault{basePath: basePath}
}

func (v *FSVault) BasePath() string {
	return v.basePath
}

func (v *FSVault) Root() ItemRef {
	return ItemRef{path: "", kind: vault.ItemKindDir}
}

func (v *FSVault) List(where ItemRef) ([]ItemRef, error) {
	if where.kind != vault.ItemKindDir {
		return nil, errors.New("xela/vault: cannot list items in non-dir item")
	}

	searchPath := filepath.Join(v.basePath, where.path)
	entries, err := os.ReadDir(searchPath)
	if err != nil {
		return nil, err
	}

	items := make([]ItemRef, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(where.path, entry.Name())
		if entry.Type().IsRegular() {
			items = append(items, ItemRef{path: path, kind: vault.ItemKindFile})
		} else if entry.Type().IsDir() {
			items = append(items, ItemRef{path: path, kind: vault.ItemKindDir})
		}
	}

	return items, nil
}

func (v *FSVault) Ref(where ItemRef, name string) (ItemRef, error) {
	if where.kind != vault.ItemKindDir {
		return ItemRef{}, errors.New("xela/vault: cannot ref inside non-dir item")
	}

	// TODO: sanitize to prevent path escape?
	fsPath := filepath.Join(v.basePath, where.path, name)

	info, err := os.Stat(fsPath)
	if err != nil {
		return ItemRef{}, err
	}

	kind := vault.ItemKindFile
	if info.IsDir() {
		kind = vault.ItemKindDir
	}

	return ItemRef{
		path: name,
		kind: kind,
	}, nil
}

func (v *FSVault) Create(where ItemRef, name string, kind vault.ItemKind) (ItemRef, error) {
	if where.kind != vault.ItemKindDir {
		return ItemRef{}, errors.New("xela/vault: cannot create inside non-dir item")
	}

	// TODO: sanitize to prevent path escape?
	fsPath := filepath.Join(v.basePath, where.path, name)

	if kind == vault.ItemKindDir {
		err := os.Mkdir(fsPath, 0)
		if err != nil {
			return ItemRef{}, err
		}
	} else {
		_, err := os.Create(fsPath)
		if err != nil {
			return ItemRef{}, err
		}
	}

	return ItemRef{
		path: filepath.Join(where.path, name),
		kind: kind,
	}, nil
}

func (v *FSVault) Read(file ItemRef) ([]byte, error) {
	if file.kind != vault.ItemKindFile {
		return nil, errors.New("xela/vault: cannot read from non-file item")
	}

	fsPath := filepath.Join(v.basePath, file.path)

	return os.ReadFile(fsPath)
}

func (v *FSVault) Write(file ItemRef, data []byte) error {
	if file.kind != vault.ItemKindFile {
		return errors.New("xela/vault: cannot write to non-file item")
	}

	fsPath := filepath.Join(v.basePath, file.path)

	return os.WriteFile(fsPath, data, 0)
}

func (v *FSVault) Delete(item ItemRef) error {
	return os.RemoveAll(item.path)
}
