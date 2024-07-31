package filesystem

import (
	"errors"
	"os"
	"path/filepath"

	"fixpt.org/xela/core"
)

var _ core.Vault[ItemRef] = &Vault{}

type Vault struct {
	basePath string
}

type ItemRef struct {
	path string
	kind core.ItemKind
}

func (r ItemRef) Name() string {
	return filepath.Base(r.path)
}

func (r ItemRef) Kind() core.ItemKind {
	return r.kind
}

var ErrNotExist error = os.ErrNotExist

func OpenVault(basePath string) *Vault {
	return &Vault{basePath: basePath}
}

func (v *Vault) Root() ItemRef {
	return ItemRef{path: "", kind: core.ItemKindDir}
}

func (v *Vault) List(where ItemRef) ([]ItemRef, error) {
	if where.kind != core.ItemKindDir {
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
			items = append(items, ItemRef{path: path, kind: core.ItemKindFile})
		} else if entry.Type().IsDir() {
			items = append(items, ItemRef{path: path, kind: core.ItemKindDir})
		}
	}

	return items, nil
}

func (v *Vault) Ref(where ItemRef, name string) (ItemRef, error) {
	if where.kind != core.ItemKindDir {
		return ItemRef{}, errors.New("xela/vault: cannot ref inside non-dir item")
	}

	// TODO: sanitize to prevent path escape?
	fsPath := filepath.Join(v.basePath, where.path, name)

	info, err := os.Stat(fsPath)
	if err != nil {
		return ItemRef{}, err
	}

	kind := core.ItemKindFile
	if info.IsDir() {
		kind = core.ItemKindDir
	}

	return ItemRef{
		path: name,
		kind: kind,
	}, nil
}

func (v *Vault) Create(where ItemRef, name string, kind core.ItemKind) (ItemRef, error) {
	if where.kind != core.ItemKindDir {
		return ItemRef{}, errors.New("xela/vault: cannot create inside non-dir item")
	}

	// TODO: sanitize to prevent path escape?
	fsPath := filepath.Join(v.basePath, where.path, name)

	if kind == core.ItemKindDir {
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

func (v *Vault) Read(file ItemRef) ([]byte, error) {
	if file.kind != core.ItemKindFile {
		return nil, errors.New("xela/vault: cannot read from non-file item")
	}

	fsPath := filepath.Join(v.basePath, file.path)

	return os.ReadFile(fsPath)
}

func (v *Vault) Write(file ItemRef, data []byte) error {
	if file.kind != core.ItemKindFile {
		return errors.New("xela/vault: cannot write to non-file item")
	}

	fsPath := filepath.Join(v.basePath, file.path)

	return os.WriteFile(fsPath, data, 0)
}

func (v *Vault) Delete(item ItemRef) error {
	return os.RemoveAll(item.path)
}
