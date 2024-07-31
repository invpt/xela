package vault

import (
	"errors"
	"os"
	"path/filepath"
)

type repoDatabase struct {
	basePath string
}

type repoItemRef struct {
	path string
	kind ItemKind
}

func (r repoItemRef) Name() string {
	return filepath.Base(r.path)
}

var repoErrNotExist error = os.ErrNotExist

func openRepoDatabase(basePath string) *repoDatabase {
	return &repoDatabase{basePath: basePath}
}

func (rd *repoDatabase) ListRepos() ([]repoItemRef, error) {
	entries, err := os.ReadDir(rd.basePath)
	if err != nil {
		return nil, err
	}

	repos := make([]repoItemRef, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsDir() {
			repos = append(repos, repoItemRef{path: entry.Name(), kind: ItemKindDir})
		}
	}

	return repos, nil
}

func (rd *repoDatabase) ListItems(where repoItemRef) ([]repoItemRef, error) {
	if where.kind != ItemKindDir {
		return nil, errors.New("xela/vault: cannot list items in non-dir item")
	}

	searchPath := filepath.Join(rd.basePath, where.path)
	entries, err := os.ReadDir(searchPath)
	if err != nil {
		return nil, err
	}

	items := make([]repoItemRef, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(where.path, entry.Name())
		if entry.Type().IsRegular() {
			items = append(items, repoItemRef{path: path, kind: ItemKindFile})
		} else if entry.Type().IsDir() {
			items = append(items, repoItemRef{path: path, kind: ItemKindDir})
		}
	}

	return items, nil
}

func (rd *repoDatabase) Ref(where repoItemRef, name string) (repoItemRef, error) {
	if where.kind != ItemKindDir {
		return repoItemRef{}, errors.New("xela/vault: cannot ref inside non-dir item")
	}

	// TODO: sanitize to prevent path escape?
	fsPath := filepath.Join(rd.basePath, where.path, name)

	info, err := os.Stat(fsPath)
	if err != nil {
		return repoItemRef{}, err
	}

	kind := ItemKindFile
	if info.IsDir() {
		kind = ItemKindDir
	}

	return repoItemRef{
		path: name,
		kind: kind,
	}, nil
}

func (rd *repoDatabase) Create(where repoItemRef, name string, kind ItemKind) (repoItemRef, error) {
	if where.kind != ItemKindDir {
		return repoItemRef{}, errors.New("xela/vault: cannot create inside non-dir item")
	}

	// TODO: sanitize to prevent path escape?
	fsPath := filepath.Join(rd.basePath, where.path, name)

	if kind == ItemKindDir {
		err := os.Mkdir(fsPath, 0)
		if err != nil {
			return repoItemRef{}, err
		}
	} else {
		_, err := os.Create(fsPath)
		if err != nil {
			return repoItemRef{}, err
		}
	}

	return repoItemRef{
		path: filepath.Join(where.path, name),
		kind: kind,
	}, nil
}

func (rd *repoDatabase) Read(file repoItemRef) ([]byte, error) {
	if file.kind != ItemKindFile {
		return nil, errors.New("xela/vault: cannot read from non-file item")
	}

	fsPath := filepath.Join(rd.basePath, file.path)

	return os.ReadFile(fsPath)
}

func (rd *repoDatabase) Write(file repoItemRef, data []byte) error {
	if file.kind != ItemKindFile {
		return errors.New("xela/vault: cannot write to non-file item")
	}

	fsPath := filepath.Join(rd.basePath, file.path)

	return os.WriteFile(fsPath, data, 0)
}

func (rd *repoDatabase) Delete(item repoItemRef) error {
	return os.RemoveAll(item.path)
}
