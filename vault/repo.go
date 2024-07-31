package vault

import (
	"errors"
	"os"
	"path/filepath"
)

type repoDatabase struct {
	basePath string
}

type repoRef struct {
	name string
}

type repoItemRef struct {
	path string
	kind ItemKind
}

var repoErrNotExist error = os.ErrNotExist

func openRepoDatabase(basePath string) *repoDatabase {
	return &repoDatabase{basePath: basePath}
}

func (rd *repoDatabase) ListRepos() ([]repoRef, error) {
	entries, err := os.ReadDir(rd.basePath)
	if err != nil {
		return nil, err
	}

	repos := make([]repoRef, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsDir() {
			repos = append(repos, repoRef{name: entry.Name()})
		}
	}

	return repos, nil
}

func (rd *repoDatabase) ListItems(repo repoRef, dirs ...repoItemRef) ([]repoItemRef, error) {
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

	searchPath := filepath.Join(rd.basePath, repo.name, dirPath)
	entries, err := os.ReadDir(searchPath)
	if err != nil {
		return nil, err
	}

	items := make([]repoItemRef, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(dirPath, entry.Name())
		if entry.Type().IsRegular() {
			items = append(items, repoItemRef{path: path, kind: ItemKindFile})
		} else if entry.Type().IsDir() {
			items = append(items, repoItemRef{path: path, kind: ItemKindDir})
		}
	}

	return items, nil
}

func (rd *repoDatabase) Ref(repo repoRef, name string) (repoItemRef, error) {
	// TODO: sanitize to prevent path escape?
	fsPath := filepath.Join(rd.basePath, repo.name, name)

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

func (rd *repoDatabase) Read(repo repoRef, file repoItemRef) ([]byte, error) {
	if file.kind != ItemKindFile {
		return nil, errors.New("xela/vault: cannot read from non-file item")
	}

	fsPath := filepath.Join(rd.basePath, repo.name, file.path)

	return os.ReadFile(fsPath)
}

func (rd *repoDatabase) Write(repo repoRef, file repoItemRef, data []byte) error {
	if file.kind != ItemKindFile {
		return errors.New("xela/vault: cannot write to non-file item")
	}

	fsPath := filepath.Join(rd.basePath, repo.name, file.path)

	return os.WriteFile(fsPath, data, 0)
}

func (rd *repoDatabase) Delete(repo repoRef, item repoItemRef) error {
	return os.RemoveAll(item.path)
}
