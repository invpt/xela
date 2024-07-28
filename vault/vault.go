package vault

import (
	"os"

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

func Open(basePath string) *VaultDatabase {
	return &VaultDatabase{basePath: basePath}
}

func (db *VaultDatabase) ListVaults() ([]string, error) {
	entries, err := os.ReadDir(db.basePath)
	if err != nil {
		return nil, err
	}

	repos := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsDir() {
			repos = append(repos, entry.Name())
		}
	}

	return repos, nil
}

func (r *VaultDatabase) ListItems(vault string) {

}
