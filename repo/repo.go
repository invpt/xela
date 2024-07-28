package repo

import (
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"
)

func hi() {
	_ = dotgit.New(osfs.New(".git"))
	git.Clone(nil, osfs.New("."), nil)
}
