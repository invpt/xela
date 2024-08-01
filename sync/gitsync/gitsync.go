package gitsync

import (
	"fixpt.org/xela/vault/fsvault"
	git "github.com/libgit2/git2go/v34"
)

func Clone(from string, into string) (*fsvault.FSVault, error) {
	_, err := git.Clone("", into, &git.CloneOptions{})
	if err != nil {
		return nil, err
	}

	return fsvault.Open(into), nil
}
