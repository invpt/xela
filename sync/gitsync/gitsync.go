package gitsync

import (
	"fixpt.org/xela/vault/fsvault"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

func Clone(from string, into string, auth transport.AuthMethod) (*fsvault.FSVault, error) {
	_, err := git.PlainClone(into, false, &git.CloneOptions{
		URL:  from,
		Auth: auth,
	})
	if err != nil {
		return nil, err
	}
	return fsvault.Open(into), nil
}
