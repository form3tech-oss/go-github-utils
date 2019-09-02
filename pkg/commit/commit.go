package commit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/form3tech-oss/go-github-utils/pkg/branch"
	"github.com/google/go-github/v28/github"
	"golang.org/x/crypto/openpgp"
)

const (
	branchPrefix = "refs/heads/"
)

type CommitOptions struct {
	RepoOwner                   string
	RepoName                    string
	CommitMessage               string
	GpgPassphrase               string
	GpgPrivateKey               string // detached armor format
	Changes                     []github.TreeEntry
	BaseTreeOverride            *string  // Pointer so we can use "" as the override.
	Branch                      string
	Username                    string
	Email                       string
	RetryCount                  int
	PullRequestSourceBranchName string
	PullRequestBody             string
}

func CreateCommit(ctx context.Context, client *github.Client, options *CommitOptions) error {
	// Use the default branch if none is specified.
	b := options.Branch
	if b == "" {
		v, err := branch.GetDefaultBranch(ctx, client, options.RepoOwner, options.RepoName)
		if err != nil {
			return err
		}
		b = v
	}

	// Get the SHA for the target branch.
	s, err := branch.GetSHAForBranch(ctx, client, options.RepoOwner, options.RepoName, b)
	if err != nil {
		return err
	}

	// create tree containing required changes
	baseTree := s
	if options.BaseTreeOverride != nil {
		baseTree = *options.BaseTreeOverride
	}
	tree, _, err := client.Git.CreateTree(ctx, options.RepoOwner, options.RepoName, baseTree, options.Changes)
	if err != nil {
		return err
	}

	// get parent commit
	parent, _, err := client.Repositories.GetCommit(ctx, options.RepoOwner, options.RepoName, s)
	if err != nil {
		return err
	}

	// This is not always populated, but is needed.
	parent.Commit.SHA = github.String(parent.GetSHA())

	date := time.Now()
	author := &github.CommitAuthor{
		Date:  &date,
		Name:  github.String(options.Username),
		Email: github.String(options.Email),
	}

	commit := &github.Commit{
		Author:  author,
		Message: &options.CommitMessage,
		Tree:    tree,
		Parents: []github.Commit{*parent.Commit},
	}

	if options.GpgPrivateKey != "" {
		k, err := readGPGPrivateKey(options.GpgPrivateKey, options.GpgPassphrase)
		if err != nil {
			return err
		}
		commit.SigningKey = k
	}

	newCommit, _, err := client.Git.CreateCommit(ctx, options.RepoOwner, options.RepoName, commit)
	if err != nil {
		return err
	}

	prBranchName := options.PullRequestSourceBranchName
	if prBranchName == "" {
		prBranchName = fmt.Sprintf("go-github-utils-%d", time.Now().UnixNano())
	}
	if !strings.HasPrefix(prBranchName, branchPrefix) {
		prBranchName = fmt.Sprintf("%s%s", branchPrefix, prBranchName)
	}
	prBranch := &github.Reference{
		Ref: github.String(prBranchName),
		Object: &github.GitObject{
			SHA: newCommit.SHA,
		},
	}

	prRef, _, err := client.Git.CreateRef(ctx, options.RepoOwner, options.RepoName, prBranch)
	if err != nil {
		return err
	}

	pr, _, err := client.PullRequests.Create(ctx, options.RepoOwner, options.RepoName, &github.NewPullRequest{
		Title:               github.String(options.CommitMessage),
		Head:                prBranch.Ref,
		Base:                github.String(b),
		Body:                github.String(options.PullRequestBody),
		MaintainerCanModify: github.Bool(false),
	})
	if err != nil {
		return err
	}

	_, response, err := client.PullRequests.Merge(ctx, options.RepoOwner, options.RepoName, pr.GetNumber(), commit.GetMessage(), nil)
	if err != nil {

		pr.State = github.String("closed")
		_, _, _ = client.PullRequests.Edit(ctx, options.RepoOwner, options.RepoName, pr.GetNumber(), pr)

		if response == nil {
			return fmt.Errorf("failed to merge PR: %s", err)
		}

		// base branch was likely modified, try again
		if response.StatusCode == 405 && options.RetryCount < 3 {
			options.RetryCount++ // don't retry again
			return CreateCommit(ctx, client, options)
		}

		return fmt.Errorf("failed to merge PR: HTTP %d: %s", response.StatusCode, err)
	}

	// PR was merged, so we can attempt to remove our working branch (ignore failures, this isn't vital)
	_, _ = client.Git.DeleteRef(ctx, options.RepoOwner, options.RepoName, prRef.GetRef())

	return nil
}

func readGPGPrivateKey(privateKey string, passphrase string) (*openpgp.Entity, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(privateKey))
	if err != nil {
		return nil, err
	}

	pk := entityList[0]
	ppb := []byte(passphrase)

	if pk.PrivateKey != nil && pk.PrivateKey.Encrypted {
		err := pk.PrivateKey.Decrypt(ppb)
		if err != nil {
			return nil, err
		}
	}

	for _, subKey := range pk.Subkeys {
		if subKey.PrivateKey != nil && subKey.PrivateKey.Encrypted {
			err := subKey.PrivateKey.Decrypt(ppb)
			if err != nil {
				return nil, err
			}
		}
	}
	return pk, nil
}
