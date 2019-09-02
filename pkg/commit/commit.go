package commit

import (
	"bytes"
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
	tree, _, err := client.Git.CreateTree(ctx, options.RepoOwner, options.RepoName, s, options.Changes)
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
		if err := signCommit(commit, options.GpgPrivateKey, options.GpgPassphrase); err != nil {
			return err
		}
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

func signCommit(commit *github.Commit, privateKey string, passphrase string) error {

	// the payload must be "an over the string commit as it would be written to the object database"
	// we sign this data to verify the commit
	payload := fmt.Sprintf(
		`tree %s
parent %s
author %s <%s> %d +0000
committer %s <%s> %d +0000

%s`,
		commit.Tree.GetSHA(),
		commit.Parents[0].GetSHA(),
		commit.Author.GetName(),
		commit.Author.GetEmail(),
		commit.Author.Date.Unix(),
		commit.Author.GetName(),
		commit.Author.GetEmail(),
		commit.Author.Date.Unix(),
		commit.GetMessage(),
	)

	// sign the payload data
	signature, err := createSignature(payload, privateKey, passphrase)
	if err != nil {
		return err
	}

	commit.Verification = &github.SignatureVerification{
		Signature: signature,
	}

	return nil
}

func createSignature(data string, privateKey string, passphrase string) (*string, error) {

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

	out := new(bytes.Buffer)
	reader := strings.NewReader(data)
	if err := openpgp.ArmoredDetachSign(out, pk, reader, nil); err != nil {
		return nil, err
	}

	signature := string(out.Bytes())
	return &signature, nil
}
