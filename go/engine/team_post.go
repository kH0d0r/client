// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package engine

import "github.com/keybase/client/go/libkb"

type NewTeamEngine struct {
	libkb.Contextified
	name string
}

func NewNewTeamEngine(g *libkb.GlobalContext, name string) *NewTeamEngine {
	return &NewTeamEngine{
		Contextified: libkb.NewContextified(g),
		name:         name,
	}
}

func (e *NewTeamEngine) Name() string {
	return "NewTeam"
}

func (e *NewTeamEngine) Prereqs() Prereqs {
	return Prereqs{
		Device: true,
	}
}

func (e *NewTeamEngine) RequiredUIs() []libkb.UIKind {
	return []libkb.UIKind{
		libkb.LogUIKind,
		libkb.SecretUIKind,
	}
}

func (e *NewTeamEngine) SubConsumers() []libkb.UIConsumer {
	return []libkb.UIConsumer{}
}

func (e *NewTeamEngine) Run(ctx *Context) (err error) {
	defer e.G().Trace("NewTeamEngine", func() error { return err })()

	me, err := libkb.LoadMe(libkb.NewLoadUserArg(e.G()))
	if err != nil {
		return err
	}

	ska := libkb.SecretKeyArg{
		Me:      me,
		KeyType: libkb.DeviceSigningKeyType,
	}
	sigKey, err := e.G().Keyrings.GetSecretKeyWithPrompt(ctx.SecretKeyPromptArg(ska, "to create a new team"))
	if err != nil {
		return err
	}
	if err = sigKey.CheckSecretKey(); err != nil {
		return err
	}

	innerJSON, err := me.TeamRootSig(sigKey, e.name)
	if err != nil {
		return err
	}

	innerJSONBytes, err := innerJSON.Marshal()
	if err != nil {
		return err
	}

	linkID := libkb.ComputeLinkID(innerJSONBytes)

	v1LinkType := libkb.LinkTypeTeamRoot
	v2LinkType, err := libkb.SigchainV2TypeFromV1TypeAndRevocations(string(v1LinkType), false)
	if err != nil {
		return err
	}

	outerLink := libkb.OuterLinkV2{
		Version:  2,
		Seqno:    1,
		Prev:     nil,
		Curr:     linkID,
		LinkType: v2LinkType,
	}
	encodedOuterLink, err := outerLink.Encode()
	if err != nil {
		return err
	}

	sig, _, err := sigKey.SignToString(encodedOuterLink)
	if err != nil {
		return err
	}

	_, err = e.G().API.Post(libkb.APIArg{
		Endpoint:    "sig/post",
		SessionType: libkb.APISessionTypeREQUIRED,
		Args: libkb.HTTPArgs{
			"sig":             libkb.S{Val: sig},
			"signing_kid":     libkb.S{Val: sigKey.GetKID().String()},
			"is_remote_proof": libkb.B{Val: false},
			"type":            libkb.S{Val: string(v1LinkType)},
			"sig_inner":       libkb.S{Val: string(innerJSONBytes)},
		},
	})
	if err != nil {
		return err
	}

	return nil
}
