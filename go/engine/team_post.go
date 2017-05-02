// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package engine

import (
	"github.com/keybase/client/go/libkb"
	jsonw "github.com/keybase/go-jsonw"
)

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

	id := libkb.RootTeamIDFromName(e.name)
	teamSection := libkb.TeamSection{
		Name: e.name,
		ID:   id,
	}
	teamSection.Members.Owner = []string{me.GetName()}
	teamSection.Members.Admin = []string{}
	teamSection.Members.Writer = []string{}
	teamSection.Members.Reader = []string{}
	teamSection.SharedKey.Boxes = map[string]string{}

	ephemeralPair, err := libkb.GenerateNaclDHKeyPair()
	if err != nil {
		return err
	}
	teamSection.SharedKey.E = ephemeralPair.Public.GetKID().String()
	teamSection.SharedKey.Gen = 1

	innerJSON, err := me.TeamRootSig(sigKey, teamSection)
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

	// TODO MAKE A STRUCT
	sigMultiItem := jsonw.NewDictionary()
	sigMultiItem.SetKey("sig", jsonw.NewString(sig))
	sigMultiItem.SetKey("signing_kid", jsonw.NewString(sigKey.GetKID().String()))
	sigMultiItem.SetKey("type", jsonw.NewString(string(v1LinkType)))
	sigMultiItem.SetKey("sig_inner", jsonw.NewString(string(innerJSONBytes)))
	sigMultiItem.SetKey("team_id", jsonw.NewString(libkb.RootTeamIDFromName(e.name)))

	sigMultiList := jsonw.NewArray(1)
	err = sigMultiList.SetIndex(0, sigMultiItem)
	if err != nil {
		return err
	}

	sigsBytes, err := sigMultiList.Marshal()
	sigsString := string(sigsBytes)
	if err != nil {
		return err
	}

	_, err = e.G().API.Post(libkb.APIArg{
		Endpoint:    "key/multi",
		SessionType: libkb.APISessionTypeREQUIRED,
		Args: libkb.HTTPArgs{
			"sigs": libkb.S{Val: sigsString},
		},
	})
	if err != nil {
		return err
	}

	return nil
}
