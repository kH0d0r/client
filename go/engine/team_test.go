// Copyright 2017 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package engine

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostNewTeam(t *testing.T) {
	tc := SetupEngineTest(t, "crypto")
	defer tc.Cleanup()

	u := CreateAndSignupFakeUser(tc, "teams")

	teamName := u.Username + "_team"
	eng := NewNewTeamEngine(tc.G, teamName)

	ctx := &Context{
		LogUI:    tc.G.UI.GetLogUI(),
		SecretUI: u.NewSecretUI(),
	}
	err := eng.Run(ctx)

	require.NoError(t, err)
}
