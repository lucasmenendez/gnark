// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"testing"

	curve "github.com/consensys/gnark-crypto/ecc/bls24-317"
	cs "github.com/consensys/gnark/constraint/bls24-317"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarkio "github.com/consensys/gnark/io"
	"github.com/stretchr/testify/require"
)

func TestContributionSerialization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	assert := require.New(t)

	// Phase 1
	srs1 := InitPhase1(9)
	srs1.Contribute()

	assert.NoError(gnarkio.RoundTripCheck(&srs1, func() interface{} { return new(Phase1) }))

	var myCircuit Circuit
	ccs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)

	r1cs := ccs.(*cs.R1CS)

	// Phase 2
	srs2, _ := InitPhase2(r1cs, &srs1)
	srs2.Contribute()

	assert.NoError(gnarkio.RoundTripCheck(&srs2, func() interface{} { return new(Phase2) }))
}
