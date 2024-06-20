package plonk

import (
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	iciclecore "github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	iciclebn254 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	iciclemsm "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/msm"
)

func projectiveToGnarkAffine(p iciclebn254.Projective) curve.G1Affine {
	px, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.X).ToBytesLittleEndian()))
	py, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.Y).ToBytesLittleEndian()))
	pz, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)((&p.Z).ToBytesLittleEndian()))

	zInv := new(fp.Element)
	x := new(fp.Element)
	y := new(fp.Element)

	zInv.Inverse(&pz)

	x.Mul(&px, zInv)
	y.Mul(&py, zInv)

	return curve.G1Affine{X: *x, Y: *y}
}

func IcicleCommit(s []fr.Element, p iciclecore.DeviceSlice) (commit curve.G1Affine) {
	var out iciclecore.DeviceSlice
	out.Malloc(iciclebn254.ProjectiveBytes, iciclebn254.ProjectiveBytes)

	cfg := iciclemsm.GetDefaultMSMConfig()
	cfg.AreScalarsMontgomeryForm = true
	cfg.ArePointsMontgomeryForm = true

	iciclemsm.Msm((iciclecore.HostSlice[fr.Element])(s), p, &cfg, out)

	outHost := make(iciclecore.HostSlice[iciclebn254.Projective], 1)
	outHost.CopyFromDevice(&out)

	return projectiveToGnarkAffine(outHost[0])
}
