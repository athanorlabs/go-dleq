package benchmarks

import (
	"testing"

	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/secp256k1"
	"github.com/athanorlabs/go-dleq/types"
	"golang.org/x/crypto/sha3"
)

var benchMsg = sha3.Sum256([]byte("benchmsg"))

func benchChallenge(b *testing.B, curve types.Curve) {
	p := curve.ScalarBaseMul(curve.NewRandomScalar())
	q := curve.ScalarBaseMul(curve.NewRandomScalar())
	dstL := make([]byte, curve.CompressedPointSize())
	dstR := make([]byte, curve.CompressedPointSize())

	eiP, okP := p.(types.PointEncodeInto)
	eiQ, okQ := q.(types.PointEncodeInto)

	b.Run("with_EncodeInto", func(b *testing.B) {
		if !(okP && okQ) {
			b.Skip("curve point does not implement types.PointEncodeInto")
		}
		buf := make([]byte, 32+len(dstL)+len(dstR))
		copy(buf[:32], benchMsg[:])
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			off := 32
			off += eiP.EncodeInto(buf[off : off+len(dstL)])
			_ = eiQ.EncodeInto(buf[off : off+len(dstR)])
			if _, err := curve.HashToScalar(buf); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("with_Encode", func(b *testing.B) {
		buf := make([]byte, 32+len(dstL)+len(dstR))
		copy(buf[:32], benchMsg[:])
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			off := 32
			L := p.Encode()
			copy(buf[off:off+len(dstL)], L)
			off += len(dstL)
			R := q.Encode()
			copy(buf[off:off+len(dstR)], R)
			if _, err := curve.HashToScalar(buf); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkChallenge_Secp256k1(b *testing.B) { benchChallenge(b, secp256k1.NewCurve()) }
func BenchmarkChallenge_Ed25519(b *testing.B)   { benchChallenge(b, ed25519.NewCurve()) }
