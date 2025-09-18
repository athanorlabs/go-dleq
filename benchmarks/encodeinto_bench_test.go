package benchmarks

import (
	"testing"

	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/secp256k1"
	"github.com/athanorlabs/go-dleq/types"
)

func benchEncodePair(b *testing.B, curve types.Curve) {
	p := curve.ScalarBaseMul(curve.NewRandomScalar())
	dst := make([]byte, curve.CompressedPointSize())

	ei, ok := p.(types.PointEncodeInto)
	if !ok {
		b.Skip("curve point does not implement types.PointEncodeInto")
	}

	b.Run("EncodeInto", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			n := ei.EncodeInto(dst)
			if n != len(dst) {
				b.Fatalf("unexpected length: got %d want %d", n, len(dst))
			}
		}
	})

	b.Run("Encode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			out := p.Encode()
			if len(out) != len(dst) {
				b.Fatalf("unexpected length: got %d want %d", len(out), len(dst))
			}
		}
	})
}

func BenchmarkEncodeInto_vs_Encode_Secp256k1(b *testing.B) {
	benchEncodePair(b, secp256k1.NewCurve())
}

func BenchmarkEncodeInto_vs_Encode_Ed25519(b *testing.B) {
	benchEncodePair(b, ed25519.NewCurve())
}
