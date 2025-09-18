package dleq

import (
	"bytes"
	"testing"

	"github.com/athanorlabs/go-dleq/ed25519"
	"github.com/athanorlabs/go-dleq/secp256k1"
	"github.com/athanorlabs/go-dleq/types"
)

// --- helpers ---

func allCurves() []types.Curve {
	return []types.Curve{
		secp256k1.NewCurve(),
		ed25519.NewCurve(),
	}
}

func mustEqualPoints(t *testing.T, a, b types.Point) {
	t.Helper()
	if !a.Equals(b) {
		t.Fatalf("points are not equal")
	}
}

func encodeViaIntoOrFallback(curve types.Curve, p types.Point) []byte {
	size := curve.CompressedPointSize()
	dst := make([]byte, size)
	if ei, ok := p.(types.PointEncodeInto); ok {
		n := ei.EncodeInto(dst)
		return dst[:n]
	}
	// Fallback: legacy API
	enc := p.Encode()
	copy(dst, enc)
	return dst
}

// --- tests ---

func TestEncodeInto_SizeAndRoundTrip(t *testing.T) {
	for _, curve := range allCurves() {
		// Create a non-trivial point: P = x*G
		x := curve.NewRandomScalar()
		P := curve.ScalarBaseMul(x)

		// Encode using EncodeInto (or fallback, if ever missing)
		out := encodeViaIntoOrFallback(curve, P)

		// Size must match CompressedPointSize()
		if want, got := curve.CompressedPointSize(), len(out); want != got {
			t.Fatalf("compressed size mismatch: want %d, got %d", want, got)
		}

		// Decoding must round-trip to the same point
		P2, err := curve.DecodeToPoint(out)
		if err != nil {
			t.Fatalf("DecodeToPoint failed: %v", err)
		}
		mustEqualPoints(t, P, P2)
	}
}

func TestEncodeInto_MatchesEncodeBytes(t *testing.T) {
	for _, curve := range allCurves() {
		x := curve.NewRandomScalar()
		P := curve.ScalarBaseMul(x)

		viaInto := encodeViaIntoOrFallback(curve, P)
		viaEncode := P.Encode()

		if !bytes.Equal(viaInto, viaEncode) {
			t.Fatalf("EncodeInto bytes differ from Encode() for curve: %#v", curve)
		}
	}
}

// --- micro-benchmarks ---

func BenchmarkPointEncodeInto_Secp256k1(b *testing.B) {
	curve := secp256k1.NewCurve()
	p := curve.ScalarBaseMul(curve.NewRandomScalar())

	ei, ok := p.(types.PointEncodeInto)
	if !ok {
		b.Skip("secp256k1 point does not implement EncodeInto")
	}
	dst := make([]byte, curve.CompressedPointSize())

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ei.EncodeInto(dst)
	}
}

func BenchmarkPointEncode_Secp256k1(b *testing.B) {
	curve := secp256k1.NewCurve()
	p := curve.ScalarBaseMul(curve.NewRandomScalar())

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Encode()
	}
}

func BenchmarkPointEncodeInto_Ed25519(b *testing.B) {
	curve := ed25519.NewCurve()
	p := curve.ScalarBaseMul(curve.NewRandomScalar())

	ei, ok := p.(types.PointEncodeInto)
	if !ok {
		b.Skip("ed25519 point does not implement EncodeInto")
	}
	dst := make([]byte, curve.CompressedPointSize())

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ei.EncodeInto(dst)
	}
}

func BenchmarkPointEncode_Ed25519(b *testing.B) {
	curve := ed25519.NewCurve()
	p := curve.ScalarBaseMul(curve.NewRandomScalar())

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Encode()
	}
}
