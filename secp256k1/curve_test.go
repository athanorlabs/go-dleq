package secp256k1

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

// SHA3-512 of these 8 bytes, read big-endian, reduces mod n to a value with a
// leading zero byte, so its minimal big-endian encoding is 31 bytes long.
func TestHashToScalar_ShortReduction(t *testing.T) {
	in := []byte{0, 0, 0, 0, 0, 0, 0, 0x6f}
	s, err := NewCurve().HashToScalar(in)
	require.NoError(t, err)
	require.Equal(t,
		"0042af3db512a071f2ae572aee980ec86262c5e04c94476d5993da9bc938dffa",
		hex.EncodeToString(s.Encode()),
	)
}

func TestHashToScalar_MatchesBigIntReduction(t *testing.T) {
	c := NewCurve().(*CurveImpl)
	in := make([]byte, 8)
	for i := uint64(0); i < 4096; i++ {
		binary.BigEndian.PutUint64(in, i)
		h := sha3.Sum512(in)
		want := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), c.order)

		s, err := c.HashToScalar(in)
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("%064x", want), hex.EncodeToString(s.Encode()), "input %d", i)
	}
}
