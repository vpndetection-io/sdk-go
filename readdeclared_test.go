// readDeclared on bare readers, which is how a body arrives: a bytes.Reader
// would hand io.Copy a single exact write and prove nothing about the buffer.

package vpndetection

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
	"testing/iotest"
)

// Only Read, so nothing reaches for WriteTo or ReadFrom.
type bare struct{ r io.Reader }

func (b bare) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestReadDeclaredFillsOneBufferOfTheDeclaredLength(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789"), 100)
	readers := map[string]func() io.Reader{
		"whole":      func() io.Reader { return bare{bytes.NewReader(body)} },
		"one byte":   func() io.Reader { return iotest.OneByteReader(bytes.NewReader(body)) },
		"halves":     func() io.Reader { return iotest.HalfReader(bytes.NewReader(body)) },
		"end inline": func() io.Reader { return iotest.DataErrReader(bytes.NewReader(body)) },
	}
	for name, reader := range readers {
		for _, prealloc := range []int64{int64(len(body)) * 2, int64(len(body)), 100, 7, 1} {
			got, err := readDeclared(reader(), int64(len(body)), prealloc)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("%s, prealloc %d: %d byte(s), %v", name, prealloc, len(got), err)
			}
			if cap(got) != len(body) {
				t.Errorf("%s, prealloc %d: capacity %d, want exactly %d: a grow went past the length",
					name, prealloc, cap(got), len(body))
			}
		}
	}
}

func TestReadDeclaredFailsABodyThatIsNotItsDeclaredLength(t *testing.T) {
	cases := map[string]struct {
		body     io.Reader
		declared int64
		want     error
	}{
		"short":                     {bare{bytes.NewReader(make([]byte, 40))}, 100, io.ErrUnexpectedEOF},
		"short, grown":              {bare{bytes.NewReader(make([]byte, 40))}, 100_000, io.ErrUnexpectedEOF},
		"empty":                     {bare{bytes.NewReader(nil)}, 1, io.ErrUnexpectedEOF},
		"long":                      {bare{bytes.NewReader(make([]byte, 20))}, 10, io.ErrUnexpectedEOF},
		"one past":                  {bare{bytes.NewReader(make([]byte, 11))}, 10, io.ErrUnexpectedEOF},
		"long for none":             {bare{bytes.NewReader(make([]byte, 1))}, 0, io.ErrUnexpectedEOF},
		"broken":                    {io.MultiReader(bytes.NewReader(make([]byte, 5)), iotest.ErrReader(errBroken)), 10, errBroken},
		"broken at end":             {io.MultiReader(bytes.NewReader(make([]byte, 10)), iotest.ErrReader(errBroken)), 10, errBroken},
		"a length past any machine": {bare{bytes.NewReader(nil)}, math.MaxInt64, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := readDeclared(tc.body, tc.declared, 4)
			if err == nil {
				t.Fatalf("a body that is not %d byte(s) came back as %d", tc.declared, len(got))
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
		})
	}
}

var errBroken = errors.New("connection reset")

func TestReadDeclaredReadsNothingButAnEmptyBodyForAZeroLength(t *testing.T) {
	got, err := readDeclared(bare{bytes.NewReader(nil)}, 0, 4)
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("an empty body: %v %v", got, err)
	}
}

// A length the server cannot back asks for at most eight times what arrived.
func TestAFullBufferGrowsByAtMostEightTimesWhatArrived(t *testing.T) {
	for _, tc := range []struct {
		arrived  int
		declared int64
		want     int64
	}{
		{64 << 20, 200 << 20, 200 << 20},
		{64 << 20, 1 << 30, 512 << 20},
		{512 << 20, 1 << 62, 4 << 30},
		{1, 1 << 62, 8},
	} {
		if got := grownCapacity(tc.arrived, tc.declared); got != tc.want {
			t.Errorf("grownCapacity(%d, %d) = %d, want %d", tc.arrived, tc.declared, got, tc.want)
		}
	}
}
