package gnocker

import (
	"testing"
)

func TestAntiReplay(t *testing.T) {
	cur := TsCur()
	ar := NewAntiReplayCur(cur)

	for i := int64(0); i < TS_HALF_WINDOW*2; i++ {
		err := ar.CheckCur(cur+i, 1, cur)
		if err != nil {
			t.Fatalf("anti replay unexpected error (off %d): %v", i, err)
		}
	}
	err := ar.CheckCur(cur, 1, cur)
	if err == nil {
		t.Fatalf("anti replay expected error")
	}

	err = ar.CheckCur(cur, 2, cur+1)
	if err == nil {
		t.Fatalf("anti replay expected error")
	}

	err = ar.CheckCur(cur+1, 1, cur+1)
	if err == nil {
		t.Fatalf("anti replay expected error")
	}

	err = ar.CheckCur(cur+1, 2, cur+1)
	if err != nil {
		t.Fatalf("anti replay unexpected error: %v", err)
	}

	err = ar.CheckCur(cur+TS_HALF_WINDOW*2+1, 1, cur+TS_HALF_WINDOW*2)
	if err != nil {
		t.Fatalf("anti replay unexpected error: %v", err)
	}
}
