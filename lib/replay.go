// Anti replay mechanism
//

package gnocker

import (
	"errors"
	"time"
)

const AR_LEN = TS_HALF_WINDOW * 2

type SetU64 map[uint64]struct{}

type AntiReplay struct {
	known_vals [AR_LEN]SetU64
	ts_start   int64
	off        uint
}

func TsCur() int64 {
	return time.Now().UTC().Unix() - TS_HALF_WINDOW
}

func NewAntiReplay() AntiReplay {
	return NewAntiReplayCur(TsCur())
}

func NewAntiReplayCur(cur int64) AntiReplay {
	ret := AntiReplay{[AR_LEN]SetU64{}, 0, 0}
	ret.reset(cur)
	return ret
}

func (self *AntiReplay) reset(cur int64) {
	self.ts_start = cur
	self.known_vals = [AR_LEN]SetU64{}
	for i := 0; i < AR_LEN; i++ {
		self.known_vals[i] = SetU64{}
	}
	self.off = 0
}

func (self *AntiReplay) get_i(i uint) *SetU64 {
	return &self.known_vals[(self.off+i)%AR_LEN]
}

func (self *AntiReplay) get_ts(ts int64, cur int64) *SetU64 {
	if cur > ts {
		return nil
	}
	n := uint(ts - cur)
	if n >= AR_LEN {
		return nil
	}
	return self.get_i(n)
}

func (self *AntiReplay) collect(cur int64) {
	if self.ts_start > cur {
		return
	}
	n := uint(cur - self.ts_start)
	if n == 0 {
		return
	}
	if n >= AR_LEN {
		self.reset(cur)
		return
	}
	for i := uint(0); i < n; i++ {
		*self.get_i(i) = SetU64{}
	}
	self.off = (self.off + n) % AR_LEN
	self.ts_start = cur
}

func (self *AntiReplay) Check(ts int64, rnd uint64) error {
	cur := TsCur()
	return self.CheckCur(ts, rnd, cur)
}

func (self *AntiReplay) CheckCur(ts int64, rnd uint64, cur int64) error {
	self.collect(cur)
	bucket := self.get_ts(ts, cur)
	// Outside of range
	if bucket == nil {
		return errors.New("outside of accepted time range")
	}
	if _, ok := (*bucket)[rnd]; ok {
		// rnd is already in bucket => replay
		return errors.New("gnock packet replay")
	}
	(*bucket)[rnd] = struct{}{}
	return nil
}
