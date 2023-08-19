package binomial

import (
	"math"
	"math/big"
)

type Binomial interface {
	CDF(int64) *big.Rat
	Prob(int64) *big.Rat
}

type FastBinomial struct {
	w int64
	p float64
}

func NewFastBinomial(weight int64, p float64) *FastBinomial {
	return &FastBinomial{weight, p}
}

func (b *FastBinomial) Prob(k int64) float64 {
	if k > b.w/2 {
		k = b.w - k
	}
	var nu float64 = 1
	for n := b.w; n > b.w-k; n-- {
		nu *= float64(n)
	}
	var de float64 = 1
	for i := k; i > 0; i-- {
		de *= float64(i)
	}
	var logCombin float64
	if de == 0 {
		logCombin = 0
	} else {
		logCombin = math.Log(nu / de)
	}
	logProb := logCombin + float64(k)*math.Log(b.p) + float64(b.w-k)*math.Log(1-b.p)
	return math.Exp(logProb)
}
