package resolver

type CtxKey uint8

const (
	ctxSessionQueries CtxKey = iota
	ctxIteration
	ctxZoneName
)
