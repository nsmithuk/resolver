package resolver

import (
	"context"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec"
	"time"
)

type Response struct {
	Msg      *dns.Msg
	Err      error
	Duration time.Duration
	Deo      dnssec.DenialOfExistenceState
	Auth     dnssec.AuthenticationResult
}

func (r *Response) Error() bool {
	return r != nil && r.Err != nil
}

func (r *Response) Empty() bool {
	return r == nil || r.Msg == nil
}

func (r *Response) truncated() bool {
	if r.Empty() {
		return false
	}
	return r.Msg.Truncated
}

func ResponseError(err error) *Response {
	return &Response{
		Err: err,
	}
}

//---

type exchanger interface {
	exchange(context.Context, *dns.Msg) *Response
}

type expiringExchanger interface {
	exchanger
	expired() bool
}
