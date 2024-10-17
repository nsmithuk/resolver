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
	Auth     dnssec.AuthenticationResult
	Duration time.Duration
}

func (r *Response) Error() bool {
	return r.Err != nil
}

func (r *Response) Empty() bool {
	return r.Msg == nil
}

func (r *Response) Truncated() bool {
	if r.Empty() {
		return false
	}
	return r.Msg.Truncated
}

func ResponseError(err error) Response {
	return Response{
		Err: err,
	}
}

//---

type exchanger interface {
	exchange(context.Context, *dns.Msg) Response
}

type expiringExchanger interface {
	exchanger
	expired() bool
}
