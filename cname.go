package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
)

func cname(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger) error {
	cnames := extractRecords[*dns.CNAME](r.Msg.Answer)
	Debug(fmt.Sprintf("resolved %s to %d cnames", qmsg.Question[0].Name, len(cnames)))

	for _, c := range cnames {
		target := dns.CanonicalName(c.Target)

		if recordsOfNameAndTypeExist(r.Msg.Answer, target, qmsg.Question[0].Qtype) || recordsOfNameAndTypeExist(r.Msg.Answer, target, dns.TypeCNAME) {
			// Skip over the answer already contains a record for the target.
			continue
		}

		qmsgCNAME := new(dns.Msg)
		qmsgCNAME.SetQuestion(target, qmsg.Question[0].Qtype)

		if isSetDO(qmsg) {
			qmsgCNAME.SetEdns0(4096, true)
		}

		rmsgCNAME := exchanger.exchange(ctx, qmsgCNAME)

		if rmsgCNAME.Error() {
			return rmsgCNAME.Err
		}
		if rmsgCNAME.Empty() {
			return fmt.Errorf("unable to follow cname [%s]", c.Target)
		}

		r.Msg.Answer = append(r.Msg.Answer, rmsgCNAME.Msg.Answer...)
		r.Msg.Ns = append(r.Msg.Ns, rmsgCNAME.Msg.Ns...)
		r.Msg.Extra = append(r.Msg.Extra, rmsgCNAME.Msg.Extra...)

		r.Auth = r.Auth.Combine(rmsgCNAME.Auth)
	}

	return nil
}
