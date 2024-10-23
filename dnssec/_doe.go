package dnssec

import (
	"context"
	"github.com/miekg/dns"
)

type denialOfExistenceNSEC struct {
	ctx     context.Context
	zone    string
	records []*dns.NSEC
}

type denialOfExistenceNSEC3 struct {
	ctx     context.Context
	zone    string
	records []*dns.NSEC3
}

func newDenialOfExistenceNSEC(ctx context.Context, zone string, ss signatures) *denialOfExistenceNSEC {
	set := ss.filterOnType(dns.TypeNSEC)
	records := make([]*dns.NSEC, len(set))
	for i, s := range set {
		records[i] = s.rrset[0].(*dns.NSEC)
	}
	return &denialOfExistenceNSEC{
		ctx,
		zone,
		records,
	}
}

func newDenialOfExistenceNSEC3(ctx context.Context, zone string, ss signatures) *denialOfExistenceNSEC3 {
	set := ss.filterOnType(dns.TypeNSEC3)
	records := make([]*dns.NSEC3, 0, len(set))
	for _, s := range set {
		record := s.rrset[0].(*dns.NSEC3)

		// We must ignore records that have unknown hash or flag values.
		if record.Hash != dns.SHA1 {
			continue
		}
		if record.Flags < 0 || record.Flags > 1 {
			continue
		}

		records = append(records, record)
	}
	return &denialOfExistenceNSEC3{
		ctx,
		zone,
		records,
	}
}

//----------------------------------------------------------

func (doe *denialOfExistenceNSEC) empty() bool {
	return len(doe.records) == 0
}

func (doe *denialOfExistenceNSEC3) empty() bool {
	return len(doe.records) == 0
}
