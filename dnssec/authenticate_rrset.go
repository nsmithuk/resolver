package dnssec

import (
	"fmt"
	"github.com/miekg/dns"
	"time"
)

func authenticate(zone string, rrsets []dns.RR, dnskeys []*dns.DNSKEY, section section) (signatures, error) {
	zone = dns.CanonicalName(zone)

	rrsigs := extractRecords[*dns.RRSIG](rrsets)
	signatures := make([]*signature, len(rrsigs))

	for i, rrsig := range rrsigs {
		sig := signature{
			zone:  zone,
			name:  rrsig.Header().Name,
			rtype: rrsig.TypeCovered,
			rrsig: rrsig,
			rrset: extractRecordsOfNameAndType(rrsets, rrsig.Header().Name, rrsig.TypeCovered),
		}
		signatures[i] = &sig

		if dns.CanonicalName(sig.zone) != dns.CanonicalName(rrsig.SignerName) {
			sig.err = fmt.Errorf("%w: zone:[%s] SignerName:[%s]", ErrAuthSignerNameMissmatch, sig.zone, rrsig.SignerName)
			continue
		}

		// Iterate over all the DNS keys and see if one will sign it?
		for _, key := range dnskeys {
			if key.Algorithm == rrsig.Algorithm && key.KeyTag() == rrsig.KeyTag && dns.CanonicalName(rrsig.SignerName) == zone {

				if dns.CountLabel(rrsig.Header().Name) < int(rrsig.Labels) {
					sig.err = fmt.Errorf("%w: owner name has %d labels and the rrsig labels field is %d", ErrInvalidLabelCount, dns.CountLabel(rrsig.Header().Name), rrsig.Labels)
					continue
				}

				if dns.CountLabel(rrsig.Header().Name) > int(rrsig.Labels) {
					sig.wildcard = true
				}

				if !rrsig.ValidityPeriod(time.Now()) {
					sig.err = fmt.Errorf("%w: msg valid %s to %s", ErrInvalidTime, dns.TimeToString(rrsig.Inception), dns.TimeToString(rrsig.Expiration))
					continue
				}

				sig.err = rrsig.Verify(key, sig.rrset)

				if sig.err != nil {
					// We'll wrap the error
					sig.err = fmt.Errorf("%w: %w", ErrInvalidSignature, sig.err)
				} else {
					// The signature was verified.
					sig.key = key
					sig.verified = true
					sig.dsSha256 = key.ToDS(dns.SHA256).Digest
					break
				}
			}
		}
	}

	//-------------------------

	/*
		https://datatracker.ietf.org/doc/html/rfc4035#section-2.2
		There MUST be an RRSIG for each RRset...
	*/

	type combination struct {
		name   string
		rrtype uint16
	}

	combinations := make(map[combination]bool, len(signatures))

	// So the number of Name+Type combinations should equal the number of signatures we have.
	for _, rrset := range rrsets {
		// We don't sign NS records
		if rrset.Header().Rrtype == dns.TypeRRSIG || (rrset.Header().Rrtype == dns.TypeNS && section == authoritySection) {
			continue
		}
		combinations[combination{
			name:   rrset.Header().Name,
			rrtype: rrset.Header().Rrtype,
		}] = true
	}

	var err error
	if len(combinations) != len(signatures) {
		err = fmt.Errorf("%w: we found %d signatures but %d valid name+type combinations", ErrUnexpectedSignatureCount, len(signatures), len(combinations))
	}

	return signatures, err
}
