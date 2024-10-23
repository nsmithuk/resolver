package dnssec

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver/dnssec/doe"
	"slices"
	"strings"
)

func (v verifier) verify(ctx context.Context, zone Zone, msg *dns.Msg, dsRecordsFromParent []*dns.DS) (AuthenticationResult, *result, error) {
	r := &result{
		name: zone.Name(),
		zone: zone,
		msg:  msg,
	}

	if len(dsRecordsFromParent) == 0 {
		return Insecure, r, nil // TODO: I'm not really sure this is an error. It's often expected once the chain breaks.
		//return Insecure, r, ErrNoParentDSRecords
	}

	// Verify DNSKEYS
	// Verify all other RRSETs
	// Delegating Answer check
	// Positive Answer check
	// Negative Answer check

	var status AuthenticationResult

	keys, err := zone.GetDNSKEYRecords()
	if err != nil {
		return status, r, err
	}

	status, err = v.verifyDNSKEYs(ctx, r, keys, dsRecordsFromParent)
	if status != Unknown || err != nil {
		return status, r, err
	}

	status, err = v.verifyRRSETs(ctx, r, extractRecords[*dns.DNSKEY](keys))
	if status != Unknown || err != nil {
		return status, r, err
	}

	status, err = v.validateDelegatingResponse(ctx, r)
	if status != Unknown || err != nil {
		return status, r, err
	}

	status, err = v.validatePositiveResponse(ctx, r)
	if status != Unknown || err != nil {
		return status, r, err
	}

	status, err = v.validateNegativeResponse(ctx, r)
	if status != Unknown || err != nil {
		return status, r, err
	}

	// We should never get here. If we do, the response was likely malformed. We'll fail-safe to Bogus.
	return Bogus, r, ErrFailsafeResponse
}

//

func verifyDNSKEYs(ctx context.Context, r *result, keys []dns.RR, dsRecordsFromParent []*dns.DS) (AuthenticationResult, error) {

	zoneKeys := extractRecords[*dns.DNSKEY](keys)
	if len(zoneKeys) == 0 {
		return Insecure, ErrKeysNotFound
	}

	//---

	// keySigningKeys are the zone's keys have a matching DS record from the parent zone.
	// These are the keys that are allowed to sign the DNSKEY rrset.
	keySigningKeys := make([]*dns.DNSKEY, 0, len(dsRecordsFromParent))
	for _, d := range dsRecordsFromParent {
		for _, k := range zoneKeys {
			if d.Algorithm == k.Algorithm && d.KeyTag == k.KeyTag() && strings.EqualFold(d.Digest, k.ToDS(d.DigestType).Digest) {
				keySigningKeys = append(keySigningKeys, k)
				break
			}
		}
	}

	if len(keySigningKeys) == 0 {
		return Insecure, ErrKeysNotFound
	}

	//---

	keySignatures, err := authenticate(r.zone.Name(), keys, keySigningKeys, answerSection)

	if err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	r.keys = keySignatures

	if err = keySignatures.Verify(); err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	return Unknown, nil
}

func verifyRRSETs(ctx context.Context, r *result, keys []*dns.DNSKEY) (AuthenticationResult, error) {

	answerSignatures, err := authenticate(r.zone.Name(), r.msg.Answer, keys, answerSection)
	if err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	authoritySignatures, err := authenticate(r.zone.Name(), r.msg.Ns, keys, authoritySection)
	if err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	recordSignatures := slices.Concat(answerSignatures, authoritySignatures)

	if err = recordSignatures.Verify(); err != nil {
		return Bogus, fmt.Errorf("%w: %w", ErrBogusResultFound, err)
	}

	r.answer = answerSignatures
	r.authority = authoritySignatures

	return Unknown, nil
}

func validateDelegatingResponse(ctx context.Context, r *result) (status AuthenticationResult, err error) {

	nsRecordsFound := recordsOfTypeExist(r.msg.Ns, dns.TypeNS)

	if nsRecordsFound && len(r.msg.Answer) == 0 && recordsOfTypeExist(r.msg.Ns, dns.TypeDS) {
		nsRecods := extractRecordsOfType(r.msg.Ns, dns.TypeNS)
		if !recordsHaveTheSameOwner(nsRecods) {
			return Bogus, ErrNSRecordsHaveMissmatchingOwners
		}

		// We extract any delegation DS records that we might have found.
		r.dsRecords = r.authority.extractDSRecords()

		return Secure, nil
	}

	// If we have NS records, but no DS records, we need to ensure there's denial of existence on those DS records.
	if nsRecordsFound && len(r.msg.Answer) == 0 {

		nsec := doe.NewDenialOfExistenceNSEC(ctx, r.zone.Name(), r.authority.extractNSECRecords())
		nsec3 := doe.NewDenialOfExistenceNSEC3(ctx, r.zone.Name(), r.authority.extractNSEC3Records())

		if nsec.Empty() && nsec3.Empty() {
			return Bogus, ErrBogusDoeRecordsNotFound
		}

		nsRecods := extractRecordsOfType(r.msg.Ns, dns.TypeNS)
		if !recordsHaveTheSameOwner(nsRecods) {
			return Bogus, ErrNSRecordsHaveMissmatchingOwners
		}

		delegationName := nsRecods[0].Header().Name

		/*
			https://datatracker.ietf.org/doc/html/rfc5155#section-8.9
			If there is an NSEC3 RR present in the response that matches the
			delegation name, then the validator MUST ensure that the NS bit is
			set and that the DS bit is not set in the Type Bit Maps field of the
			NSEC3 RR.  The validator MUST also ensure that the NSEC3 RR is from
			the correct (i.e., parent) zone.  This is done by ensuring that the
			SOA bit is not set in the Type Bit Maps field of this NSEC3 RR.

			Note that the presence of an NS bit implies the absence of a DNAME
			bit, so there is no need to check for the DNAME bit in the Type Bit
			Maps field of the NSEC3 RR.
		*/

		if !nsec.Empty() {
			// The Type Bit Map must show there are NS records, but there are no CNAME, DS or SOA records.
			if nameSeen, typeSeen := nsec.TypeBitMapContainsAnyOf(delegationName, []uint16{dns.TypeNS}); nameSeen && typeSeen {
				if nameSeen, typeSeen = nsec.TypeBitMapContainsAnyOf(delegationName, []uint16{dns.TypeCNAME, dns.TypeDS, dns.TypeSOA}); nameSeen && !typeSeen {
					r.denialOfExistence = NsecMissingDS
					return Secure, nil
				}
			}
		}

		if !nsec3.Empty() {
			// The Type Bit Map must show there are NS records, but there are no CNAME, DS or SOA records.
			if nameSeen, typeSeen := nsec3.TypeBitMapContainsAnyOf(delegationName, []uint16{dns.TypeNS}); nameSeen && typeSeen {
				if nameSeen, typeSeen = nsec3.TypeBitMapContainsAnyOf(delegationName, []uint16{dns.TypeCNAME, dns.TypeDS, dns.TypeSOA}); nameSeen && !typeSeen {
					r.denialOfExistence = Nsec3MissingDS
					return Secure, nil
				}
			}

			if optedOut, _, _, _ := nsec3.PerformClosestEncloserProof(delegationName); optedOut {
				// We have found an opt-out, thus we will conclude any children are insecure.
				r.denialOfExistence = Nsec3OptOut
				return Secure, nil
			}
		}

	}

	return Unknown, nil
}

func validatePositiveResponse(ctx context.Context, r *result) (status AuthenticationResult, err error) {

	if len(r.msg.Answer) > 0 && !recordsOfTypeExist(r.msg.Ns, dns.TypeSOA) {

		// We extract any delegation DS records that we might have found.
		r.dsRecords = r.answer.extractDSRecords()

		nsec := doe.NewDenialOfExistenceNSEC(ctx, r.zone.Name(), r.authority.extractNSECRecords())
		nsec3 := doe.NewDenialOfExistenceNSEC3(ctx, r.zone.Name(), r.authority.extractNSEC3Records())

		wildcardSignaturesSeen := false
		wildcardSignaturesVerified := false
		for _, sig := range r.answer {
			if sig.wildcard {

				// TODO: this check needs to ensure only one RRSET has been expanded, as there
				// can be multiple

				if wildcardSignaturesSeen {
					// More than one wildcard signature is suspicious
					return Bogus, ErrMultipleWildcardSignatures
				}

				wildcardSignaturesSeen = true

				nsecVerified := false
				nsec3Verified := false

				if !nsec.Empty() {
					nsecVerified = nsec.PerformExpandedWildcardProof(r.msg.Question[0].Name)
				}
				if !nsec3.Empty() {
					nsec3Verified = nsec3.PerformExpandedWildcardProof(sig.name, sig.rrsig.Labels)
				}
				if nsecVerified || nsec3Verified {
					wildcardSignaturesVerified = true
				}

			}
		}

		// Then this implies that the specific QNAME didn't exist, so we expect a NSEC(3) record proving that.
		// https://datatracker.ietf.org/doc/html/rfc5155#section-8.8
		if wildcardSignaturesSeen && !wildcardSignaturesVerified {
			return Bogus, nil
		} else {
			return Secure, nil
		}
	}

	return Unknown, nil
}

func validateNegativeResponse(ctx context.Context, r *result) (AuthenticationResult, error) {

	if recordsOfTypeExist(r.msg.Ns, dns.TypeSOA) {

		qname := r.msg.Question[0].Name
		qtype := r.msg.Question[0].Qtype

		nsec := doe.NewDenialOfExistenceNSEC(ctx, r.zone.Name(), r.authority.extractNSECRecords())
		nsec3 := doe.NewDenialOfExistenceNSEC3(ctx, r.zone.Name(), r.authority.extractNSEC3Records())

		if nsec.Empty() && nsec3.Empty() {
			return Bogus, ErrBogusDoeRecordsNotFound
		}

		if !nsec.Empty() {
			if nameSeen, typeSeen := nsec.TypeBitMapContainsAnyOf(qname, []uint16{dns.TypeCNAME, qtype}); nameSeen && !typeSeen {
				r.denialOfExistence = NsecNoData
				return Secure, nil
			}

			if nsec.PerformQNameDoesNotExistProof(qname) {
				r.denialOfExistence = NsecNxDomain
				return Secure, nil
			}
		}

		if !nsec3.Empty() {
			// Check for a NODATA response on the QName.
			if nameSeen, typeSeen := nsec3.TypeBitMapContainsAnyOf(qname, []uint16{dns.TypeCNAME, qtype}); nameSeen && !typeSeen {
				r.denialOfExistence = Nsec3NoData
				return Secure, nil
			}

			/*
				https://datatracker.ietf.org/doc/html/rfc5155#section-8.7

				The validator MUST verify a closest encloser proof for QNAME and MUST
				find an NSEC3 RR present in the response that matches the wildcard
				name generated by prepending the asterisk label to the closest
				encloser.  Furthermore, the bits corresponding to both QTYPE and
				CNAME MUST NOT be set in the wildcard matching NSEC3 RR.
			*/
			// Check for a NODATA response on a wildcard.
			if closestEncloser, _, ok := nsec3.FindClosestEncloser(qname); ok {
				if nameSeen, typeSeen := nsec3.TypeBitMapContainsAnyOf("*."+closestEncloser, []uint16{dns.TypeCNAME, qtype}); nameSeen && !typeSeen {
					r.denialOfExistence = Nsec3NoData
					return Secure, nil
				}
			}

			if optedOut, closestEncloserProof, nextCloserNameProof, wildcardProof := nsec3.PerformClosestEncloserProof(qname); optedOut {
				r.denialOfExistence = Nsec3OptOut
				return Secure, nil
			} else if closestEncloserProof && nextCloserNameProof && wildcardProof {
				r.denialOfExistence = Nsec3NxDomain
				return Secure, nil
			}
		}

	}

	return Unknown, nil
}
