package dnssec

import "errors"

var (
	ErrNoDSRecords                     = errors.New("no DS records passed")
	ErrUnableToFetchDSRecord           = errors.New("unable to fetch missing DS record")
	ErrKeysNotFound                    = errors.New("no dnskey records found for zone")
	ErrKeySigningKeysNotFound          = errors.New("no dnskey records found that match the parent ds records")
	ErrAuthSignerNameMissmatch         = errors.New("auth signer name does match the zone's origin")
	ErrSignatureSetEmpty               = errors.New("cannot verify an empty signature set")
	ErrUnableToVerify                  = errors.New("unable to verify signature")
	ErrInvalidTime                     = errors.New("current time is outside of the msg validity period")
	ErrInvalidSignature                = errors.New("msg signature is invalid")
	ErrInvalidLabelCount               = errors.New("number of labels in the rrset owner name is less the value in the rrsig rr's labels field")
	ErrMultipleVaryingSignerNames      = errors.New("rrsigs in the response contain multiple varying signer names")
	ErrNSRecordsHaveMissmatchingOwners = errors.New("the ns records in the authority section do not have matching owners")
	ErrFailsafeResponse                = errors.New("unable to determine if response is delegating, positive or negative. we fail-safe to bogus")
	ErrUnexpectedSignatureCount        = errors.New("an unexpected number of rrsig records were found given the rrsets seen")
	ErrMultipleWildcardSignatures      = errors.New("multiple wildcard signatures seen")
	ErrDSLookupLoop                    = errors.New("the maximum number of ds record lookups has been reached")

	ErrSignerNameNotParentOfQName = errors.New("the signer name is not a parent of the qname")

	ErrBogusResultFound        = errors.New("we've deemed the result bogus")
	ErrBogusDoeRecordsNotFound = errors.New("denial of existence records missing")
)
