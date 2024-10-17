package resolver

import (
	"github.com/miekg/dns"
)

var dnsRecordTypes = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	35:  "NAPTR",
	36:  "KX",
	37:  "CERT",
	39:  "DNAME",
	43:  "DS",
	46:  "RRSIG",
	47:  "NSEC",
	48:  "DNSKEY",
	50:  "NSEC3",
	51:  "NSEC3PARAM",
	257: "CAA",
}

func TypeToString(rrtype uint16) string {
	if name, ok := dnsRecordTypes[rrtype]; ok {
		return name
	} else {
		return "unknown"
	}
}

//---

var dnsRCodes = map[int]string{
	0:  "NoError",   // RcodeSuccess
	1:  "FormErr",   // RcodeFormatError
	2:  "ServFail",  // RcodeServerFailure
	3:  "NXDomain",  // RcodeNameError
	4:  "NotImp",    // RcodeNotImplemented
	5:  "Refused",   // RcodeRefused
	6:  "YXDomain",  // RcodeYXDomain
	7:  "YXRRSet",   // RcodeYXRrset
	8:  "NXRRSet",   // RcodeNXRrset
	9:  "NotAuth",   // RcodeNotAuth
	10: "NotZone",   // RcodeNotZone
	16: "BADSIG",    // RcodeBadSig and RcodeBadVers
	17: "BADKEY",    // RcodeBadKey
	18: "BADTIME",   // RcodeBadTime
	19: "BADMODE",   // RcodeBadMode
	20: "BADNAME",   // RcodeBadName
	21: "BADALG",    // RcodeBadAlg
	22: "BADTRUNC",  // RcodeBadTrunc
	23: "BADCOOKIE", // RcodeBadCookie
}

func RcodeToString(rcode int) string {
	if name, ok := dnsRCodes[rcode]; ok {
		return name
	} else {
		return "unknown"
	}
}

//---

func isSetDO(msg *dns.Msg) bool {
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			return opt.Do()
		}
	}
	return false
}

func canonicalName(name string) string {
	return dns.CanonicalName(name)
}

func extractRecords[T dns.RR](rr []dns.RR) []T {
	result := make([]T, 0, len(rr))
	for _, record := range rr {
		if typedRecord, ok := record.(T); ok {
			result = append(result, typedRecord)
		}
	}
	return result
}

func recordsOfTypeExist(rr []dns.RR, t uint16) bool {
	for _, record := range rr {
		if record.Header().Rrtype == t {
			return true
		}
	}
	return false
}
