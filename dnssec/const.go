package dnssec

type AuthenticationResult uint8

const (
	Unknown AuthenticationResult = iota
	Insecure
	Secure
	Bogus
)

type DenialOfExistenceState uint8

const (
	NotFound DenialOfExistenceState = iota

	NsecMissingDS
	NsecNoData
	NsecNxDomain
	NsecWildcard

	Nsec3MissingDS
	Nsec3NoData
	Nsec3NxDomain
	Nsec3OptOut
	Nsec3Wildcard
)

type section bool

const (
	answerSection    section = true
	authoritySection section = false
)
