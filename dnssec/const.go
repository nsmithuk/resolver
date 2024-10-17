package dnssec

type AuthenticationResult uint8

const (
	Unknown AuthenticationResult = iota
	Insecure
	Secure
	Bogus
	Indeterminate
)

type DenialOfExistenceState uint8

const (
	NotFound DenialOfExistenceState = iota

	NsecMissingDS
	NsecNoData
	NsecNxDomain

	Nsec3MissingDS
	Nsec3NoData
	Nsec3NxDomain
	Nsec3OptOut
)

type section bool

const (
	answerSection    section = true
	authoritySection section = false
)

type output uint8

const (
	Continue output = iota
	IsSecure
	IsBogus
	IsIndeterminate
	IsError
)
