package dnssec

import "github.com/miekg/dns"

func (a *Authenticator) Result() (AuthenticationResult, DenialOfExistenceState, error) {
	a.finished.Store(true)
	a.processing.Wait()
	defer a.Close()

	// If we have no answers at all we have nothing to go on, thus we don't know what the status is.
	if len(a.results) == 0 {
		return Unknown, NotFound, nil
	}

	//-----------------------------------------------------------
	// If any result was Bogus, then Bogus.

	for _, r := range a.results {
		if r.state == Bogus {
			return Bogus, NotFound, r.err
		}
	}

	//-----------------------------------------------------------
	// If the chain moved from Secure to Insecure,
	// there must be Denial of Existence - otherwise Bogus.

	for i, r := range a.results {
		if r.state == Secure {
			continue
		}

		if i == 0 {
			// If the first result was not secure, we might as well give up now.
			return r.state, r.denialOfExistence, r.err
		}

		lastResult := a.results[i-1]

		// TODO: is lastResult.denialOfExistence != NotFound correct?

		//if lastResult.denialOfExistence == Nsec3OptOut {
		//	// If the denial of existence was an opt-out, the best we can conclude is Insecure.
		//	return Insecure, lastResult.denialOfExistence, r.err
		//}
		//
		//// We expect the NSEC proof for a missing DS.
		//if lastResult.denialOfExistence == NsecMissingDS || lastResult.denialOfExistence == Nsec3MissingDS {
		//	return Insecure, lastResult.denialOfExistence, r.err
		//}

		// We'll accept any form of DOE.
		if lastResult.denialOfExistence != NotFound {
			return Insecure, lastResult.denialOfExistence, r.err
		}

		return Bogus, lastResult.denialOfExistence, r.err
	}

	//-----------------------------------------------------------
	// We're now just interested in the last result...

	last := a.results[len(a.results)-1]

	if last.state != Secure {
		return last.state, last.denialOfExistence, last.err
	}

	if last.denialOfExistence == Nsec3OptOut {
		return Insecure, last.denialOfExistence, last.err
	}

	// If there was DOE found...
	if last.denialOfExistence != NotFound {
		return Secure, last.denialOfExistence, last.err
	}

	//-----------------------------------------------------------
	// We now expect a positive answer

	// We should see no SOA.
	if recordsOfTypeExist(last.msg.Ns, dns.TypeSOA) {
		return Bogus, last.denialOfExistence, last.err
	}

	if len(extractRecordsOfNameAndType(last.msg.Answer, a.question.Name, a.question.Qtype)) > 0 {
		return Secure, last.denialOfExistence, last.err
	}

	if len(extractRecordsOfNameAndType(last.msg.Answer, a.question.Name, dns.TypeCNAME)) > 0 {
		return Secure, last.denialOfExistence, last.err
	}

	// We default to worse case.
	return Bogus, last.denialOfExistence, last.err
}
