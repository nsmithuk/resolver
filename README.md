# resolver

A recursive DNS resolver with a Go-based API, designed to handle domain name resolution from the root nameservers.
It includes support for DNSSEC validation via the dnssec package, which ensures the authenticity 
and integrity of DNS responses. Please note that the dnssec package will eventually be moved to its own 
dedicated project.

Current Status: This is an alpha release and remains a work in progress. Users should expect potential 
changes and improvements as development continues.  It is not recommended to rely on this project for
security-critical applications at this stage.

# Licence
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Also see:
- [github.com/miekg/dns license](https://github.com/miekg/dns/blob/master/LICENSE)
