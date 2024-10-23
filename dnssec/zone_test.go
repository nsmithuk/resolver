package dnssec

import (
	"errors"
	"github.com/miekg/dns"
	"testing"
)

// MockZone is a mock implementation of the Zone interface
type MockZone struct {
	name             string
	lookupDNSKEYFunc func() ([]dns.RR, error)
}

func (m *MockZone) Name() string {
	return m.name
}

func (m *MockZone) GetDNSKEYRecords() ([]dns.RR, error) {
	if m.lookupDNSKEYFunc != nil {
		return m.GetDNSKEYRecords()
	}
	return nil, errors.New("no mock function provided for LookupDNSKEY")
}

func TestWrappedZone_Name(t *testing.T) {
	// Arrange
	mockZone := &MockZone{name: "mockzone.com."}
	wz := &wrappedZone{
		name:   "example.com.",
		parent: mockZone,
	}

	// Act
	result := wz.Name()

	// Assert
	if result != "example.com." {
		t.Errorf("expected name to be 'example.com.', got %s", result)
	}
}

//func TestWrappedZone_LookupDS(t *testing.T) {
//	// Arrange
//	mockZone := &MockZone{
//		lookupDSFunc: func(qname string) (*dns.Msg, error) {
//			msg := new(dns.Msg)
//			msg.Answer = []dns.RR{new(dns.DS)} // Simulate a DS record response
//			return msg, nil
//		},
//	}
//	wz := &wrappedZone{
//		name:   "example.com.",
//		parent: mockZone,
//	}
//
//	// Act
//	result, err := wz.LookupDS("example.com.")
//
//	// Assert
//	if err != nil {
//		t.Errorf("unexpected error: %v", err)
//	}
//	if result == nil {
//		t.Fatalf("expected a non-nil dns.Msg, got nil")
//	}
//	if len(result.Answer) != 1 {
//		t.Errorf("expected 1 DS record, got %d", len(result.Answer))
//	}
//}

//func TestWrappedZone_LookupDNSKEY(t *testing.T) {
//	// Arrange
//	mockZone := &MockZone{
//		lookupDNSKEYFunc: func() ([]dns.RR, error) {
//			return []dns.RR{new(dns.DNSKEY)}, nil // Simulate a DNSKEY record response
//		},
//	}
//	wz := &wrappedZone{
//		name:   "example.com.",
//		parent: mockZone,
//	}
//
//	// Act
//	result, err := wz.GetDNSKEYRecords()
//
//	// Assert
//	if err != nil {
//		t.Errorf("unexpected error: %v", err)
//	}
//	if result == nil {
//		t.Fatalf("expected a non-nil result, got nil")
//	}
//	if len(result) != 1 {
//		t.Errorf("expected 1 DNSKEY record, got %d", len(result))
//	}
//}
