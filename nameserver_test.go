package resolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock DNS Client
type MockDNSClient struct {
	mock.Mock
}

func (m *MockDNSClient) ExchangeContext(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	args := m.Called(ctx, msg, addr)
	return args.Get(0).(*dns.Msg), args.Get(1).(time.Duration), args.Error(2)
}

func TestExchangeWithClientFactory_ValidDNSMessage(t *testing.T) {
	// Setup
	ns := &nameserver{addr: "192.0.2.53"}

	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()
	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the ExchangeContext function to return the expected response and no error
	mockClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(expectedResponse, expectedDuration, nil)

	// Execute
	response := ns.exchangeWithClientFactory(ctx, msg, factory)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
}

func TestExchangeWithClientFactory_NilDNSMessage(t *testing.T) {
	// Setup
	ns := &nameserver{addr: "192.0.2.53"}

	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}

	ctx := context.TODO()

	// Execute
	response := ns.exchangeWithClientFactory(ctx, nil, factory)

	// Assertions
	assert.ErrorIs(t, response.Err, ErrNilMessageSentToExchange)
}

func TestExchangeWithClientFactory_DNSClientError(t *testing.T) {
	// Setup
	ns := &nameserver{addr: "192.0.2.53"}

	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()
	expectedError := errors.New("mock client error")

	// Mock the ExchangeContext function to return an error
	mockClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), expectedError)

	// Execute
	response := ns.exchangeWithClientFactory(ctx, msg, factory)

	// Assertions
	assert.Error(t, response.Err)
	assert.Equal(t, expectedError, response.Err)
}

func TestExchangeWithClientFactory_UDPErrorFallbackToTCP(t *testing.T) {
	// Setup
	ns := &nameserver{addr: "192.0.2.53"}

	udpClient := new(MockDNSClient)
	tcpClient := new(MockDNSClient)

	// Define the factory to return the correct client for each protocol
	factory := func(protocol string) dnsClient {
		if protocol == "udp" {
			return udpClient
		}
		return tcpClient
	}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the UDP client to return an error, and the TCP client to return a valid response
	udpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), errors.New("mock UDP error")).Once()
	tcpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(expectedResponse, expectedDuration, nil).Once()

	// Execute
	response := ns.exchangeWithClientFactory(ctx, msg, factory)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
	udpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
	tcpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestExchangeWithClientFactory_TruncatedResponseFallbackToTCP(t *testing.T) {
	// Setup
	ns := &nameserver{addr: "192.0.2.53"}

	udpClient := new(MockDNSClient)
	tcpClient := new(MockDNSClient)

	// Define the factory to return the correct client for each protocol
	factory := func(protocol string) dnsClient {
		if protocol == "udp" {
			return udpClient
		}
		return tcpClient
	}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	// Simulate a truncated response for UDP, which will force the function to retry with TCP
	truncatedResponse := &dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}}
	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the UDP client to return a truncated response, and the TCP client to return a valid response
	udpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(truncatedResponse, time.Duration(0), nil).Once()
	tcpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return(expectedResponse, expectedDuration, nil).Once()

	// Execute
	response := ns.exchangeWithClientFactory(ctx, msg, factory)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
	udpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
	tcpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestExchangeWithClientFactory_BothUDPAndTCPReturnErrors(t *testing.T) {
	// Setup
	ns := &nameserver{addr: "192.0.2.53"}

	udpClient := new(MockDNSClient)
	tcpClient := new(MockDNSClient)

	// Define the factory to return the correct client for each protocol
	factory := func(protocol string) dnsClient {
		if protocol == "udp" {
			return udpClient
		}
		return tcpClient
	}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	// Mock both UDP and TCP to return errors
	udpError := errors.New("mock UDP error")
	tcpError := errors.New("mock TCP error")

	udpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), udpError).Once()
	tcpClient.On("ExchangeContext", ctx, msg, "192.0.2.53:53").Return((*dns.Msg)(nil), time.Duration(0), tcpError).Once()

	// Execute
	response := ns.exchangeWithClientFactory(ctx, msg, factory)

	// Assertions
	assert.Error(t, response.Err)
	assert.Equal(t, tcpError, response.Err)
	udpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
	tcpClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}

func TestExchangeWithClientFactory_IPv6AddressFormatting(t *testing.T) {
	// Setup
	ns := &nameserver{addr: "2001:db8::1"}

	mockClient := new(MockDNSClient)
	factory := func(protocol string) dnsClient {
		return mockClient
	}

	// Prepare the DNS message with a valid question
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	ctx := context.TODO()

	expectedResponse := new(dns.Msg)
	expectedDuration := 10 * time.Millisecond

	// Mock the ExchangeContext to return a valid response
	mockClient.On("ExchangeContext", ctx, msg, "[2001:db8::1]:53").Return(expectedResponse, expectedDuration, nil).Once()

	// Execute
	response := ns.exchangeWithClientFactory(ctx, msg, factory)

	// Assertions
	assert.NoError(t, response.Err)
	assert.Equal(t, expectedResponse, response.Msg)
	assert.Equal(t, expectedDuration, response.Duration)
	mockClient.AssertNumberOfCalls(t, "ExchangeContext", 1)
}
