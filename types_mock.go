package resolver

import (
	"context"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/mock"
)

// Mock expiringExchanger to simulate pool expiration behavior and DNS message exchange
type MockExpiringExchanger struct {
	mock.Mock
}

// Mock the expired function
func (m *MockExpiringExchanger) expired() bool {
	args := m.Called()
	return args.Bool(0)
}

// Mock the exchange function to simulate DNS message exchange
func (m *MockExpiringExchanger) exchange(ctx context.Context, msg *dns.Msg) Response {
	args := m.Called(ctx, msg)
	return args.Get(0).(Response)
}
