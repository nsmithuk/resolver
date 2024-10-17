package resolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestZones_Get_ExistingZoneWithValidPool(t *testing.T) {
	// Setup
	z := &zone{name: "example.com."}
	mockPool := new(MockExpiringExchanger)
	z.pool = mockPool

	mockPool.On("expired").Return(false)

	zs := &zones{
		zones: map[string]*zone{"example.com.": z},
	}

	// Execute
	result := zs.get("example.com.")

	// Assertions: Should return the existing zone since the pool is valid
	assert.NotNil(t, result)
	assert.Equal(t, z, result)
}

func TestZones_Get_NonExistingZone(t *testing.T) {
	// Setup: Empty zones map
	zs := &zones{
		zones: make(map[string]*zone),
	}

	// Execute
	result := zs.get("nonexistent.com.")

	// Assertions: Should return nil since the zone does not exist
	assert.Nil(t, result)
}

func TestZones_Get_ExistingZoneWithExpiredPool(t *testing.T) {
	// Setup
	z := &zone{name: "example.com."}
	mockPool := new(MockExpiringExchanger)
	z.pool = mockPool

	// Mock the pool to return expired
	mockPool.On("expired").Return(true)

	zs := &zones{
		zones: map[string]*zone{"example.com.": z},
	}

	// Execute
	result := zs.get("example.com.")

	// Assertions: Should return nil since the pool has expired
	assert.Nil(t, result)
}

func TestZones_Add_NewZone(t *testing.T) {
	// Setup: Empty zones map
	zs := &zones{
		zones: make(map[string]*zone),
	}
	newZone := &zone{name: "newzone.com."}

	// Execute
	zs.add(newZone)

	// Assertions: The new zone should be added to the map
	assert.NotNil(t, zs.zones["newzone.com."])
	assert.Equal(t, newZone, zs.zones["newzone.com."])
}

func TestZones_Add_ZoneToUninitializedMap(t *testing.T) {
	// Setup: Uninitialized zones map
	zs := &zones{}
	newZone := &zone{name: "uninitialized.com."}

	// Execute
	zs.add(newZone)

	// Assertions: The new zone should be added and the map should be initialized
	assert.NotNil(t, zs.zones["uninitialized.com."])
	assert.Equal(t, newZone, zs.zones["uninitialized.com."])
}
