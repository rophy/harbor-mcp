package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllow_UnderLimit(t *testing.T) {
	l := New(3, 0)
	now := time.Now()
	for i := 0; i < 3; i++ {
		assert.True(t, l.AllowAt("alice", now.Add(time.Duration(i)*time.Second)), "request %d should be allowed", i)
	}
}

func TestAllow_ExceedsLimit(t *testing.T) {
	l := New(3, 0)
	now := time.Now()
	for i := 0; i < 3; i++ {
		l.AllowAt("alice", now)
	}
	assert.False(t, l.AllowAt("alice", now), "4th request should be rejected")
}

func TestAllow_WindowExpiry(t *testing.T) {
	l := New(2, 0)
	now := time.Now()
	l.AllowAt("alice", now)
	l.AllowAt("alice", now)

	assert.False(t, l.AllowAt("alice", now), "should be rejected within window")

	later := now.Add(61 * time.Second)
	assert.True(t, l.AllowAt("alice", later), "should be allowed after window expires")
}

func TestAllow_BurstAllowance(t *testing.T) {
	l := New(2, 3)
	now := time.Now()
	for i := 0; i < 5; i++ {
		assert.True(t, l.AllowAt("alice", now), "request %d should be allowed (rpm+burst=5)", i)
	}
	assert.False(t, l.AllowAt("alice", now), "6th request should be rejected")
}

func TestAllow_PerUserIsolation(t *testing.T) {
	l := New(1, 0)
	now := time.Now()
	require.True(t, l.AllowAt("alice", now))
	require.True(t, l.AllowAt("bob", now))
	assert.False(t, l.AllowAt("alice", now), "alice's second request should be rejected")
}

func TestRPM(t *testing.T) {
	l := New(42, 5)
	assert.Equal(t, 42, l.RPM())
}
