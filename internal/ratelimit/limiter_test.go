package ratelimit

import (
	"testing"
	"time"
)

func TestAllow_UnderLimit(t *testing.T) {
	l := New(3, 0)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.AllowAt("alice", now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
}

func TestAllow_ExceedsLimit(t *testing.T) {
	l := New(3, 0)
	now := time.Now()
	for i := 0; i < 3; i++ {
		l.AllowAt("alice", now)
	}
	if l.AllowAt("alice", now) {
		t.Fatal("4th request should be rejected")
	}
}

func TestAllow_WindowExpiry(t *testing.T) {
	l := New(2, 0)
	now := time.Now()
	l.AllowAt("alice", now)
	l.AllowAt("alice", now)

	if l.AllowAt("alice", now) {
		t.Fatal("should be rejected within window")
	}

	later := now.Add(61 * time.Second)
	if !l.AllowAt("alice", later) {
		t.Fatal("should be allowed after window expires")
	}
}

func TestAllow_BurstAllowance(t *testing.T) {
	l := New(2, 3)
	now := time.Now()
	for i := 0; i < 5; i++ {
		if !l.AllowAt("alice", now) {
			t.Fatalf("request %d should be allowed (rpm+burst=5)", i)
		}
	}
	if l.AllowAt("alice", now) {
		t.Fatal("6th request should be rejected")
	}
}

func TestAllow_PerUserIsolation(t *testing.T) {
	l := New(1, 0)
	now := time.Now()
	if !l.AllowAt("alice", now) {
		t.Fatal("alice's first request should be allowed")
	}
	if !l.AllowAt("bob", now) {
		t.Fatal("bob's first request should be allowed")
	}
	if l.AllowAt("alice", now) {
		t.Fatal("alice's second request should be rejected")
	}
}

func TestRPM(t *testing.T) {
	l := New(42, 5)
	if l.RPM() != 42 {
		t.Fatalf("expected RPM=42, got %d", l.RPM())
	}
}
