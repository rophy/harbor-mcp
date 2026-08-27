package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	rpm          int
	burst        int
	mu           sync.Mutex
	users        map[string]*window
	sweepCounter int
}

type window struct {
	timestamps []time.Time
}

func New(rpm, burst int) *Limiter {
	return &Limiter{
		rpm:   rpm,
		burst: burst,
		users: make(map[string]*window),
	}
}

func (l *Limiter) Allow(key string) bool {
	return l.AllowAt(key, time.Now())
}

func (l *Limiter) AllowAt(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-time.Minute)

	// Evict inactive users every 1000 calls
	l.sweepCounter++
	if l.sweepCounter >= 1000 {
		l.sweepCounter = 0
		for k, w := range l.users {
			if len(w.timestamps) == 0 || w.timestamps[len(w.timestamps)-1].Before(cutoff) {
				delete(l.users, k)
			}
		}
	}

	w, ok := l.users[key]
	if !ok {
		w = &window{}
		l.users[key] = w
	}

	start := 0
	for start < len(w.timestamps) && w.timestamps[start].Before(cutoff) {
		start++
	}
	w.timestamps = w.timestamps[start:]

	limit := l.rpm + l.burst
	if len(w.timestamps) >= limit {
		return false
	}
	w.timestamps = append(w.timestamps, now)
	return true
}

func (l *Limiter) RPM() int {
	return l.rpm
}
