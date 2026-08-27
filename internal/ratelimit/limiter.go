package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	rpm   int
	burst int
	mu    sync.Mutex
	users map[string]*window
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

	w, ok := l.users[key]
	if !ok {
		w = &window{}
		l.users[key] = w
	}

	cutoff := now.Add(-time.Minute)
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
