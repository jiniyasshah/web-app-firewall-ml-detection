package limiter

import (
	"sync"
	"time"
)

type ClientStatus struct {
	CurrCount       int       // Requests in current window
	PrevCount       int       // Requests in previous window
	CurrWindowStart time.Time // When the current window started
}

type RateLimiter struct {
	clients map[string]*ClientStatus
	mu      sync.Mutex
	limit   float64       // Use float for precise calculation
	window  time.Duration // e.g., 1 Minute
}

func New(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*ClientStatus),
		limit:   float64(limit),
		window:  window,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	// Calculate which "window" slot we are in (e.g., the 12:05 slot)
	// Truncate floors the time to the nearest window interval
	currWindowStart := now.Truncate(rl.window)

	status, exists := rl.clients[ip]
	
	if !exists {
		// New user
		rl.clients[ip] = &ClientStatus{
			CurrCount:       1,
			CurrWindowStart: currWindowStart,
		}
		return true
	}

	// Check if we have moved to a new window since the last request
	if currWindowStart.After(status.CurrWindowStart) {
		// Calculate how many windows have passed
		elapsedWindows := currWindowStart.Sub(status.CurrWindowStart) / rl.window
		
		if elapsedWindows == 1 {
			// Normally moved to the immediate next window
			// The old "Current" becomes "Previous"
			status.PrevCount = status.CurrCount
			status.CurrCount = 0
		} else {
			// Skipped huge time (e.g., user away for 1 hour)
			// Both previous and current are effectively 0
			status.PrevCount = 0
			status.CurrCount = 0
		}
		status.CurrWindowStart = currWindowStart
	}

	// --- THE SLIDING WINDOW FORMULA ---
	// Calculate percentage of time elapsed in the current window
	timeIntoWindow := now.Sub(currWindowStart)
	// Percentage of the *previous* window that still "weighs" on us
	// If we are 10% into new window, 90% of previous window counts.
	prevWeight := float64(rl.window-timeIntoWindow) / float64(rl.window)

	estimatedRate := float64(status.PrevCount)*prevWeight + float64(status.CurrCount)

	if estimatedRate >= rl.limit {
		return false // Blocked
	}

	// Allowed: Increment count
	status.CurrCount++
	return true
}

// IsRateLimited returns true if the user is blocked
func (rl *RateLimiter) IsRateLimited(ip string) bool {
	return !rl.Allow(ip)
}