// Package eventservice provides the durable event envelope, a transactional
// outbox simulation, and a replay/dedup consumer (DESIGN §6.10).
package eventservice

import (
	"sync"

	"github.com/agent-sandbox/platform/domain"
)

// Outbox is an append-only durable event log. Callers append within the same
// critical section as the state change, simulating transactional atomicity.
type Outbox struct {
	mu     sync.Mutex
	events []domain.Event
}

func NewOutbox() *Outbox { return &Outbox{} }

// Append records an event and returns its sequence cursor.
func (o *Outbox) Append(ev domain.Event) int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, ev)
	return int64(len(o.events))
}

// Replay returns events after cursor, plus the new cursor.
func (o *Outbox) Replay(cursor int64) ([]domain.Event, int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if cursor < 0 {
		cursor = 0
	}
	if cursor > int64(len(o.events)) {
		cursor = int64(len(o.events))
	}
	out := make([]domain.Event, len(o.events)-int(cursor))
	copy(out, o.events[cursor:])
	return out, int64(len(o.events))
}

func (o *Outbox) Len() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return int64(len(o.events))
}

// Consumer replays the outbox from a cursor and dedups by event_id
// (at-least-once delivery safe).
type Consumer struct {
	cursor int64
	seen   map[string]bool
}

func NewConsumer() *Consumer {
	return &Consumer{seen: map[string]bool{}}
}

// Poll returns newly delivered events, deduplicated by event_id.
func (c *Consumer) Poll(o *Outbox) []domain.Event {
	events, next := o.Replay(c.cursor)
	c.cursor = next
	var fresh []domain.Event
	for _, ev := range events {
		if c.seen[ev.EventID] {
			continue
		}
		c.seen[ev.EventID] = true
		fresh = append(fresh, ev)
	}
	return fresh
}

// Reset moves the consumer back to the start, keeping the dedup set.
func (c *Consumer) Reset() { c.cursor = 0 }
