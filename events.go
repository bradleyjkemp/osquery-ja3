package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kolide/osquery-go/plugin/table"
)

var eventsLock sync.Mutex
var events []handshakeEvent

type handshakeEvent struct {
	time           time.Time
	ja3, ja3s, sni string
}

func logHandshake(ja3, ja3s, sni string) {
	if *verbose {
		fmt.Printf("%s -> %s [%s]\n", ja3, ja3s, sni)
	}
	eventsLock.Lock()
	defer eventsLock.Unlock()

	// In case events are never queried, do a quick cleanup here too
	cleanOldEvents()

	events = append(events, handshakeEvent{
		time.Now(),
		ja3, ja3s, sni,
	})
}

func generateEventsTable(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	eventsLock.Lock()
	defer eventsLock.Unlock()

	cleanOldEvents()

	// this is very inneficient, we should use the provided queryContext to only return events within the time range requested
	rows := make([]map[string]string, 0, len(events))
	for _, event := range events {
		rows = append(rows, map[string]string{
			"time": fmt.Sprint(event.time.Unix()),
			"ja3":  event.ja3,
			"ja3s": event.ja3s,
			"sni":  event.sni,
		})
	}
	return rows, nil
}

func cleanOldEvents() {
	firstRetainedEvent := 0
	for i, event := range events {
		if time.Now().Sub(event.time) < eventRetentionPeriod {
			// This event is within the retention period so all the later ones will be too
			break
		}
		firstRetainedEvent = i
	}
	events = events[firstRetainedEvent:]
}
