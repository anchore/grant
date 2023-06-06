package bus

import "github.com/wagoodman/go-partybus"

var publisher partybus.Publisher

// Set sets the singleton event bus publisher. This is optional; if no bus is provided, the library will
// behave no differently than if a bus had been provided.
func Set(p partybus.Publisher) {
	publisher = p
}

func Get() partybus.Publisher {
	return publisher
}

// Publish an event onto the bus. If there is no bus set by the calling application, this does nothing.
func Publish(e partybus.Event) {
	if publisher != nil {
		publisher.Publish(e)
	}
}
