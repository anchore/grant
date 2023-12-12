package tui

import (
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly"
	"github.com/anchore/grant/event"
)

var _ interface {
	bubbly.EventHandler
	bubbly.MessageListener
	bubbly.HandleWaiter
} = (*Handler)(nil)

type HandlerConfig struct {
	TitleWidth int
}

type Handler struct {
	WindowSize tea.WindowSizeMsg
	Running    *sync.WaitGroup
	Config     HandlerConfig

	bubbly.EventHandler
}

func DefaultHandlerConfig() HandlerConfig {
	return HandlerConfig{
		TitleWidth: 30,
	}
}

func New(cfg HandlerConfig) *Handler {
	d := bubbly.NewEventDispatcher()

	h := &Handler{
		EventHandler: d,
		Running:      &sync.WaitGroup{},
		Config:       cfg,
	}

	// register all supported event types with the respective handler functions
	d.AddHandlers(map[partybus.EventType]bubbly.EventHandlerFn{
		event.TaskStartedEvent: h.handleTaskStarted,
	})

	return h
}

func (m *Handler) OnMessage(msg tea.Msg) {
	if msg, ok := msg.(tea.WindowSizeMsg); ok {
		m.WindowSize = msg
	}
}

func (m *Handler) Wait() {
	m.Running.Wait()
}
