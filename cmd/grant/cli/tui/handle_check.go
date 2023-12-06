package tui

import (
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grant/event"
	"github.com/anchore/grant/internal/log"
)

var _ tea.Model = (*checkViewModel)(nil)

func (m *Handler) handleCLICheckCmdStarted(e partybus.Event) ([]tea.Model, tea.Cmd) {
	sourceNames, prog, err := event.ParseCheckCommandStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil, nil
	}

	return []tea.Model{newCheckViewModel(sourceNames, prog, m.WindowSize)}, nil
}

type checkViewModel struct {
	SourceNames []string
	Total       progress.StagedProgressable
	Progress    map[string]progress.StagedProgressable

	WindowSize tea.WindowSizeMsg
	Spinner    spinner.Model

	SourceNameStyle lipgloss.Style
	TitleStyle      lipgloss.Style
	WaitingStyle    lipgloss.Style
	CheckingStyle   lipgloss.Style
	DoneStyle       lipgloss.Style
	ErrorStyle      lipgloss.Style
}

func newCheckViewModel(sourceNames []string, total progress.StagedProgressable, windowSize tea.WindowSizeMsg) checkViewModel {
	padding := 0
	for _, name := range sourceNames {
		if len(name) > padding {
			padding = len(name)
		}
	}

	return checkViewModel{
		SourceNames: sourceNames,
		Total:       total,
		Progress:    make(map[string]progress.StagedProgressable),

		Spinner: spinner.New(
			spinner.WithSpinner(
				// matches the same spinner as syft/grype
				spinner.Spinner{
					Frames: strings.Split("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", ""),
					FPS:    150 * time.Millisecond,
				},
			),
			spinner.WithStyle(
				lipgloss.NewStyle().Foreground(lipgloss.Color("13")), // 13 = high intensity magenta (ANSI 16-bit color code)
			),
		),

		WindowSize: windowSize,

		SourceNameStyle: lipgloss.NewStyle().Width(padding),
		TitleStyle:      lipgloss.NewStyle().Bold(true),
		WaitingStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("#777777")),
		CheckingStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
		DoneStyle:       lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		ErrorStyle:      lipgloss.NewStyle().Foreground(lipgloss.Color("9")),
	}
}

func (m checkViewModel) Init() tea.Cmd {
	return nil
}

func (m checkViewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.WindowSize = msg
		return m, nil
	case spinner.TickMsg:
		spinModel, spinCmd := m.Spinner.Update(msg)
		m.Spinner = spinModel
		return m, spinCmd
	case partybus.Event:
		log.WithFields("component", "ui").Tracef("event: %q", msg.Type)
		// TODO: handle source check started event
	}

	return m, nil
}

func (m checkViewModel) View() string {
	isCompleted := progress.IsCompleted(m.Total)
	if isCompleted {
		return "done"
	}
	return "not done"
}
