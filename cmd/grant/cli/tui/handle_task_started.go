package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/grant/event"
)

func (m *Handler) handleTaskStarted(e partybus.Event) ([]tea.Model, tea.Cmd) {
	cmd, prog, err := event.ParseTaskStarted(e)
	if err != nil {
		//log.Warnf("unable to parse event: %+v", err)
		return nil, nil
	}

	tsk := taskprogress.New(
		m.Running,
		taskprogress.WithStagedProgressable(prog),
	)

	tsk.HideProgressOnSuccess = true
	tsk.HideOnSuccess = true
	tsk.TitleWidth = len(cmd.Title.WhileRunning)
	tsk.HintEndCaps = nil
	tsk.TitleOptions = taskprogress.Title{
		Default: cmd.Title.Default,
		Running: cmd.Title.WhileRunning,
		Success: cmd.Title.OnSuccess,
		Failed:  cmd.Title.OnFail,
	}
	tsk.Context = []string{cmd.Context}
	tsk.WindowSize = m.WindowSize

	return []tea.Model{tsk}, nil
}
