// SPDX-License-Identifier: AGPL-3.0-only

package wtp

// TaskState is an Agent-profile task state.
type TaskState string

// Task states.
const (
	TaskCreated          TaskState = "created"
	TaskAssigned         TaskState = "assigned"
	TaskAccepted         TaskState = "accepted"
	TaskRunning          TaskState = "running"
	TaskAwaitingApproval TaskState = "awaiting_approval"
	TaskCompleted        TaskState = "completed"
	TaskFailed           TaskState = "failed"
	TaskCancelled        TaskState = "cancelled"
)

var successors = map[TaskState][]TaskState{
	TaskCreated:          {TaskAssigned, TaskCancelled},
	TaskAssigned:         {TaskAccepted, TaskCancelled},
	TaskAccepted:         {TaskRunning, TaskCancelled},
	TaskRunning:          {TaskAwaitingApproval, TaskCompleted, TaskFailed, TaskCancelled},
	TaskAwaitingApproval: {TaskRunning, TaskCompleted, TaskFailed, TaskCancelled},
}

// Successors returns the states reachable from s in one step (nil for terminal states).
func Successors(s TaskState) []TaskState { return successors[s] }

// CheckTransition returns ERR_STATE unless from → to is allowed.
func CheckTransition(from, to TaskState) error {
	for _, t := range successors[from] {
		if t == to {
			return nil
		}
	}
	return errf(ErrState, "illegal task transition %s → %s", from, to)
}
