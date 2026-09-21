package audit

import (
	"testing"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

func TestRecordDedupReplay(t *testing.T) {
	l := NewLogger()
	ev := model.AuditEvent{
		Type: model.EventSessionRevoke, SessionID: "s1", Success: true,
		Reason: "user logout", DedupKey: "revoke:s1:user logout",
	}
	first, ok1 := l.Record(ev)
	if !ok1 || first.ID == "" && first.Type == "" {
		t.Fatal("first record must be stored")
	}
	// Replay with same DedupKey: not recorded again.
	_, ok2 := l.Record(ev)
	if ok2 {
		t.Fatal("duplicate DedupKey must be rejected")
	}
	_, ok3 := l.Record(ev)
	if ok3 {
		t.Fatal("third replay must also be rejected")
	}
	if l.Count() != 1 {
		t.Fatalf("replayed events must not duplicate, count=%d", l.Count())
	}
	t.Log("INPUT 同一 DedupKey 撤销事件上报 3 次 -> 判定依据 seen 映射幂等 -> 命中规则 仅落 1 条，重复上报不产生重复副作用")

	// Different dedup keys are stored independently.
	l.Record(model.AuditEvent{Type: model.EventLocked, Subject: "u", DedupKey: "lock:u:t1"})
	l.Record(model.AuditEvent{Type: model.EventLocked, Subject: "u", DedupKey: "lock:u:t2"})
	if l.Count() != 3 {
		t.Fatalf("distinct dedup keys must be stored, count=%d", l.Count())
	}

	// Empty DedupKey: no dedup (always stored).
	l.Record(model.AuditEvent{Type: model.EventLoginFailure, Subject: "u"})
	l.Record(model.AuditEvent{Type: model.EventLoginFailure, Subject: "u"})
	if n := len(l.ByType(model.EventLoginFailure)); n != 2 {
		t.Fatalf("keyless events stored verbatim, got %d", n)
	}

	// Stored events must be copies: caller mutation cannot change history.
	ev2 := model.AuditEvent{Type: model.EventAccessDenied, DedupKey: "d1", Details: map[string]string{"r": "x"}}
	stored, _ := l.Record(ev2)
	ev2.Details["r"] = "mutated"
	if got := l.List(); got[3].Details["r"] != "x" && stored.Details["r"] != "x" {
		t.Fatal("history must be insulated from caller mutation")
	}
}
