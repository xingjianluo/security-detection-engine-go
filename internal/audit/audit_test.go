package audit

import (
	"sync"
	"testing"
)

func TestAppendOnlyMonotonicAndFilter(t *testing.T) {
	l := NewLog()
	l.Append(Record{Action: ActionAlertCreate, Tenant: "t1"})
	l.Append(Record{Action: ActionAlertClose, Tenant: "t2"})
	l.Append(Record{Action: ActionAlertAck, Tenant: "t1"})

	if l.Len() != 3 {
		t.Fatalf("len=%d want 3", l.Len())
	}
	all := l.List("")
	for i, r := range all {
		if r.Seq != int64(i+1) {
			t.Fatalf("seq not monotonic: %+v", r)
		}
	}
	t1 := l.List("t1")
	if len(t1) != 2 {
		t.Fatalf("t1 records=%d want 2", len(t1))
	}
	for _, r := range t1 {
		if r.Tenant != "t1" {
			t.Fatalf("tenant filter leaked: %+v", r)
		}
	}
}

func TestConcurrentAppend(t *testing.T) {
	l := NewLog()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.Append(Record{Action: ActionAccessDenied, Tenant: "t1"})
		}(i)
	}
	wg.Wait()
	if l.Len() != 100 {
		t.Fatalf("len=%d want 100", l.Len())
	}
	seqs := map[int64]bool{}
	for _, r := range l.List("") {
		if seqs[r.Seq] {
			t.Fatalf("duplicate seq %d", r.Seq)
		}
		seqs[r.Seq] = true
	}
}
