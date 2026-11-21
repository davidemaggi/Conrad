package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/davidemaggi/conrad/internal/store"
)

func TestPassword(t *testing.T) {
	if _, err := HashPassword("short"); err != ErrWeakPassword {
		t.Fatal("weak password accepted")
	}
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPassword(h, "correct horse battery"); !ok {
		t.Fatal("verify failed")
	}
	if ok, _ := VerifyPassword(h, "wrong horse battery!"); ok {
		t.Fatal("wrong password verified")
	}
}

func TestSessionAndCSRF(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	now := time.Unix(1_800_000_000, 0)
	st.SetClock(func() time.Time { return now })
	m := NewSessions(st, true)
	rec := httptest.NewRecorder()
	s, err := m.Create(context.Background(), rec, httptest.NewRequest("POST", "/", nil), "password")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if _, err := m.Get(req); err != nil {
		t.Fatal(err)
	}
	if CheckCSRF(req, s) {
		t.Fatal("POST without header must fail CSRF")
	}
	req.Header.Set(CSRFHeader, s.CSRFToken)
	if !CheckCSRF(req, s) {
		t.Fatal("valid CSRF rejected")
	}
	req.Header.Set(CSRFHeader, "forged")
	if CheckCSRF(req, s) {
		t.Fatal("forged CSRF accepted")
	}
	now = now.Add(13 * time.Hour)
	if _, err := m.Get(req); err == nil {
		t.Fatal("idle session should expire")
	}
	_ = http.StatusOK
}

func TestThrottle(t *testing.T) {
	th := NewThrottle()
	now := time.Unix(0, 0)
	th.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		th.Fail("ip")
	}
	if th.Wait("ip") != 0 {
		t.Fatal("3 failures should be free")
	}
	th.Fail("ip")
	th.Fail("ip")
	if d := th.Wait("ip", "user"); d != 2*time.Second {
		t.Fatalf("want 2s backoff, got %v", d)
	}
	th.Reset("ip")
	if th.Wait("ip") != 0 {
		t.Fatal("reset failed")
	}
}
