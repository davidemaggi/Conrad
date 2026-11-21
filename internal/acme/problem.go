package acme

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const errNS = "urn:ietf:params:acme:error:"

// Problem is an RFC 7807 problem document with ACME error types.
type Problem struct {
	Type        string     `json:"type"`
	Detail      string     `json:"detail,omitempty"`
	Status      int        `json:"status,omitempty"`
	Identifier  *ident     `json:"identifier,omitempty"`
	Subproblems []*Problem `json:"subproblems,omitempty"`
}

func (p *Problem) Error() string { return p.Type + ": " + p.Detail }

func prob(status int, typ, format string, args ...any) *Problem {
	return &Problem{Type: errNS + typ, Detail: fmt.Sprintf(format, args...), Status: status}
}

func malformed(f string, a ...any) *Problem    { return prob(400, "malformed", f, a...) }
func unauthorized(f string, a ...any) *Problem { return prob(403, "unauthorized", f, a...) }
func notFoundP(f string, a ...any) *Problem    { return prob(404, "malformed", f, a...) }
func serverErr(f string, a ...any) *Problem    { return prob(500, "serverInternal", f, a...) }
func rejectedID(f string, a ...any) *Problem   { return prob(400, "rejectedIdentifier", f, a...) }

func (p *Problem) json() string {
	b, _ := json.Marshal(p)
	return string(b)
}

func parseProblem(s string) *Problem {
	if s == "" {
		return nil
	}
	p := &Problem{}
	if json.Unmarshal([]byte(s), p) != nil {
		return nil
	}
	return p
}

func writeProblem(w http.ResponseWriter, p *Problem) {
	if p.Status == 0 {
		p.Status = 500
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
