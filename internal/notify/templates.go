package notify

import (
	"bytes"
	htmltemplate "html/template"
	"strings"
	"text/template"
	"time"
)

// Data carries the fields templates may use; zero values are omitted.
type Data struct {
	CommonName string    `json:"commonName,omitempty"`
	Names      []string  `json:"names,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	NotAfter   time.Time `json:"notAfter,omitzero"`
	DaysLeft   int       `json:"daysLeft,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Authority  string    `json:"authority,omitempty"` // CA name for ca.* events
	Kind       string    `json:"kind,omitempty"`      // root | intermediate
	Error      string    `json:"error,omitempty"`
	Link       string    `json:"link,omitempty"`
}

// Event is a notification.
type Event struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	At      time.Time `json:"occurredAt"`
	Subject string    `json:"subject,omitempty"` // certificate or authority id
	Data    Data      `json:"data"`
}

type msg struct{ subject, intro string }

var messages = map[string]map[string]msg{
	"en": {
		CertExpiring: {"Certificate {{.CommonName}} expires in {{.DaysLeft}} {{if eq .DaysLeft 1}}day{{else}}days{{end}}", "The certificate below expires soon and has not been renewed. Check the ACME client on the host that uses it."},
		CertIssued:   {"Certificate issued: {{.CommonName}}", "A new certificate was issued."},
		CertRevoked:  {"Certificate revoked: {{.CommonName}}", "A certificate was revoked."},
		CAExpiring:   {"CA {{.Authority}} expires in {{.DaysLeft}} {{if eq .DaysLeft 1}}day{{else}}days{{end}}", "A certificate authority is close to expiry. Rotate the issuer (or create a successor root) from the Authorities page."},
		CALocked:     {"Conrad CA is locked", "Conrad started but its CA keys are locked: ACME and issuance are unavailable until you unlock the CA in the web UI."},
		ACMEFailed:   {"ACME validation failed for {{.CommonName}}", "An ACME client failed to validate an identifier."},
		Test:         {"Conrad test notification", "Sweet manatee of Galilee, it works! This is a test notification from Conrad."},
	},
	"it": {
		CertExpiring: {"Il certificato {{.CommonName}} scade tra {{.DaysLeft}} {{if eq .DaysLeft 1}}giorno{{else}}giorni{{end}}", "Il certificato qui sotto scade a breve e non è stato rinnovato. Controlla il client ACME sull'host che lo usa."},
		CertIssued:   {"Certificato emesso: {{.CommonName}}", "È stato emesso un nuovo certificato."},
		CertRevoked:  {"Certificato revocato: {{.CommonName}}", "Un certificato è stato revocato."},
		CAExpiring:   {"La CA {{.Authority}} scade tra {{.DaysLeft}} {{if eq .DaysLeft 1}}giorno{{else}}giorni{{end}}", "Un'autorità di certificazione è vicina alla scadenza. Ruota l'issuer (o crea una root successore) dalla pagina Autorità."},
		CALocked:     {"La CA di Conrad è bloccata", "Conrad è partito ma le chiavi della CA sono bloccate: ACME ed emissione non sono disponibili finché non sblocchi la CA dall'interfaccia web."},
		ACMEFailed:   {"Validazione ACME fallita per {{.CommonName}}", "Un client ACME non è riuscito a validare un identificativo."},
		Test:         {"Notifica di prova di Conrad", "Dolce lamantino di Galilea, funziona! Questa è una notifica di prova di Conrad."},
	},
}

var labels = map[string]map[string]string{
	"en": {"name": "Name", "names": "Names", "issuer": "Issuer", "serial": "Serial", "notAfter": "Expires", "reason": "Reason", "authority": "Authority", "error": "Error", "open": "Open in Conrad", "footer": "Sent by Conrad. Manage notifications in Settings."},
	"it": {"name": "Nome", "names": "Nomi", "issuer": "Issuer", "serial": "Seriale", "notAfter": "Scadenza", "reason": "Motivo", "authority": "Autorità", "error": "Errore", "open": "Apri in Conrad", "footer": "Inviato da Conrad. Gestisci le notifiche in Impostazioni."},
}

type row struct{ Label, Value string }

// Rendered is a localized notification.
type Rendered struct {
	Subject, Text, HTML string
}

func lang(l string) string {
	if _, ok := messages[l]; ok {
		return l
	}
	return "en"
}

func execText(src string, d Data) string {
	t, err := template.New("").Parse(src)
	if err != nil {
		return src
	}
	var b bytes.Buffer
	if t.Execute(&b, d) != nil {
		return src
	}
	return b.String()
}

func rows(l string, d Data) []row {
	lb := labels[l]
	var out []row
	add := func(k, v string) {
		if v != "" {
			out = append(out, row{lb[k], v})
		}
	}
	add("authority", d.Authority)
	add("name", d.CommonName)
	if len(d.Names) > 1 || (len(d.Names) == 1 && d.Names[0] != d.CommonName) {
		add("names", strings.Join(d.Names, ", "))
	}
	add("issuer", d.Issuer)
	add("serial", d.Serial)
	if !d.NotAfter.IsZero() {
		add("notAfter", d.NotAfter.UTC().Format("2006-01-02 15:04 MST"))
	}
	add("reason", d.Reason)
	add("error", d.Error)
	return out
}

var htmlTmpl = htmltemplate.Must(htmltemplate.New("mail").Parse(`<!doctype html>
<html><body style="margin:0;background:#f4f6f2;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1b2a1f">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:12px;overflow:hidden;border:1px solid #dfe5da">
<tr><td style="background:#1f5c3a;color:#fff;padding:16px 24px;font-weight:700;letter-spacing:.08em">CONRAD · CERTIFIED · APPROVED</td></tr>
<tr><td style="padding:24px">
<h1 style="font-size:18px;margin:0 0 12px">{{.Subject}}</h1>
<p style="margin:0 0 16px;line-height:1.5">{{.Intro}}</p>
{{if .Rows}}<table role="presentation" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:14px;width:100%">
{{range .Rows}}<tr><td style="color:#5b6b5f;border-top:1px solid #eef1ec;width:30%">{{.Label}}</td><td style="border-top:1px solid #eef1ec;font-family:ui-monospace,Menlo,monospace">{{.Value}}</td></tr>{{end}}
</table>{{end}}
{{if .Link}}<p style="margin:20px 0 0"><a href="{{.Link}}" style="background:#1f5c3a;color:#fff;text-decoration:none;padding:10px 16px;border-radius:8px;display:inline-block">{{.Open}}</a></p>{{end}}
</td></tr>
<tr><td style="padding:12px 24px;font-size:12px;color:#5b6b5f;background:#f8faf6">{{.Footer}}</td></tr>
</table></td></tr></table></body></html>`))

// Render produces the localized subject, text and HTML bodies.
func Render(language string, e Event) Rendered {
	l := lang(language)
	m, ok := messages[l][e.Type]
	if !ok {
		m = msg{e.Type, ""}
	}
	subject := execText(m.subject, e.Data)
	intro := execText(m.intro, e.Data)
	rs := rows(l, e.Data)

	var t strings.Builder
	t.WriteString(intro + "\n\n")
	for _, r := range rs {
		t.WriteString(r.Label + ": " + r.Value + "\n")
	}
	if e.Data.Link != "" {
		t.WriteString("\n" + labels[l]["open"] + ": " + e.Data.Link + "\n")
	}
	t.WriteString("\n-- \n" + labels[l]["footer"] + "\n")

	var h bytes.Buffer
	_ = htmlTmpl.Execute(&h, map[string]any{
		"Subject": subject, "Intro": intro, "Rows": rs, "Link": e.Data.Link,
		"Open": labels[l]["open"], "Footer": labels[l]["footer"],
	})
	return Rendered{Subject: subject, Text: t.String(), HTML: h.String()}
}
