package ca

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"text/template"
)

var mobileconfigTmpl = template.Must(template.New("mc").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>conrad-root.crt</string>
			<key>PayloadContent</key>
			<data>{{.Data}}</data>
			<key>PayloadDescription</key>
			<string>Adds the Conrad root CA</string>
			<key>PayloadDisplayName</key>
			<string>{{.Name}}</string>
			<key>PayloadIdentifier</key>
			<string>lab.conrad.root.{{.ID}}.cert</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{{.CertUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Trust certificates issued by your Conrad homelab CA.</string>
	<key>PayloadDisplayName</key>
	<string>{{.Name}}</string>
	<key>PayloadIdentifier</key>
	<string>lab.conrad.root.{{.ID}}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{{.ProfileUUID}}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`))

// MobileConfig renders an Apple configuration profile installing rootDER.
// UUIDs are derived from the certificate so the profile is stable.
func MobileConfig(name string, rootDER []byte) ([]byte, error) {
	sum := sha256.Sum256(rootDER)
	var buf bytes.Buffer
	err := mobileconfigTmpl.Execute(&buf, map[string]string{
		"Data":        base64.StdEncoding.EncodeToString(rootDER),
		"Name":        name,
		"ID":          hex.EncodeToString(sum[:4]),
		"CertUUID":    uuidFrom(sum[0:16]),
		"ProfileUUID": uuidFrom(sum[16:32]),
	})
	return buf.Bytes(), err
}

func uuidFrom(b []byte) string {
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
