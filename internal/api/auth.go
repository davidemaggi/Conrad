package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/davidemaggi/conrad/internal/auth"
	"github.com/davidemaggi/conrad/internal/ca"
	"github.com/davidemaggi/conrad/internal/crypto/signer"
	"github.com/davidemaggi/conrad/internal/policy"
	"github.com/davidemaggi/conrad/internal/store"
)

const passwordLoginSetting = "auth.password_login"

// dummyHash keeps login timing similar for unknown usernames.
var dummyHash, _ = auth.HashPassword("conrad-dummy-password")

var languages = map[string]bool{"en": true, "it": true}

func (a *API) passwordLoginEnabled(r *http.Request) bool {
	v, err := a.Store.GetSetting(r.Context(), passwordLoginSetting)
	return err != nil || v != "false"
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hasAdmin, err := a.Store.HasAdmin(ctx)
	if err != nil {
		a.failErr(w, err)
		return
	}
	caInit, err := a.CA.Initialized(ctx)
	if err != nil {
		a.failErr(w, err)
		return
	}
	oc, _ := auth.LoadOIDC(ctx, a.Store)
	_, sessErr := a.Sessions.Get(r)
	lang := "en"
	if ad, err := a.Store.GetAdmin(ctx); err == nil {
		lang = ad.Language
	}
	writeJSON(w, 200, map[string]any{
		"setupRequired":   !hasAdmin,
		"caInitialized":   caInit,
		"caLocked":        caInit && a.CA.Locked(),
		"authenticated":   sessErr == nil,
		"passwordLogin":   a.passwordLoginEnabled(r),
		"oidcEnabled":     oc.Enabled,
		"keyProvider":     a.CA.Provider().Name(),
		"defaultLanguage": lang,
		"version":         a.Version,
	})
}

type setupRequest struct {
	Token string `json:"token"`
	Admin struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Language string `json:"language"`
	} `json:"admin"`
	CA *struct {
		Mode            string     `json:"mode"` // generate | import
		Passphrase      string     `json:"passphrase"`
		Subject         ca.Subject `json:"subject"`
		Algorithm       string     `json:"algorithm"`
		ValidityYears   int        `json:"validityYears"`
		NameConstraints []string   `json:"nameConstraints"`
		Issuer          struct {
			Slug          string `json:"slug"`
			Name          string `json:"name"`
			Algorithm     string `json:"algorithm"`
			ValidityYears int    `json:"validityYears"`
		} `json:"issuer"`
		RootCertPEM   string `json:"rootCertPem"`
		RootKeyPEM    string `json:"rootKeyPem"`
		IssuerCertPEM string `json:"issuerCertPem"`
		IssuerKeyPEM  string `json:"issuerKeyPem"`
	} `json:"ca"`
	Policy *policy.Policy `json:"policy"`
}

func years(n int) time.Duration { return time.Duration(n) * 365 * 24 * time.Hour }

func (a *API) setup(w http.ResponseWriter, r *http.Request) {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	ctx := r.Context()
	if has, err := a.Store.HasAdmin(ctx); err != nil || has {
		fail(w, http.StatusConflict, "setup.done", "setup has already been completed")
		return
	}
	var in setupRequest
	if !decode(w, r, &in) {
		return
	}
	ip := auth.ClientIP(r)
	if wait := a.throttle.Wait("setup:" + ip); wait > 0 {
		a.throttled(w, wait)
		return
	}
	if !a.Setup.check(in.Token) {
		a.throttle.Fail("setup:" + ip)
		fail(w, http.StatusForbidden, "setup.bad_token", "invalid setup token; see the server log")
		return
	}
	in.Admin.Username = strings.TrimSpace(in.Admin.Username)
	if in.Admin.Username == "" {
		fail(w, http.StatusBadRequest, "validation", "username is required")
		return
	}
	if !languages[in.Admin.Language] {
		in.Admin.Language = "en"
	}
	hash, err := auth.HashPassword(in.Admin.Password)
	if err != nil {
		fail(w, http.StatusBadRequest, "auth.weak_password", err.Error())
		return
	}
	if in.Policy != nil {
		if err := in.Policy.Validate(); err != nil {
			fail(w, http.StatusBadRequest, "policy.invalid", err.Error())
			return
		}
	}

	caInit, err := a.CA.Initialized(ctx)
	if err != nil {
		a.failErr(w, err)
		return
	}
	var issuerSlug string
	if !caInit {
		if in.CA == nil {
			fail(w, http.StatusBadRequest, "validation", "CA settings are required")
			return
		}
		c := in.CA
		var iss *store.Authority
		switch c.Mode {
		case "", "generate":
			_, iss, err = a.CA.Init(ctx, ca.InitRequest{
				Secret: c.Passphrase, Subject: c.Subject, Algorithm: signer.Algorithm(c.Algorithm),
				Validity: years(c.ValidityYears), NameConstraints: c.NameConstraints,
				Issuer: ca.IssuerRequest{Slug: c.Issuer.Slug, Name: c.Issuer.Name, Algorithm: signer.Algorithm(c.Issuer.Algorithm), Validity: years(c.Issuer.ValidityYears)},
			})
		case "import":
			_, iss, err = a.CA.Import(ctx, ca.ImportRequest{
				Secret: c.Passphrase, RootCertPEM: c.RootCertPEM, RootKeyPEM: c.RootKeyPEM,
				IssuerCertPEM: c.IssuerCertPEM, IssuerKeyPEM: c.IssuerKeyPEM, IssuerSlug: c.Issuer.Slug, IssuerName: c.Issuer.Name,
			})
		default:
			fail(w, http.StatusBadRequest, "validation", "ca.mode must be generate or import")
			return
		}
		if err != nil {
			if errors.Is(err, ca.ErrInvalidSlug) || errors.Is(err, ca.ErrAlreadyInit) {
				a.failErr(w, err)
				return
			}
			fail(w, http.StatusBadRequest, "setup.ca_failed", err.Error())
			return
		}
		issuerSlug = iss.Slug
		a.audit(r, "ca.initialized", iss.ID, map[string]any{"mode": c.Mode, "issuer": iss.Slug})
	} else if iss, err := a.CA.Issuer(ctx, ""); err == nil {
		issuerSlug = iss.Slug
	}
	if in.Policy != nil && issuerSlug != "" {
		if err := policy.Save(ctx, a.Store, issuerSlug, *in.Policy); err != nil {
			fail(w, http.StatusBadRequest, "policy.invalid", err.Error())
			return
		}
	}
	if err := a.Store.CreateAdmin(ctx, &store.Admin{Username: in.Admin.Username, PasswordHash: hash, Language: in.Admin.Language}); err != nil {
		if errors.Is(err, store.ErrAdminExists) {
			fail(w, http.StatusConflict, "setup.done", "setup has already been completed")
			return
		}
		a.failErr(w, err)
		return
	}
	a.Setup.consume()
	a.audit(r, "setup.completed", in.Admin.Username, nil)
	s, err := a.Sessions.Create(ctx, w, r, "password")
	if err != nil {
		a.failErr(w, err)
		return
	}
	a.caReady(ctx)
	writeJSON(w, http.StatusCreated, map[string]any{"csrfToken": s.CSRFToken})
}

func (a *API) throttled(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds() + 0.999)
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	failDetails(w, http.StatusTooManyRequests, "auth.throttled", "too many attempts; try again later", map[string]any{"retryAfter": secs})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !a.passwordLoginEnabled(r) {
		fail(w, http.StatusForbidden, "auth.password_disabled", "password login is disabled; use single sign-on")
		return
	}
	ip := auth.ClientIP(r)
	keys := []string{"ip:" + ip, "user:" + strings.ToLower(in.Username)}
	if wait := a.throttle.Wait(keys...); wait > 0 {
		a.throttled(w, wait)
		return
	}
	ctx := r.Context()
	ad, err := a.Store.GetAdmin(ctx)
	hash := dummyHash
	if err == nil && strings.EqualFold(ad.Username, in.Username) {
		hash = ad.PasswordHash
	}
	ok, _ := auth.VerifyPassword(hash, in.Password)
	if err != nil || !ok || !strings.EqualFold(ad.Username, in.Username) {
		a.throttle.Fail(keys...)
		a.Audit.Record(ctx, in.Username, "auth.login_failed", "", ip, nil)
		fail(w, http.StatusUnauthorized, "auth.invalid_credentials", "invalid username or password")
		return
	}
	a.throttle.Reset(keys...)
	s, err := a.Sessions.Create(ctx, w, r, "password")
	if err != nil {
		a.failErr(w, err)
		return
	}
	a.audit(r, "auth.login", ad.Username, map[string]any{"method": "password"})
	writeJSON(w, 200, map[string]any{"csrfToken": s.CSRFToken, "admin": ad})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	a.Sessions.Destroy(w, r)
	a.audit(r, "auth.logout", "", nil)
	writeJSON(w, http.StatusNoContent, nil)
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	ad, err := a.Store.GetAdmin(r.Context())
	if err != nil {
		a.failErr(w, err)
		return
	}
	s := r.Context().Value(ctxKey{}).(*store.Session)
	writeJSON(w, 200, map[string]any{"admin": ad, "method": s.Method, "csrfToken": s.CSRFToken, "sessionExpires": s.ExpiresAt})
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	ad, err := a.Store.GetAdmin(ctx)
	if err != nil {
		a.failErr(w, err)
		return
	}
	key := "pwchange:" + auth.ClientIP(r)
	if wait := a.throttle.Wait(key); wait > 0 {
		a.throttled(w, wait)
		return
	}
	if ok, _ := auth.VerifyPassword(ad.PasswordHash, in.Current); !ok {
		a.throttle.Fail(key)
		fail(w, http.StatusForbidden, "auth.invalid_credentials", "current password is wrong")
		return
	}
	hash, err := auth.HashPassword(in.New)
	if err != nil {
		fail(w, http.StatusBadRequest, "auth.weak_password", err.Error())
		return
	}
	ad.PasswordHash = hash
	if err := a.Store.UpdateAdmin(ctx, ad); err != nil {
		a.failErr(w, err)
		return
	}
	// Log out every other session, then start a fresh one for this browser.
	_ = a.Store.DeleteAllSessions(ctx)
	s, err := a.Sessions.Create(ctx, w, r, "password")
	if err != nil {
		a.failErr(w, err)
		return
	}
	a.audit(r, "auth.password_changed", ad.Username, nil)
	writeJSON(w, 200, map[string]any{"csrfToken": s.CSRFToken})
}

func (a *API) updateProfile(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Language string `json:"language"`
	}
	if !decode(w, r, &in) {
		return
	}
	ad, err := a.Store.GetAdmin(r.Context())
	if err != nil {
		a.failErr(w, err)
		return
	}
	if u := strings.TrimSpace(in.Username); u != "" {
		ad.Username = u
	}
	if in.Language != "" {
		if !languages[in.Language] {
			fail(w, http.StatusBadRequest, "validation", "unsupported language")
			return
		}
		ad.Language = in.Language
	}
	if err := a.Store.UpdateAdmin(r.Context(), ad); err != nil {
		a.failErr(w, err)
		return
	}
	writeJSON(w, 200, ad)
}

func (a *API) getAuthSettings(w http.ResponseWriter, r *http.Request) {
	oc, err := auth.LoadOIDC(r.Context(), a.Store)
	if err != nil {
		a.failErr(w, err)
		return
	}
	secretSet := oc.ClientSecret != ""
	oc.ClientSecret = ""
	writeJSON(w, 200, map[string]any{
		"passwordLoginEnabled": a.passwordLoginEnabled(r),
		"oidc":                 oc,
		"oidcClientSecretSet":  secretSet,
		"oidcRedirectUrl":      a.OIDC.RedirectURL,
	})
}

func (a *API) putAuthSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PasswordLoginEnabled bool            `json:"passwordLoginEnabled"`
		OIDC                 auth.OIDCConfig `json:"oidc"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !in.PasswordLoginEnabled && !in.OIDC.Enabled {
		fail(w, http.StatusBadRequest, "settings.no_login_method", "enable OIDC before disabling password login")
		return
	}
	ctx := r.Context()
	if err := auth.SaveOIDC(ctx, a.Store, in.OIDC); err != nil {
		fail(w, http.StatusBadRequest, "settings.oidc_invalid", err.Error())
		return
	}
	if err := a.Store.SetSetting(ctx, passwordLoginSetting, strconv.FormatBool(in.PasswordLoginEnabled)); err != nil {
		a.failErr(w, err)
		return
	}
	a.audit(r, "settings.auth_changed", "", map[string]any{"passwordLogin": in.PasswordLoginEnabled, "oidc": in.OIDC.Enabled, "issuer": in.OIDC.Issuer})
	a.getAuthSettings(w, r)
}

func (a *API) oidcStart(w http.ResponseWriter, r *http.Request) {
	u, err := a.OIDC.AuthURL(r.Context())
	if err != nil {
		a.Log.Warn("oidc start failed", "err", err)
		http.Redirect(w, r, "/login?error=oidc_unavailable", http.StatusFound)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (a *API) oidcCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ctx := r.Context()
	ip := auth.ClientIP(r)
	if q.Get("error") != "" {
		http.Redirect(w, r, "/login?error=oidc_denied", http.StatusFound)
		return
	}
	id, err := a.OIDC.Callback(ctx, q.Get("state"), q.Get("code"))
	if err != nil {
		a.Audit.Record(ctx, "oidc", "auth.login_failed", "", ip, map[string]any{"error": err.Error()})
		http.Redirect(w, r, "/login?error=oidc_denied", http.StatusFound)
		return
	}
	if _, err := a.Sessions.Create(ctx, w, r, "oidc"); err != nil {
		a.failErr(w, err)
		return
	}
	a.Audit.Record(ctx, "admin", "auth.login", id.Subject, ip, map[string]any{"method": "oidc", "email": id.Email})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *API) unlock(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Secret string `json:"secret"`
	}
	if !decode(w, r, &in) {
		return
	}
	if wait := a.throttle.Wait("unlock"); wait > 0 {
		a.throttled(w, wait)
		return
	}
	if err := a.CA.Unlock(r.Context(), in.Secret); err != nil {
		a.throttle.Fail("unlock")
		a.audit(r, "ca.unlock_failed", "", nil)
		fail(w, http.StatusForbidden, "ca.bad_secret", "wrong passphrase or PIN")
		return
	}
	a.throttle.Reset("unlock")
	a.audit(r, "ca.unlocked", "", nil)
	a.caReady(r.Context())
	writeJSON(w, 200, map[string]any{"locked": false})
}
