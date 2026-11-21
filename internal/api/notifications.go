package api

import (
	"context"
	"net/http"
	"time"

	"github.com/davidemaggi/conrad/internal/notify"
)

func (a *API) listChannels(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListChannels(r.Context())
	if err != nil {
		a.failErr(w, err)
		return
	}
	out := []*notify.Channel{}
	for _, sc := range list {
		if c, err := notify.Decode(sc); err == nil {
			out = append(out, c.Redacted())
		}
	}
	writeJSON(w, 200, map[string]any{"items": out, "events": notify.AllEvents})
}

func decodeChannel(w http.ResponseWriter, r *http.Request) (*notify.Channel, bool) {
	var c notify.Channel
	if !decode(w, r, &c) {
		return nil, false
	}
	if c.Events == nil {
		c.Events = append([]string{}, notify.DefaultEvents...)
	}
	return &c, true
}

func (a *API) createChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeChannel(w, r)
	if !ok {
		return
	}
	if err := c.Normalize(); err != nil {
		fail(w, http.StatusBadRequest, "notify.invalid", err.Error())
		return
	}
	sc := c.Encode()
	if err := a.Store.InsertChannel(r.Context(), sc); err != nil {
		a.failErr(w, err)
		return
	}
	c.ID = sc.ID
	a.audit(r, "notify.channel_created", c.ID, map[string]any{"kind": c.Kind, "name": c.Name})
	writeJSON(w, http.StatusCreated, c.Redacted())
}

func (a *API) loadChannel(w http.ResponseWriter, r *http.Request) (*notify.Channel, bool) {
	sc, err := a.Store.GetChannel(r.Context(), r.PathValue("id"))
	if err != nil {
		a.failErr(w, err)
		return nil, false
	}
	c, err := notify.Decode(sc)
	if err != nil {
		a.failErr(w, err)
		return nil, false
	}
	return c, true
}

func (a *API) updateChannel(w http.ResponseWriter, r *http.Request) {
	old, ok := a.loadChannel(w, r)
	if !ok {
		return
	}
	c, ok := decodeChannel(w, r)
	if !ok {
		return
	}
	c.ID, c.Kind = old.ID, old.Kind
	c.KeepSecrets(old)
	if err := c.Normalize(); err != nil {
		fail(w, http.StatusBadRequest, "notify.invalid", err.Error())
		return
	}
	if err := a.Store.UpdateChannel(r.Context(), c.Encode()); err != nil {
		a.failErr(w, err)
		return
	}
	a.audit(r, "notify.channel_updated", c.ID, map[string]any{"name": c.Name, "enabled": c.Enabled})
	writeJSON(w, 200, c.Redacted())
}

func (a *API) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.Store.DeleteChannel(r.Context(), id); err != nil {
		a.failErr(w, err)
		return
	}
	a.audit(r, "notify.channel_deleted", id, nil)
	writeJSON(w, http.StatusNoContent, nil)
}

func (a *API) runTest(w http.ResponseWriter, r *http.Request, c *notify.Channel) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := a.Notifier.Test(ctx, c); err != nil {
		failDetails(w, http.StatusBadGateway, "notify.test_failed", err.Error(), map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) testChannel(w http.ResponseWriter, r *http.Request) {
	if c, ok := a.loadChannel(w, r); ok {
		a.runTest(w, r, c)
	}
}

// testDraftChannel tests unsaved settings; with an "id" the stored secret is reused when left empty.
func (a *API) testDraftChannel(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeChannel(w, r)
	if !ok {
		return
	}
	if c.ID != "" {
		if sc, err := a.Store.GetChannel(r.Context(), c.ID); err == nil {
			if old, err := notify.Decode(sc); err == nil {
				c.KeepSecrets(old)
			}
		}
	}
	if err := c.Normalize(); err != nil {
		fail(w, http.StatusBadRequest, "notify.invalid", err.Error())
		return
	}
	a.runTest(w, r, c)
}

func (a *API) getNotifySettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"thresholdsDays": notify.Thresholds(r.Context(), a.Store)})
}

func (a *API) putNotifySettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ThresholdsDays []int `json:"thresholdsDays"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := notify.SaveThresholds(r.Context(), a.Store, in.ThresholdsDays); err != nil {
		fail(w, http.StatusBadRequest, "notify.invalid", err.Error())
		return
	}
	a.audit(r, "notify.settings_changed", "", map[string]any{"thresholds": in.ThresholdsDays})
	a.getNotifySettings(w, r)
}
