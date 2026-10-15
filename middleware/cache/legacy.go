package cache

import (
	"context"
	"slices"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/internal/fieldname"
	"github.com/gofiber/fiber/v3/internal/headerlookup"
	"github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/utils/v2"
	"github.com/valyala/fasthttp"
)

// legacyKeyVersion is the key version that spelled credentials out in an external Storage's keys.
// Its entries are never read; legacyPurge deletes them as clients return. Remove once none remain.
const legacyKeyVersion = "v4"

// Purging is bounded: a burst of legacyProbeBurst probes, then one more each second, with
// legacyWorkers running at once. Whatever is left expires on its own.
const (
	legacyProbeBurst   = 1024
	legacyWorkers      = 8
	legacyPurgeTimeout = 5 * time.Second
)

// legacyPurge deletes what the previous key version stored for a request, found by keying it as
// that version did. A Storage cannot list its keys, so it reaches only credentials that return.
type legacyPurge struct {
	m       *manager
	busy    chan struct{} // a slot for each purge running off the request path
	headers []string      // the credential headers that version kept in the key
	cookies []string      // and the cookies
	cfgs    []Config      // keys as the previous version did, credential values spelled out
	next    atomic.Int64  // the second the probes spent so far are paid back by
}

// newLegacyPurge returns nil when there is nothing to purge: an in-memory store, a custom
// KeyGenerator, or a key without a credential header or cookie. That version lacked
// KeyCredentialHeaders, so a header named there now was in KeyHeaders then or not in the key at
// all: when the two keys differ, both are tried.
func newLegacyPurge(cfg *Config, m *manager) *legacyPurge {
	if cfg.Storage == nil || !cfg.usesDefaultKeyGenerator {
		return nil
	}
	if len(cfg.credentialKeyHeaders) == 0 && len(cfg.KeyCookies) == 0 {
		return nil
	}
	p := &legacyPurge{m: m, headers: cfg.credentialKeyHeaders, cookies: cfg.KeyCookies, busy: make(chan struct{}, legacyWorkers)}
	for _, keyHeaders := range [][]string{cfg.plainKeyHeaders, cfg.movedKeyHeaders} {
		if len(p.cfgs) > 0 && slices.Equal(keyHeaders, p.cfgs[0].KeyHeaders) {
			continue
		}
		previous := *cfg
		previous.KeyHeaders = keyHeaders
		previous.credentialKeyHeaders = nil
		previous.spellCookies = true
		p.cfgs = append(p.cfgs, previous)
	}
	return p
}

// sends reports whether the request sends a credential that version spelled out in its key.
func (p *legacyPurge) sends(c fiber.Ctx) bool {
	return sendsCredential(c, p.cookies, p.headers)
}

// allow spends a probe, if any is left. One is refilled each second, so a flood cannot end the purge.
func (p *legacyPurge) allow() bool {
	now := int64(utils.Timestamp())
	for {
		spent := p.next.Load()
		due := max(spent, now)
		if due-now >= legacyProbeBurst {
			return false
		}
		if p.next.CompareAndSwap(spent, due+1) {
			return true
		}
	}
}

// purge deletes the entry, body, manifest and variant the previous version stored for the request.
// It is best effort and runs off the request path, which a Storage round trip would otherwise delay.
func (p *legacyPurge) purge(c fiber.Ctx, hasAuthorization bool) { //nolint:revive // flag-parameter: a property of the request, not a mode of operation
	if p == nil || !p.sends(c) {
		return
	}
	select {
	case p.busy <- struct{}{}:
	default:
		return
	}
	if !p.allow() {
		<-p.busy
		return
	}

	canonical := headerlookup.Canonical(c)
	var bases [2]string
	for i := range p.cfgs {
		bases[i] = p.base(c, &p.cfgs[i], hasAuthorization, canonical)
	}

	// The request is recycled once the handler returns: keep the headers the variant is keyed on.
	var header fasthttp.RequestHeader
	c.Request().Header.CopyTo(&header)
	go p.run(bases[:len(p.cfgs)], &header, canonical) //nolint:gosec // G118: the request is recycled once the handler returns, so the purge cannot borrow its context
}

// base keys the request as the previous version did, with the KeyHeaders of cfg.
func (p *legacyPurge) base(c fiber.Ctx, cfg *Config, hasAuthorization, canonical bool) string { //nolint:revive // flag-parameter: properties of the request, not modes of operation
	bufPtr := acquireKeyBuffer()
	buf := (*bufPtr)[:0]
	buf = append(buf, legacyKeyVersion...)
	buf = append(buf, '|')
	buf = append(buf, c.Method()...)
	buf = append(buf, '|')
	buf = appendDefaultKey(buf, c, cfg)
	if hasAuthorization {
		buf = append(buf, "|auth="...)
		buf = appendAuthHash(buf, fieldname.Lines(&c.Request().Header, fiber.HeaderAuthorization, canonical))
	}
	base := string(buf)
	releaseKeyBuffer(bufPtr, buf)
	return base
}

// run deletes what purge found, with a slot of busy that it gives back.
func (p *legacyPurge) run(bases []string, header *fasthttp.RequestHeader, canonical bool) { //nolint:revive // flag-parameter: a property of the header store
	defer func() { <-p.busy }()
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("cache: purging the previous key version panicked: %v", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), legacyPurgeTimeout)
	defer cancel()

	for _, base := range bases {
		// A body goes only once its metadata has, so a delete that fails never leaves metadata without a body.
		entries := [][]string{{base, base + "_body"}}
		manifestKey := base + "|vary"
		if names, found, err := loadVaryManifest(ctx, p.m, manifestKey); err == nil && found {
			variant := varyKey(base, names, header, canonical)
			entries = append(entries, []string{manifestKey}, []string{variant, variant + "_body"})
		}
		for _, keys := range entries {
			for _, key := range keys {
				if err := p.m.del(ctx, key); err != nil {
					log.Warnf("cache: failed to purge an entry of the previous key version: %v", err)
					break
				}
			}
		}
	}
}
