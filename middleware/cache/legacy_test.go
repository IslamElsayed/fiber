package cache

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/internal/headerlookup"
	"github.com/gofiber/utils/v2"
	"github.com/stretchr/testify/require"
)

// legacyCredential is a way for a key to hold a credential: its config, how a request sends
// it, and how the current and the previous key version wrote it.
type legacyCredential struct {
	send    func(credential string) map[string]string
	hashed  func(credential string) string
	spelled func(credential string) string
	name    string
	cfg     Config
}

func (lc *legacyCredential) config(storage fiber.Storage) Config {
	cfg := lc.cfg
	cfg.Storage = storage
	return cfg
}

// settle waits for the purges that run off the request path. Taking every slot waits for the purges
// holding one, and orders what they wrote before what the test reads.
func (p *legacyPurge) settle(t *testing.T) {
	t.Helper()
	for range cap(p.busy) {
		p.busy <- struct{}{}
	}
	for range cap(p.busy) {
		<-p.busy
	}
}

// hookedStorage runs onGet, onSet and onDelete before it reads, writes and deletes a key, when set.
type hookedStorage struct {
	*failingCacheStorage
	onGet    func(key string)
	onSet    func(key string, exp time.Duration)
	onDelete func(key string)
}

func (s *hookedStorage) SetWithContext(ctx context.Context, key string, val []byte, exp time.Duration) error {
	if s.onSet != nil {
		s.onSet(key, exp)
	}
	return s.failingCacheStorage.SetWithContext(ctx, key, val, exp)
}

func (s *hookedStorage) GetWithContext(ctx context.Context, key string) ([]byte, error) {
	if s.onGet != nil {
		s.onGet(key)
	}
	return s.failingCacheStorage.GetWithContext(ctx, key)
}

func (s *hookedStorage) DeleteWithContext(ctx context.Context, key string) error {
	if s.onDelete != nil {
		s.onDelete(key)
	}
	return s.failingCacheStorage.DeleteWithContext(ctx, key)
}

func legacyCredentials() []legacyCredential {
	return []legacyCredential{
		{
			name:    "credential header",
			cfg:     Config{KeyHeaders: []string{"X-API-Key"}},
			send:    func(credential string) map[string]string { return map[string]string{"X-API-Key": credential} },
			hashed:  func(credential string) string { return "x-api-key:1sha256:" + authDigest(credential) },
			spelled: func(credential string) string { return "x-api-key:1|" + credential },
		},
		{
			name:    "KeyCookies cookie",
			cfg:     Config{KeyCookies: []string{"session"}},
			send:    func(credential string) map[string]string { return map[string]string{"Cookie": "session=" + credential} },
			hashed:  func(credential string) string { return "session:sha256:" + authDigest(credential) },
			spelled: func(credential string) string { return "session:" + credential },
		},
	}
}

// What the previous key version stored for a request, with the credential spelled out in its
// keys, is deleted when that request misses. Other credentials' entries stay.
func Test_legacyPurge_RemovesWhatThePreviousVersionStoredForTheRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range legacyCredentials() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			const (
				token = "tok_0123456789abcdefghijklmnopqrstuvwxyz"
				other = "tok_other_other_other_other_other_other"
			)
			var deleted atomic.Int32
			storage := &hookedStorage{failingCacheStorage: newFailingCacheStorage(), onDelete: func(string) { deleted.Add(1) }}
			app := fiber.New()
			app.Use(New(tc.config(storage)))
			app.Get("/", func(c fiber.Ctx) error {
				c.Set(fiber.HeaderVary, "Accept-Language")
				return c.SendString("body")
			})
			withToken := tc.send(token)
			keys := func() []string {
				storage.mu.RLock()
				defer storage.mu.RUnlock()
				return slices.Collect(maps.Keys(storage.data))
			}

			// The current version keys the request without spelling the credential out. The purge of this
			// request, of the entry and its body, has run before anything is planted for the next to find.
			require.Equal(t, cacheMiss, getRoot(t, app, withToken).cache)
			require.Eventually(t, func() bool { return deleted.Load() == 2 }, 5*time.Second, time.Millisecond)
			var manifest, variant string
			for _, key := range keys() {
				require.NotContains(t, key, token)
				switch {
				case strings.HasSuffix(key, "|vary"):
					manifest = key
				case strings.Contains(key, "|vary|") && !strings.HasSuffix(key, "_body"):
					variant = key
				}
			}
			require.NotEmpty(t, manifest)
			require.NotEmpty(t, variant)
			base := strings.TrimSuffix(manifest, "|vary")
			require.Contains(t, base, tc.hashed(token))

			// What the previous version stored: the same keys with the credential in the clear, and another's beside them.
			legacy := func(credential string) []string {
				legacyBase := legacyKeyVersion + "|" + strings.TrimPrefix(strings.Replace(base, tc.hashed(token), tc.spelled(credential), 1), cacheKeyVersion+"|")
				legacyVariant := legacyBase + strings.TrimPrefix(variant, base)
				return []string{legacyBase, legacyBase + "_body", legacyBase + "|vary", legacyVariant, legacyVariant + "_body"}
			}
			plant := func(credential string) {
				storage.mu.Lock()
				defer storage.mu.Unlock()
				for _, key := range legacy(credential) {
					require.Contains(t, key, credential)
					storage.data[key] = []byte("accept-language")
				}
			}
			present := func(credential string) int {
				storage.mu.RLock()
				defer storage.mu.RUnlock()
				n := 0
				for _, key := range legacy(credential) {
					if _, ok := storage.data[key]; ok {
						n++
					}
				}
				return n
			}
			forgetCurrent := func() {
				storage.mu.Lock()
				defer storage.mu.Unlock()
				maps.DeleteFunc(storage.data, func(key string, _ []byte) bool {
					return strings.HasPrefix(key, cacheKeyVersion+"|")
				})
			}
			plant(token)
			plant(other)
			forgetCurrent()

			// A request without the credential is not the one those entries were stored for.
			require.Equal(t, cacheMiss, getRoot(t, app, nil).cache)
			require.Equal(t, 5, present(token))
			forgetCurrent()

			// The one that sends it ends them, and stores its answer under the current version.
			require.Equal(t, cacheMiss, getRoot(t, app, withToken).cache)
			require.Eventually(t, func() bool { return present(token) == 0 }, 5*time.Second, time.Millisecond,
				"the credential is still spelled out in a key")
			require.Equal(t, 5, present(other), "another credential's entries went with it")
			for _, key := range keys() {
				if strings.HasPrefix(key, cacheKeyVersion+"|") {
					require.NotContains(t, key, token)
				}
			}
			require.Equal(t, cacheHit, getRoot(t, app, withToken).cache)
		})
	}
}

// The purge adds bounded work, and only where the previous version can have left something.
func Test_legacyPurge_IsBoundedAndOnlyWhereItCanMatter(t *testing.T) {
	t.Parallel()

	t.Run("not for memory, a custom key or nothing the key hashes", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		for name, cfg := range map[string]Config{
			"memory":                   {KeyHeaders: []string{"X-API-Key"}},
			"memory with a cookie":     {KeyCookies: []string{"session"}},
			"custom key":               {Storage: storage, KeyHeaders: []string{"X-API-Key"}, KeyGenerator: pathKey},
			"custom key with a cookie": {Storage: storage, KeyCookies: []string{"session"}, KeyGenerator: pathKey},
			"no credential or cookie":  {Storage: storage},
		} {
			cfg = configDefault(cfg)
			require.Nil(t, newLegacyPurge(&cfg, nil), name)
		}
	})

	t.Run("for a credential header or a cookie of the key", func(t *testing.T) {
		t.Parallel()

		for _, tc := range legacyCredentials() {
			cfg := configDefault(tc.config(newFailingCacheStorage()))
			require.NotNil(t, newLegacyPurge(&cfg, nil), tc.name)
		}
		// A declared header was in KeyHeaders then, or the previous version did not key on it at all.
		cfg := configDefault(Config{Storage: newFailingCacheStorage(), KeyCredentialHeaders: []string{"X-Company-Token"}})
		require.NotNil(t, newLegacyPurge(&cfg, nil))
	})

	t.Run("keys the headers as the previous version did", func(t *testing.T) {
		t.Parallel()

		storage := newFailingCacheStorage()
		cfg := configDefault(Config{
			Storage:              storage,
			KeyHeaders:           []string{"X-API-Key"},
			KeyCredentialHeaders: []string{"X-Company-Token"},
		})
		purge := newLegacyPurge(&cfg, newManager(storage, true))
		require.NotNil(t, purge)

		// The declared header was in KeyHeaders then, or added by the upgrade: a key with it and one
		// without are both tried, and a request that sends only it spends a probe.
		require.Len(t, purge.cfgs, 2)
		withToken := requestWith(map[string]string{"X-API-Key": "k", "X-Company-Token": "t"})
		without := requestWith(map[string]string{"X-API-Key": "k"})
		require.Equal(t, string(appendDefaultKey(nil, without, &purge.cfgs[0])), string(appendDefaultKey(nil, withToken, &purge.cfgs[0])))
		require.Contains(t, string(appendDefaultKey(nil, withToken, &purge.cfgs[1])), "h=x-api-key:1|k|x-company-token:1|t")
		require.True(t, purge.sends(requestWith(map[string]string{"X-Company-Token": "t"})))
		require.True(t, purge.sends(without))

		// One key when KeyHeaders names the declared header as well, or there is none.
		for _, cfg := range []Config{
			{Storage: storage, KeyHeaders: []string{"X-API-Key", "X-Company-Token"}, KeyCredentialHeaders: []string{"X-Company-Token"}},
			{Storage: storage, KeyHeaders: []string{"X-API-Key"}},
		} {
			cfg = configDefault(cfg)
			require.Len(t, newLegacyPurge(&cfg, nil).cfgs, 1)
		}
	})

	t.Run("only a request that sends what the key holds spends the budget", func(t *testing.T) {
		t.Parallel()

		for _, tc := range legacyCredentials() {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				storage := newFailingCacheStorage()
				cfg := configDefault(tc.config(storage))
				purge := newLegacyPurge(&cfg, newManager(storage, true))
				require.NotNil(t, purge)

				purge.purge(requestWith(nil), false)
				purge.purge(requestWith(tc.send("")), false)
				require.Zero(t, purge.next.Load(), "nothing was spelled out in a key for a request without the credential")

				purge.purge(requestWith(tc.send("tok")), false)
				require.NotZero(t, purge.next.Load())
			})
		}
	})

	t.Run("past its budget it leaves entries to expire, and the budget refills", func(t *testing.T) {
		t.Parallel()

		for _, tc := range legacyCredentials() {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				storage := newFailingCacheStorage()
				cfg := configDefault(tc.config(storage))
				purge := newLegacyPurge(&cfg, newManager(storage, true))
				require.NotNil(t, purge)

				c := requestWith(tc.send("tok"))
				legacyBase := legacyKeyVersion + "|GET|" + string(appendDefaultKey(nil, c, &purge.cfgs[0]))
				require.Contains(t, legacyBase, tc.spelled("tok"))
				storage.data[legacyBase] = []byte("entry")

				// Spent for the next two bursts: far enough ahead that a tick of the clock changes nothing.
				purge.next.Store(int64(utils.Timestamp()) + 2*legacyProbeBurst)
				purge.purge(c, false)
				purge.settle(t)
				require.Contains(t, storage.data, legacyBase)

				// Paid back but for a probe: the last one is spent, and the one after is not.
				purge.next.Store(int64(utils.Timestamp()) + legacyProbeBurst - 10)
				purge.purge(c, false)
				purge.settle(t)
				require.NotContains(t, storage.data, legacyBase)

				// A flood leaves the budget empty only until the seconds pay it back: the probes are spent
				// a second each from the second they came in. Asserted on the accounting, and refused a
				// second past the boundary, since a tick of the clock between two lines pays one probe back.
				now := int64(utils.Timestamp())
				purge.next.Store(now - 100)
				for range legacyProbeBurst {
					require.True(t, purge.allow())
				}
				require.Equal(t, now+legacyProbeBurst, purge.next.Load())
				purge.next.Store(int64(utils.Timestamp()) + legacyProbeBurst + 1)
				require.False(t, purge.allow())
			})
		}
	})
}

// A Storage round trip is not worth a miss's latency: the purge runs after the request has its answer.
func Test_legacyPurge_DoesNotDelayTheRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range legacyCredentials() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gate := make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(gate) }) }
			t.Cleanup(release)
			storage := &hookedStorage{failingCacheStorage: newFailingCacheStorage(), onDelete: func(string) { <-gate }}
			app := fiber.New()
			app.Use(New(tc.config(storage)))
			app.Get("/", func(c fiber.Ctx) error { return c.SendString("body") })

			c := requestWith(tc.send("tok"))
			cfg := configDefault(tc.config(storage))
			purge := newLegacyPurge(&cfg, newManager(storage, true))
			legacyBase := legacyKeyVersion + "|GET|" + string(appendDefaultKey(nil, c, &purge.cfgs[0]))
			storage.data[legacyBase] = []byte("entry")

			// The answer comes while the purge is still held up in the Storage.
			require.Equal(t, cacheMiss, getRoot(t, app, tc.send("tok")).cache)
			storage.mu.RLock()
			_, stillThere := storage.data[legacyBase]
			storage.mu.RUnlock()
			require.True(t, stillThere)

			release()
			require.Eventually(t, func() bool {
				storage.mu.RLock()
				defer storage.mu.RUnlock()
				_, ok := storage.data[legacyBase]
				return !ok
			}, 5*time.Second, time.Millisecond)
		})
	}
}

// Purges that run at once are bounded; a request that finds them all busy leaves its entries to expire.
func Test_legacyPurge_RunsFewAtOnce(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	storage := &hookedStorage{failingCacheStorage: newFailingCacheStorage(), onDelete: func(string) { <-gate }}
	tc := legacyCredentials()[0]
	cfg := configDefault(tc.config(storage))
	purge := newLegacyPurge(&cfg, newManager(storage, true))

	c := requestWith(tc.send("tok"))
	for range legacyWorkers + 5 {
		purge.purge(c, false)
	}
	require.Len(t, purge.busy, legacyWorkers)
	spent := purge.next.Load() - int64(utils.Timestamp())
	require.InDelta(t, legacyWorkers, spent, 1, "a request that found them all busy spent no probe")

	release()
	purge.settle(t)
}

// A Storage that panics must not take the process down with the purge it ran in.
func Test_legacyPurge_SurvivesAPanickingStorage(t *testing.T) {
	t.Parallel()

	storage := &hookedStorage{failingCacheStorage: newFailingCacheStorage(), onDelete: func(string) { panic("storage failure") }}
	tc := legacyCredentials()[0]
	cfg := configDefault(tc.config(storage))
	purge := newLegacyPurge(&cfg, newManager(storage, true))

	purge.purge(requestWith(tc.send("tok")), false)
	purge.settle(t)
	require.Empty(t, purge.busy)
}

// The purge finds what the previous key version stored by keying the request as that version did.
// These keys were written by that version's code, not built from the current helpers, so a change to
// how keys are built cannot move the purge off them unnoticed.
func Test_legacyPurge_FindsTheKeysThePreviousVersionWrote(t *testing.T) {
	t.Parallel()

	const (
		token   = "tok_0123456789abcdefghijklmnopqrstuvwxyz"
		english = "b766314692de2facc52e249450ed7b33d0a22ad6327608617e8d0d5c92e701e3" // the variant for Accept-Language: en
		french  = "630e580ef81e9631d71c703c58741110e880b0364d9eae8f2d7d361f982f7cf6" // and for fr, beside Accept: text/html
	)
	for _, tc := range []struct {
		headers map[string]string
		name    string
		uri     string
		keys    []string
		cfg     Config
	}{
		{
			name:    "a credential header, a query to sort and a Vary",
			cfg:     Config{KeyHeaders: []string{"X-API-Key"}},
			uri:     "/demo?b=2&a=1",
			headers: map[string]string{"X-API-Key": token, "Accept-Language": "en"},
			keys: []string{
				"v4|GET|scheme=http|host=example.com|/demo|q=a=1&b=2|h=x-api-key:1|" + token + "|vary",
				"v4|GET|scheme=http|host=example.com|/demo|q=a=1&b=2|h=x-api-key:1|" + token + "|vary|" + english,
				"v4|GET|scheme=http|host=example.com|/demo|q=a=1&b=2|h=x-api-key:1|" + token + "|vary|" + english + "_body",
			},
		},
		{
			name:    "a KeyCookies cookie among the default headers",
			cfg:     Config{KeyCookies: []string{"session"}},
			uri:     "/demo?b=2&a=1",
			headers: map[string]string{"Cookie": "session=abc; other=1", "Accept-Language": "en"},
			keys: []string{
				"v4|GET|scheme=http|host=example.com|/demo|q=a=1&b=2|h=accept:0|accept-encoding:0|accept-language:1|en|c=session:abc|vary",
				"v4|GET|scheme=http|host=example.com|/demo|q=a=1&b=2|h=accept:0|accept-encoding:0|accept-language:1|en|c=session:abc|vary|" + english,
				"v4|GET|scheme=http|host=example.com|/demo|q=a=1&b=2|h=accept:0|accept-encoding:0|accept-language:1|en|c=session:abc|vary|" + english + "_body",
			},
		},
		{
			name:    "Authorization beside a credential header",
			cfg:     Config{KeyHeaders: []string{"X-API-Key"}},
			uri:     "/demo",
			headers: map[string]string{"X-API-Key": token, "Authorization": "Bearer one", "Accept-Language": "en"},
			keys: []string{
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=x-api-key:1|" + token + "|auth=123ae5f9e4f2cd9e01884b1d364a1091f055fca1db4d380603f9429b4413f7e1|vary",
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=x-api-key:1|" + token + "|auth=123ae5f9e4f2cd9e01884b1d364a1091f055fca1db4d380603f9429b4413f7e1|vary|" + english,
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=x-api-key:1|" + token + "|auth=123ae5f9e4f2cd9e01884b1d364a1091f055fca1db4d380603f9429b4413f7e1|vary|" + english + "_body",
			},
		},
		{
			name:    "a credential header and no Vary",
			cfg:     Config{KeyHeaders: []string{"X-API-Key"}},
			uri:     "/demo",
			headers: map[string]string{"X-API-Key": token},
			keys: []string{
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=x-api-key:1|" + token,
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=x-api-key:1|" + token + "_body",
			},
		},
		{
			name:    "a header since moved to KeyCredentialHeaders, which that version keyed on alone",
			cfg:     Config{KeyCredentialHeaders: []string{"X-Company-Token"}},
			uri:     "/demo",
			headers: map[string]string{"X-Company-Token": token},
			keys: []string{
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=x-company-token:1|" + token,
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=x-company-token:1|" + token + "_body",
			},
		},
		{
			name:    "a header since moved to KeyCredentialHeaders from beside another",
			cfg:     Config{KeyHeaders: []string{"Accept"}, KeyCredentialHeaders: []string{"X-Company-Token"}},
			uri:     "/demo",
			headers: map[string]string{"X-Company-Token": token, "Accept": "text/html"},
			keys: []string{
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=accept:1|text/html|x-company-token:1|" + token,
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=accept:1|text/html|x-company-token:1|" + token + "_body",
			},
		},
		{
			name:    "headers of the default set beside a credential header",
			cfg:     Config{KeyHeaders: []string{"Accept", "Accept-Encoding", "Accept-Language", "X-API-Key"}},
			uri:     "/demo",
			headers: map[string]string{"X-API-Key": token, "Accept": "text/html", "Accept-Language": "fr"},
			keys: []string{
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=accept:1|text/html|accept-encoding:0|accept-language:1|fr|x-api-key:1|" + token + "|vary",
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=accept:1|text/html|accept-encoding:0|accept-language:1|fr|x-api-key:1|" + token + "|vary|" + french,
				"v4|GET|scheme=http|host=example.com|/demo|q=|h=accept:1|text/html|accept-encoding:0|accept-language:1|fr|x-api-key:1|" + token + "|vary|" + french + "_body",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			storage := newFailingCacheStorage()
			for _, key := range tc.keys {
				storage.data[key] = []byte("accept-language")
			}
			cfg := tc.cfg
			cfg.Storage = storage
			app := fiber.New()
			app.Use(New(cfg))
			app.Get("/demo", func(c fiber.Ctx) error { return c.SendString("body") })

			req := httptest.NewRequest(fiber.MethodGet, tc.uri, http.NoBody)
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			require.Equal(t, fiber.StatusOK, doRequest(t, app, req).status)
			require.Eventually(t, func() bool {
				storage.mu.RLock()
				defer storage.mu.RUnlock()
				for _, key := range tc.keys {
					if _, ok := storage.data[key]; ok {
						return false
					}
				}
				return true
			}, 5*time.Second, time.Millisecond, "a key the previous version wrote was not purged")
		})
	}
}

// The previous version kept the digest of Authorization at the end of the key, so the purge of a
// request that sends one deletes that key, and leaves the entry of the same request without it.
func Test_legacyPurge_KeepsAuthorizationInTheKey(t *testing.T) {
	t.Parallel()

	storage := newFailingCacheStorage()
	tc := legacyCredentials()[0]
	cfg := configDefault(tc.config(storage))
	purge := newLegacyPurge(&cfg, newManager(storage, true))

	headers := tc.send("tok")
	headers[fiber.HeaderAuthorization] = "Bearer one"
	c := requestWith(headers)
	without := legacyKeyVersion + "|GET|" + string(appendDefaultKey(nil, c, &purge.cfgs[0]))
	with := without + "|auth=" + authDigest("Bearer one")
	for _, key := range []string{without, with, with + "_body"} {
		storage.data[key] = []byte("entry")
	}

	purge.purge(c, true)
	purge.settle(t)
	require.NotContains(t, storage.data, with)
	require.NotContains(t, storage.data, with+"_body")
	require.Contains(t, storage.data, without)
}

// A body goes only once its metadata has, so a delete that fails leaves that entry whole for a
// version that can still read it, and the entries beside it are purged all the same.
func Test_legacyPurge_KeepsAnEntryWholeWhenItsMetadataCannotBeDeleted(t *testing.T) {
	t.Parallel()

	storage := newFailingCacheStorage()
	tc := legacyCredentials()[0]
	cfg := configDefault(tc.config(storage))
	purge := newLegacyPurge(&cfg, newManager(storage, true))

	c := requestWith(tc.send("tok"))
	base := legacyKeyVersion + "|GET|" + string(appendDefaultKey(nil, c, &purge.cfgs[0]))
	variant := varyKey(base, []string{"accept-language"}, &c.Request().Header, headerlookup.Canonical(c))
	for _, key := range []string{base, base + "_body", base + "|vary", variant, variant + "_body"} {
		storage.data[key] = []byte("accept-language")
	}
	storage.errs["del|"+base] = errors.New("storage unavailable")

	purge.purge(c, false)
	purge.settle(t)
	require.Contains(t, storage.data, base)
	require.Contains(t, storage.data, base+"_body", "kept with the metadata it belongs to")
	require.NotContains(t, storage.data, base+"|vary")
	require.NotContains(t, storage.data, variant)
	require.NotContains(t, storage.data, variant+"_body")
}
