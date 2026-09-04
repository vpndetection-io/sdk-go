// Package vpndetection is the official Go client library for the VPNDetection
// API: anonymity detection covering VPNs, residential proxies, Tor nodes,
// hosting servers, CDNs and relays.
//
// Start with New and Client.Lookup. No API key is needed: the free tier answers
// ip and is_vpn and allows 1000 requests per day per source address.
package vpndetection

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/errgroup"

	"github.com/vpndetection-io/sdk-go/internal/api"
)

// DefaultBaseURL is the production API. Override it with WithBaseURL.
const DefaultBaseURL = "https://api.vpndetection.io"

const (
	defaultCacheSize   = 10_000
	defaultCacheTTL    = time.Hour
	defaultConcurrency = 8
	defaultRetries     = 2
	defaultTimeout     = 30 * time.Second
	retryBaseDelay     = 250 * time.Millisecond
)

// Client is a client for the VPNDetection API. It is safe for concurrent use.
//
// The cache is per instance and never global: two clients holding different API
// keys are on different plans and entitled to different fields, so a shared
// cache would serve one of them the other's shape.
type Client struct {
	// Database is the licensed dataset downloads, for keys that carry the
	// db.download scope.
	Database *Database

	api         *api.ClientWithResponses
	cache       *expirable.LRU[string, Result]
	concurrency int
	retries     int
}

// New builds a client. With no options it queries the production API on the
// free tier.
func New(opts ...Option) (*Client, error) {
	cfg := config{
		baseURL:     DefaultBaseURL,
		cacheSize:   defaultCacheSize,
		cacheTTL:    defaultCacheTTL,
		concurrency: defaultConcurrency,
		retries:     defaultRetries,
		httpClient:  &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, fmt.Errorf("vpndetection: %w", err)
		}
	}

	httpClient := redirectControlled(cfg.httpClient)
	apiOpts := []api.ClientOption{api.WithHTTPClient(httpClient)}
	if cfg.apiKey != "" {
		apiOpts = append(apiOpts, api.WithRequestEditorFn(bearer(cfg.apiKey)))
	}
	inner, err := api.NewClientWithResponses(cfg.baseURL, apiOpts...)
	if err != nil {
		return nil, fmt.Errorf("vpndetection: %w", err)
	}

	client := &Client{
		Database:    &Database{api: inner, transfer: untimed(httpClient), retries: cfg.retries},
		api:         inner,
		concurrency: cfg.concurrency,
		retries:     cfg.retries,
	}
	if !cfg.cacheOff {
		client.cache = expirable.NewLRU[string, Result](cfg.cacheSize, nil, cfg.cacheTTL)
	}
	return client, nil
}

// Lookup classifies one address.
//
// A bogon is answered locally and never reaches the network. Everything else is
// served, then cached for this client. Treat the answer as read only: repeat
// lookups of one address hand back the same cached pointers.
func (c *Client) Lookup(ctx context.Context, ip string, opts ...LookupOption) (*Result, error) {
	if IsBogon(ip) {
		return bogonResult(ip), nil
	}
	if c.cache != nil {
		if hit, ok := c.cache.Get(ip); ok {
			return &hit, nil
		}
	}

	call := c.callConfig()
	for _, opt := range opts {
		opt.applyLookup(&call)
	}
	result, err := withRetry(ctx, call.retries, func() (*Result, error) {
		res, err := c.api.LookupIPWithResponse(ctx, ip)
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		return &Result{LookupResponse: *res.JSON200}, nil
	})
	if err != nil {
		return nil, err
	}

	if c.cache != nil {
		c.cache.Add(ip, *result)
	}
	return result, nil
}

// LookupBatch classifies many addresses concurrently.
//
// The answers are keyed by address rather than positional, so duplicates in the
// input collapse to a single request and the caller never has to line two lists
// up. An address that fails carries its error as its value, so one bad entry
// cannot lose the rest of the answers. The returned error is reserved for the
// batch as a whole failing, which today means the context was canceled.
func (c *Client) LookupBatch(
	ctx context.Context, ips []string, opts ...BatchOption,
) (map[string]BatchResult, error) {
	call := c.callConfig()
	for _, opt := range opts {
		opt.applyBatch(&call)
	}

	unique := dedupe(ips)
	// Written by index rather than into the map, so the workers need no lock.
	answers := make([]BatchResult, len(unique))
	group := new(errgroup.Group)
	group.SetLimit(call.concurrency)
	for i, ip := range unique {
		group.Go(func() error {
			result, err := c.Lookup(ctx, ip, Retries(call.retries))
			answers[i] = BatchResult{Result: result, Err: err}
			return nil
		})
	}
	// Every unit records its own outcome and returns nil, so this only waits.
	_ = group.Wait()

	results := make(map[string]BatchResult, len(unique))
	for i, ip := range unique {
		results[ip] = answers[i]
	}
	if err := ctx.Err(); err != nil {
		return results, fmt.Errorf("vpndetection: batch: %w", err)
	}
	return results, nil
}

// IsBogon reports whether an address is answered locally rather than served.
// Exposed here so the check is reachable from the client you already hold; the
// package-level IsBogon is the same function.
func (c *Client) IsBogon(ip string) bool {
	return IsBogon(ip)
}

// BatchResult is one address's outcome within a batch. Exactly one of Result
// and Err is set.
type BatchResult struct {
	Result *Result
	Err    error
}

// Option configures a Client.
type Option func(*config) error

// WithAPIKey authenticates as the key's organization. Which fields a lookup
// answers with, and how many requests are allowed, follow the key's plan.
func WithAPIKey(key string) Option {
	return func(c *config) error {
		c.apiKey = key
		return nil
	}
}

// WithBaseURL points the client at a different deployment of the API.
func WithBaseURL(rawURL string) Option {
	return func(c *config) error {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return fmt.Errorf("base url %q: %w", rawURL, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("base url %q needs a scheme and a host", rawURL)
		}
		c.baseURL = rawURL
		return nil
	}
}

// WithCache sizes the per-client answer cache. Defaults are 10000 addresses and
// a one hour TTL.
func WithCache(size int, ttl time.Duration) Option {
	return func(c *config) error {
		if size < 1 {
			return fmt.Errorf("cache size must be at least 1, got %d", size)
		}
		if ttl <= 0 {
			return fmt.Errorf("cache ttl must be positive, got %s", ttl)
		}
		c.cacheSize, c.cacheTTL, c.cacheOff = size, ttl, false
		return nil
	}
}

// WithoutCache turns caching off, so every lookup of a non-bogon address is
// served.
func WithoutCache() Option {
	return func(c *config) error {
		c.cacheOff = true
		return nil
	}
}

// WithConcurrency sets how many requests a batch keeps in flight. Default 8.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("concurrency must be at least 1, got %d", n)
		}
		c.concurrency = n
		return nil
	}
}

// WithRetries sets how many further attempts a transient failure gets.
// Default 2.
func WithRetries(n int) Option {
	return func(c *config) error {
		if n < 0 {
			return fmt.Errorf("retries cannot be negative, got %d", n)
		}
		c.retries = n
		return nil
	}
}

// WithHTTPClient supplies the HTTP client to send with, for a custom transport,
// proxy or timeout. Without it the SDK uses a client with a 30 second timeout.
//
// The client is copied rather than mutated, and the copy adds a CheckRedirect
// that defers to yours (see Database.DownloadURL). A dataset transfer runs on a
// second copy with Timeout cleared, and is bounded by its context instead.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) error {
		if client == nil {
			return errors.New("http client cannot be nil")
		}
		c.httpClient = client
		return nil
	}
}

// LookupOption overrides a client default for one call. Every LookupOption
// works on a batch too.
type LookupOption interface {
	BatchOption
	applyLookup(*callConfig)
}

// BatchOption overrides a client default for one batch. Options that only mean
// something for a batch are BatchOption alone, so passing one to Lookup does
// not compile rather than being accepted and ignored.
type BatchOption interface {
	applyBatch(*callConfig)
}

// Retries overrides the client's retry count for this call.
func Retries(n int) LookupOption {
	return retriesOption(n)
}

// Concurrency overrides the client's in-flight request limit for this batch, so
// one large batch does not need a second client to widen it.
func Concurrency(n int) BatchOption {
	return concurrencyOption(n)
}

type config struct {
	apiKey      string
	baseURL     string
	cacheSize   int
	cacheTTL    time.Duration
	cacheOff    bool
	concurrency int
	retries     int
	httpClient  *http.Client
}

type callConfig struct {
	retries     int
	concurrency int
}

func (c *Client) callConfig() callConfig {
	return callConfig{retries: c.retries, concurrency: c.concurrency}
}

type retriesOption int

func (o retriesOption) applyLookup(c *callConfig) { c.retries = int(o) }
func (o retriesOption) applyBatch(c *callConfig)  { c.retries = int(o) }

type concurrencyOption int

func (o concurrencyOption) applyBatch(c *callConfig) { c.concurrency = int(o) }

func bearer(key string) api.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+key)
		return nil
	}
}

// Database.DownloadURL wants the 302 itself rather than what it points at, and
// following that redirect would stream a multi-gigabyte dataset into memory.
// Suppressing it per request through the context keeps a caller's own
// CheckRedirect in force everywhere else.
type noRedirectKey struct{}

func withoutRedirects(ctx context.Context) context.Context {
	return context.WithValue(ctx, noRedirectKey{}, true)
}

func redirectControlled(client *http.Client) *http.Client {
	controlled := *client
	inner := client.CheckRedirect
	controlled.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.Context().Value(noRedirectKey{}) != nil {
			return http.ErrUseLastResponse
		}
		if inner != nil {
			return inner(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &controlled
}

// A dataset transfer runs on the same transport but no whole-request Timeout,
// since one that bounds a lookup sensibly would kill a gigabyte download part
// way through. Its deadline is the context the caller passed.
func untimed(client *http.Client) *http.Client {
	transfer := *client
	transfer.Timeout = 0
	return &transfer
}

// Backs off exponentially, except that a server-supplied Retry-After wins over
// the schedule. A 429 WITHOUT that header is a spent allowance rather than a
// throttle and is not retried at all, which Error.Retryable decides.
func withRetry[T any](ctx context.Context, retries int, attempt func() (T, error)) (T, error) {
	var zero T
	delay := retryBaseDelay
	for remaining := retries; ; remaining-- {
		value, err := attempt()
		if err == nil {
			return value, nil
		}
		var apiErr *Error
		if remaining <= 0 || !errors.As(err, &apiErr) || !apiErr.Retryable() {
			return zero, err
		}
		wait := delay
		if apiErr.RetryAfter > 0 {
			wait = apiErr.RetryAfter
		}
		if err := sleep(ctx, wait); err != nil {
			return zero, errorFromTransport(err)
		}
		delay *= 2
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func dedupe(ips []string) []string {
	seen := make(map[string]struct{}, len(ips))
	unique := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	return unique
}
