# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="24"/>](https://vpndetection.io/) VPNDetection Go Client Library

[![Go Reference](https://pkg.go.dev/badge/github.com/vpndetection-io/sdk-go.svg)](https://pkg.go.dev/github.com/vpndetection-io/sdk-go)
[![license](https://img.shields.io/github/license/vpndetection-io/sdk-go)](LICENSE)

The official Go client library for the [VPNDetection](https://vpndetection.io) API.

The library helps you query VPNDetection's APIs for anonymity detection including VPNs, residential proxies, Tor nodes, hosting servers, CDNs, relays and more.

## Getting Started

```bash
go get github.com/vpndetection-io/sdk-go
```

Requires Go 1.24 or newer. The module path ends in `sdk-go`, but the package it declares is `vpndetection`:

```go
import vpndetection "github.com/vpndetection-io/sdk-go"
```

## Usage

**No API key needed to start.** The free tier answers `ip` and `is_vpn`, and allows 1000 requests per day per source address.

```go
client, err := vpndetection.New()
if err != nil {
    log.Fatal(err)
}

result, err := client.Lookup(ctx, "45.83.91.1")
if err != nil {
    log.Fatal(err)
}
fmt.Println(result.IsVpn)   // true
```

### With an API key

An API key raises your quota, and raises your features on a paid plan. Create one in the [console](https://app.vpndetection.io), then pass it in:

```go
client, err := vpndetection.New(vpndetection.WithAPIKey(os.Getenv("VPNDETECTION_API_KEY")))

result, err := client.Lookup(ctx, "45.83.91.1")
fmt.Println(result.IsVpn)               // true
fmt.Println(vpndetection.BoolValue(result.IsHosting))  // true

if vpn := result.Vpn; vpn != nil && vpn.Provider != nil {
    fmt.Println(*vpn.Provider)          // mullvad
}
```

### Batch lookup

You can do batch lookups with a list, which parallelizes requests for you efficiently:

```go
results, err := client.LookupBatch(ctx, []string{"45.83.91.1", "8.8.8.8", "1.1.1.1"})

for ip, result := range results {
    if result.Err != nil {
        fmt.Printf("%s: %v\n", ip, result.Err)
        continue
    }
    fmt.Printf("%s: %v\n", ip, result.Result.IsVpn)
}
```

Results are keyed by address, so duplicates in your list collapse into a single request and one address failing never loses the rest.

Concurrency and other variables are configurable per-call:

```go
results, err := client.LookupBatch(ctx, manyIPs,
    vpndetection.Concurrency(32), vpndetection.Retries(4))
```

### Caching

Answers are cached by default, so repeat lookups of the same address are free:

```go
client, err := vpndetection.New()

result, err := client.Lookup(ctx, "45.83.91.1")
fmt.Println(result.IsVpn)    // true, API request

result2, err := client.Lookup(ctx, "45.83.91.1")
fmt.Println(result2.IsVpn)   // true, no API request, result was cached
```

You can change the default cache variables (max size, TTL, etc) on initialization, or even disable it:

```go
client, err := vpndetection.New(vpndetection.WithCache(50_000, 6*time.Hour))
clientNoCache, err := vpndetection.New(vpndetection.WithoutCache())
```

### Private and reserved addresses

Private, loopback, link-local, documentation and multicast addresses (and their IPv6 equivalents, including the 6to4 and Teredo ranges) can never be VPN or proxy infrastructure. The library answers them locally, so they cost no request and no quota:

```go
result, err := client.Lookup(ctx, "192.168.1.1")
result.IsBogon   // true, this answer was computed rather than served
result.IsVpn     // false
```

Because the answer is computed rather than served, it always carries every field, whatever plan you are on. Do not read your plan's shape off a private address.

The check is available on the client, which is handy when your inputs are addresses anyway:

```go
client.IsBogon("10.0.0.1")   // true
client.IsBogon("8.8.8.8")    // false
```

It is also callable on its own, if you want it without a client:

```go
vpndetection.IsBogon("10.0.0.1")   // true
```

### Errors

Failures return a `*vpndetection.Error` carrying a `Kind` and a `Retryable` flag:

```go
result, err := client.Lookup(ctx, "1.1.1.1")
var apiErr *vpndetection.Error
if errors.As(err, &apiErr) {
    fmt.Println(apiErr.Kind, apiErr.Retryable())
}
```

`Kind` is one of `bad_request`, `unauthorized`, `forbidden`, `rate_limited`, `quota_exceeded`, `server_error` or `network`.

Note that `rate_limited` and `quota_exceeded` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded.

### Database downloads

If your key carries the `db.download` scope, the licensed datasets are available through `client.Database`. `DownloadFile` fetches one to a path, streaming it straight to disk so that nothing bigger than a chunk is ever held in memory:

```go
datasets, err := client.Database.List(ctx)

written, err := client.Database.DownloadFile(ctx,
    "vpn_ip_extended_v1", vpndetection.FormatMMDB, "./vpn_ip_extended_v1.mmdb")
fmt.Printf("%d bytes\n", written)
```

Or stream it into a writer of your own, take the time-limited link and run the transfer yourself, or take a small dataset as bytes:

```go
written, err := client.Database.Download(ctx, "vpn_ip_extended_v1", vpndetection.FormatMMDB, w)
url, err := client.Database.DownloadURL(ctx, "vpn_ip_extended_v1", vpndetection.FormatMMDB)
raw, err := client.Database.DownloadBytes(ctx, "cdn_ip_v1", vpndetection.FormatCSVGZ)
```

`DownloadBytes` holds the whole file in memory, and the catalog runs from `cdn_ip_v1` at 10 KB to `resproxy_ip_90d_v1` at 1.79 GB, so use `DownloadFile` for anything you have not measured.

### Absent is not false

Every field beyond `IP` and `IsVpn` is a pointer, because your plan decides which of them the API sends. A `nil` pointer means "not in your plan", not "checked, and no".

```go
vpndetection.BoolValue(result.IsHosting)  // when you only want the flag
result.IsHosting == nil                   // not in your plan
```

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="96"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
