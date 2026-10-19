# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.3.2 are described by their release commits.

## 5.8.0 - 2026-10-19

### Features

- Re-pin the spec to 2026.10.19: num_ports and num_proxies in the pubproxy detail ([`fdc8607`](https://github.com/vpndetection-io/sdk-go/commit/fdc8607d0e10d6a381dfc3cccdbdb34b8027d112))

## 5.7.0 - 2026-10-18

### Features

- Re-pin the spec to 2026.10.18: is_pubproxy and the pubproxy detail ([`f4da8a6`](https://github.com/vpndetection-io/sdk-go/commit/f4da8a6dc9ac2268d3b5ccbb9c5d97e0d8b85594))

## 5.6.0 - 2026-10-17

### Features

- Re-pin the spec to 2026.10.16: dynamic client registration ([`40ec43a`](https://github.com/vpndetection-io/sdk-go/commit/40ec43a908163dd40fdbcf1a56cc0aa5cfed0106))

## 5.5.3 - 2026-10-16

### Fixes

- Re-pin the spec to 2026.10.15: descriptions in US spelling ([`c923fdd`](https://github.com/vpndetection-io/sdk-go/commit/c923fdd2675312a9dce7d8130c309352112ed068))
- Retry an answer a call cannot read, as a server error with its status ([`d358979`](https://github.com/vpndetection-io/sdk-go/commit/d358979d9ee8775a427e0b9c78fa912fd4fecefa))
- Trim the API key, and refuse one holding a control character ([`bbd0a53`](https://github.com/vpndetection-io/sdk-go/commit/bbd0a53333d9e408dcaaa512e7007920c8c94903))

## 5.5.2 - 2026-10-10

### Fixes

- Re-pin the spec to 2026.10.09: rotating a key needs apikeys.reveal ([`21e211c`](https://github.com/vpndetection-io/sdk-go/commit/21e211ccea9774723f73c1143b5da9ded1b0e847))

## 5.5.1 - 2026-10-10

### Fixes

- Start the middleware with only an API key ([`0fd1613`](https://github.com/vpndetection-io/sdk-go/commit/0fd1613c0e7891848710b83e829adbe06f0a7865))
- Read a Retry-After as digits or an HTTP date, and nothing else ([`d6d9e9b`](https://github.com/vpndetection-io/sdk-go/commit/d6d9e9bfbf22a8cec3f6c097913a854573f46c07))

## 5.5.0 - 2026-10-04

### Features

- Add the authorization code sign-in, with PKCE ([`6e58cfe`](https://github.com/vpndetection-io/sdk-go/commit/6e58cfe94b6b0be0f3bfc22772d59e8362baedda))

## 5.4.4 - 2026-10-04

### Fixes

- Re-pin the spec to 2026.10.03: metadata needs no license ([`51f44a9`](https://github.com/vpndetection-io/sdk-go/commit/51f44a9eebd5d44bc1b76977edd66fb9b4c23b55))

## 5.4.3 - 2026-09-29

### Fixes

- Recognize 26 more reserved ranges as bogons, as the API does ([`438f090`](https://github.com/vpndetection-io/sdk-go/commit/438f0907f6f9d009e06b34f6f521ff8878b9d995))

## 5.4.2 - 2026-09-28

### Fixes

- Judge an IPv4-mapped address as the IPv4 address it carries ([`41d1255`](https://github.com/vpndetection-io/sdk-go/commit/41d12555463afdd0430e9a44375c107abc17a3d3))

## 5.4.1 - 2026-09-28

### Fixes

- Compile on 32-bit platforms again ([`19bcb5d`](https://github.com/vpndetection-io/sdk-go/commit/19bcb5d393ffb23e7907edbe373708cbb59dbdbf))
- Read a lookup's and a batch's Retry-After from the response ([`ba31e01`](https://github.com/vpndetection-io/sdk-go/commit/ba31e010f62e88dd8b298b98630c89b2ecc46372))

## 5.4.0 - 2026-09-27

### Features

- Surface client_id_metadata_document_supported on OauthMetadata ([`6b8f639`](https://github.com/vpndetection-io/sdk-go/commit/6b8f63930b095e112385b2ceb35fbbf26f7e5e1a))

## 5.3.4 - 2026-09-27

### Fixes

- Drop every trailing slash, and bound an overlong Retry-After ([`1dd18eb`](https://github.com/vpndetection-io/sdk-go/commit/1dd18eb86cbb7efc790a24ee07cdf8a9f2fb22df))
- End the poll's sleep at its deadline, and saturate a server's values ([`d615108`](https://github.com/vpndetection-io/sdk-go/commit/d6151088a7c3cfcb9857c1337a3c29a0ee1df3c3))

## 5.3.3 - 2026-09-26

### Fixes

- Fail DownloadBytes on a length no process can hold, never panic ([`aa4a546`](https://github.com/vpndetection-io/sdk-go/commit/aa4a54695c03f1bf77dc485a8994e21468a93024))

## 5.3.2 - 2026-09-25

### Fixes

- Share one request per address between concurrent misses ([`38df1c1`](https://github.com/vpndetection-io/sdk-go/commit/38df1c18b246a958003af73593f04440b8915f8f))
