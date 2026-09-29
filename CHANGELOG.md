# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.3.2 are described by their release commits.

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
