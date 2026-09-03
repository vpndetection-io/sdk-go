package vpndetection

import (
	"context"
	"net/http"

	"github.com/vpndetection-io/sdk-go/internal/api"
)

// Database is the licensed dataset downloads. Access is granted by contract
// rather than self-serve, and needs a key carrying the db.download scope.
type Database struct {
	api     *api.ClientWithResponses
	retries int
}

// List is the datasets your organization is licensed to download.
func (d *Database) List(ctx context.Context) ([]LicensedDataset, error) {
	return withRetry(ctx, d.retries, func() ([]LicensedDataset, error) {
		res, err := d.api.ListDatabasesWithResponse(ctx)
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		return res.JSON200.Datasets, nil
	})
}

// Metadata is what is inside one dataset: schema, samples, row count and sizes.
// It carries `updated` and `entries` without downloading anything, so poll it
// to decide whether today's build is worth fetching.
func (d *Database) Metadata(ctx context.Context, id string) (*DatasetMetadata, error) {
	return withRetry(ctx, d.retries, func() (*DatasetMetadata, error) {
		res, err := d.api.DatabaseMetadataWithResponse(ctx, &api.DatabaseMetadataParams{ID: id})
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		return res.JSON200, nil
	})
}

// Checksums are the digests of one published file, for verifying a download.
func (d *Database) Checksums(ctx context.Context, id string, format Format) (*Checksums, error) {
	return withRetry(ctx, d.retries, func() (*Checksums, error) {
		res, err := d.api.DatabaseChecksumWithResponse(ctx, &api.DatabaseChecksumParams{
			ID:     id,
			Format: api.DatabaseChecksumParamsFormat(format),
		})
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		sums := res.JSON200.Checksums
		return &Checksums{
			MD5:    deref(sums.Md5),
			SHA1:   deref(sums.Sha1),
			SHA256: deref(sums.Sha256),
			SHA512: deref(sums.Sha512),
		}, nil
	})
}

// Downloads is your organization's recent download attempts, newest first. A
// limit of zero or less takes the API's own default.
func (d *Database) Downloads(ctx context.Context, limit int) ([]Download, error) {
	return withRetry(ctx, d.retries, func() ([]Download, error) {
		params := &api.ListDownloadsParams{}
		if limit > 0 {
			params.Limit = &limit
		}
		res, err := d.api.ListDownloadsWithResponse(ctx, params)
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		return res.JSON200.Downloads, nil
	})
}

// DownloadURL is the time-limited URL for one dataset file.
//
// The API answers 302 to object storage. The URL is returned rather than the
// bytes so the caller decides how to transfer a file that routinely runs to
// gigabytes; the link authorizes the START of a transfer, so one already
// running is not interrupted when it lapses.
func (d *Database) DownloadURL(ctx context.Context, id string, format Format) (string, error) {
	ctx = withoutRedirects(ctx)
	return withRetry(ctx, d.retries, func() (string, error) {
		res, err := d.api.DownloadDatabaseWithResponse(ctx, &api.DownloadDatabaseParams{
			ID:     id,
			Format: api.DownloadDatabaseParamsFormat(format),
		})
		if err != nil {
			return "", errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusFound {
			return "", errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		if res.Headers302 == nil || res.Headers302.Location == nil {
			return "", &Error{
				Kind:       KindServerError,
				Message:    "redirect carried no Location header",
				StatusCode: res.StatusCode(),
			}
		}
		return *res.Headers302.Location, nil
	})
}

// Format is a format a dataset is published in. Not every dataset is built in
// every format: the _provider catalogs are keyed by provider id rather than
// by IP range, so no MMDB exists for them.
type Format string

const (
	FormatCSVGZ Format = "csvgz"
	FormatMMDB  Format = "mmdb"
)

// Checksums of one published dataset file. A digest the exporter did not write
// is an empty string.
type Checksums struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
}

// The dataset shapes, re-exported so a consumer never has to name an internal
// package.
type (
	LicensedDataset       = api.LicensedDataset
	DatasetFormatSize     = api.DatasetFormatSize
	DatasetMetadata       = api.DatasetMetadata
	DatasetMetadataColumn = api.DatasetMetadataColumn
	Download              = api.Download
	// Redistribution is what a license permits you to do with the data.
	Redistribution = api.LicensedDatasetRedistribution
	// DownloadOutcome is how one download attempt ended.
	DownloadOutcome = api.DownloadOutcome
)

const (
	RedistributionEvaluation   = api.Evaluation
	RedistributionInternal     = api.Internal
	RedistributionRedistribute = api.Redistribute
)

const (
	DownloadOutcomeOK           = api.DownloadOutcomeOk
	DownloadOutcomeUnauthorized = api.DownloadOutcomeUnauthorized
	DownloadOutcomeDenied       = api.DownloadOutcomeDenied
	DownloadOutcomeExpired      = api.DownloadOutcomeExpired
	DownloadOutcomeUnknown      = api.DownloadOutcomeUnknown
	DownloadOutcomeUnavailable  = api.DownloadOutcomeUnavailable
)
