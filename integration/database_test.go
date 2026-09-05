// The licensed-download half, which only the max key can reach: it is the tier
// holding dataset licences, and db.download is a scope the other three keys do
// not carry.
//
// The transfer is budgeted before it starts. Metadata publishes a size per
// format, and that size is checked against the ceiling below FIRST, so a
// mistaken dataset id can never quietly pull one of the gigabyte datasets
// through CI.

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	vpndetection "github.com/vpndetection-io/sdk-go"
)

const (
	// The max organization licenses cdn_ip for license_type, and at ~10 KB it
	// is the only dataset small enough to move in CI.
	datasetID = "cdn_ip_v1"
	format    = vpndetection.FormatCSVGZ
	// 8 MiB against a ~10 KB dataset. Three orders of magnitude of headroom, so
	// tripping it means the suite is pointed somewhere unintended, which is
	// exactly when a transfer must not go ahead.
	ceiling = 8 << 20
	// A real catalogue id the max organization holds no licence for.
	unlicensedID = "hosting_ip_v1"
)

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestTheLicensedCatalogueAnswersTheSchemaTheClientWasGeneratedFrom(t *testing.T) {
	client, rec := maxClient(t)

	datasets, err := client.Database.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(datasets) == 0 {
		t.Fatal("the max organization licenses nothing")
	}
	// Named first, and with what actually arrived, because every typed assertion
	// below reads as a zero value when the payload disagrees, and a bare "want a
	// string" costs a whole CI cycle to interpret.
	served := servedKeys(t, rec, "/api/v1/database/list")
	for _, want := range []string{"base", "versions"} {
		if !slices.Contains(served, want) {
			t.Fatalf("the payload carries %s, and LicensedDataset declares %s",
				strings.Join(served, ", "), want)
		}
	}
	if slices.Contains(served, "docsGroup") {
		t.Error("docsGroup is a docs-site slug and must not be published as API surface")
	}

	standings := []vpndetection.Standing{
		vpndetection.StandingExpired, vpndetection.StandingLicensed, vpndetection.StandingUnlicensed,
	}
	rights := []vpndetection.LicenseType{
		vpndetection.LicenseTypeEvaluation, vpndetection.LicenseTypeStandard,
		vpndetection.LicenseTypeRedistribute,
	}
	var ids []string
	for _, d := range datasets {
		if d.Base == "" || d.Name == "" {
			t.Errorf("a licensed family carries no base or name: %+v", d)
		}
		if !slices.Contains(standings, d.Standing) {
			t.Errorf("%s carries an undocumented standing %q", d.Base, d.Standing)
		}
		if !slices.Contains(rights, d.LicenseType) {
			t.Errorf("%s carries an undocumented right %q", d.Base, d.LicenseType)
		}
		// The point of the family shape: a license covers the family, and these
		// are the ids the download and checksum calls take. Before the spec was
		// corrected this list did not exist, so List could not tell a caller what
		// to download.
		if len(d.Versions) == 0 {
			t.Errorf("%s carries no versions", d.Base)
		}
		for _, v := range d.Versions {
			if v.ID == "" {
				t.Errorf("%s has a version with no id", d.Base)
			}
			if len(v.Formats) == 0 {
				t.Errorf("%s carries no formats", v.ID)
			}
			ids = append(ids, v.ID)
		}
	}
	t.Logf("licensed: %s", strings.Join(ids, ", "))
}

func TestADatasetTheOrganizationDoesNotLicenseIsRefusedCleanly(t *testing.T) {
	client, rec := maxClient(t)

	_, err := client.Database.DownloadURL(t.Context(), unlicensedID, format)

	var apiErr *vpndetection.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("a refusal must arrive as the library error type, got %T (%v). If %s is now"+
			" licensed to this organization, point this at one that is not", err, err, unlicensedID)
	}
	if apiErr.Kind != vpndetection.KindForbidden {
		t.Errorf("Kind = %q, want %q", apiErr.Kind, vpndetection.KindForbidden)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Retryable() {
		t.Error("a licence refusal is not worth retrying")
	}
	// The API says which refusal this is (`{"rc":"NOT_LICENSED"}`). Falling back
	// to the status means the client never read the envelope.
	if apiErr.Message == "" || strings.HasPrefix(apiErr.Message, "request failed with status") {
		t.Errorf("Message = %q, which is the client fallback, so the body went unread", apiErr.Message)
	}
	if issued := len(rec.seen()); issued != 1 {
		t.Errorf("issued %d request(s), and a 4xx must not be retried", issued)
	}
}

func TestDownloadFileStreamsARealDatasetToDiskIntact(t *testing.T) {
	dl := transferred(t)

	if dl.written <= 0 {
		t.Fatal("nothing was transferred")
	}
	info, err := os.Stat(dl.path)
	if err != nil {
		t.Fatalf("the download is not on disk: %v", err)
	}
	if info.Size() != dl.written {
		t.Errorf("the file is %d bytes and the method reported %d", info.Size(), dl.written)
	}
	if _, err := os.Stat(dl.path + ".part"); !os.IsNotExist(err) {
		t.Error("the .part file outlived a successful transfer")
	}
	body, err := os.ReadFile(dl.path)
	if err != nil {
		t.Fatalf("reading the download back: %v", err)
	}
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Error("the payload is not gzip")
	}

	if !hexDigest.MatchString(dl.checksums.SHA256) {
		t.Fatalf("sha256 = %q, so the checksums did not unwrap past the envelope", dl.checksums.SHA256)
	}
	if got := digest(body); got != dl.checksums.SHA256 {
		t.Errorf("the bytes hash to %s, and the API publishes %s", got, dl.checksums.SHA256)
	}

	// The presigned URL authorizes itself, so the request that follows the 302
	// must carry no credential.
	storage := 0
	for _, f := range dl.facts {
		if f.origin == staging {
			continue
		}
		storage++
		if f.carriedKey {
			t.Errorf("the API key was sent to object storage at %s", f.origin)
		}
	}
	if storage == 0 {
		t.Error("nothing was fetched from object storage, so no 302 was followed")
	}
}

func TestDownloadBytesAgreesWithTheStreamedCopy(t *testing.T) {
	dl := transferred(t)
	client, _ := maxClient(t)

	raw, err := client.Database.DownloadBytes(t.Context(), datasetID, format)
	if err != nil {
		t.Fatalf("DownloadBytes: %v", err)
	}

	if int64(len(raw)) != dl.written {
		t.Errorf("the in-memory copy is %d bytes and the streamed one %d", len(raw), dl.written)
	}
	if got := digest(raw); got != dl.checksums.SHA256 {
		t.Errorf("the in-memory copy hashes to %s, and the API publishes %s", got, dl.checksums.SHA256)
	}
}

// A client of its own per test, so one test's request record cannot be read
// through another's.
func maxClient(t *testing.T) (*vpndetection.Client, *recorder) {
	t.Helper()
	if reason := maxRung().skipReason(); reason != "" {
		t.Skip(reason)
	}
	return clientFor(t, maxRung())
}

type transfer struct {
	written   int64
	path      string
	checksums *vpndetection.Checksums
	facts     []fact
}

// Memoized so the two transfer tests share one download rather than pulling the
// dataset twice each. Held in a directory of the package's own, because a
// t.TempDir belongs to whichever test happened to ask first and would be gone
// before the other read it.
var shared *transfer

func transferred(t *testing.T) *transfer {
	t.Helper()
	if shared != nil {
		return shared
	}
	client, rec := maxClient(t)

	meta, err := client.Database.Metadata(t.Context(), datasetID)
	if err != nil {
		t.Fatalf("Metadata(%s): %v", datasetID, err)
	}
	if meta.ID != datasetID {
		t.Fatalf("Metadata answered about %q, want %q", meta.ID, datasetID)
	}
	size := publishedSize(t, meta)
	if size <= 0 || size > ceiling {
		t.Fatalf("%s is %d bytes, past the %d ceiling, so it is not transferred",
			datasetID, size, ceiling)
	}

	path := filepath.Join(tempDir(t), datasetID+".csv.gz")
	written, err := client.Database.DownloadFile(t.Context(), datasetID, format, path)
	if err != nil {
		t.Fatalf("DownloadFile(%s): %v", datasetID, err)
	}
	// Read after the transfer, so a rebuild between the two calls shows up as a
	// digest mismatch rather than passing against a digest of nothing.
	checksums, err := client.Database.Checksums(t.Context(), datasetID, format)
	if err != nil {
		t.Fatalf("Checksums(%s): %v", datasetID, err)
	}
	t.Logf("%s.%s: %d bytes, metadata says %d", datasetID, format, written, size)

	shared = &transfer{written: written, path: path, checksums: checksums, facts: rec.seen()}
	return shared
}

func publishedSize(t *testing.T, meta *vpndetection.DatasetMetadata) int {
	t.Helper()
	if meta.Size == nil {
		t.Fatalf("%s publishes no size to check a transfer against", datasetID)
	}
	size, ok := (*meta.Size)[string(format)]
	if !ok {
		t.Fatalf("%s publishes no %s size to check a transfer against", datasetID, format)
	}
	return size
}

// The keys the payload actually carried, which the typed decode cannot show: an
// undocumented field silently disappears into a struct that has no home for it.
func servedKeys(t *testing.T, rec *recorder, path string) []string {
	t.Helper()
	var envelope struct {
		Datasets []map[string]json.RawMessage `json:"datasets"`
	}
	rec.mu.Lock()
	raw := rec.bodies[path]
	rec.mu.Unlock()
	if raw == nil {
		t.Fatalf("no JSON answer was captured for %s", path)
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("parsing the answer to %s: %v", path, err)
	}
	keys := map[string]bool{}
	for _, dataset := range envelope.Datasets {
		for key := range dataset {
			keys[key] = true
		}
	}
	return slices.Sorted(maps.Keys(keys))
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// A scratch directory for the package rather than for one test, and removed by
// TestMain once every test has had its look at what was transferred.
var tempRoot string

func tempDir(t *testing.T) string {
	t.Helper()
	if tempRoot != "" {
		return tempRoot
	}
	dir, err := os.MkdirTemp("", "vpndetection-integration-")
	if err != nil {
		t.Fatalf("creating a scratch directory: %v", err)
	}
	tempRoot = dir
	return dir
}

func removeTempDir() {
	if tempRoot != "" {
		os.RemoveAll(tempRoot)
	}
}
