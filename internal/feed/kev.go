package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVCache is the set of CVEs CISA says are being exploited, kept with its ETag
type KEVCache struct {
	ETag string   `json:"etag"`
	CVEs []string `json:"cves"`
}

// Exploited returns the CVEs in CISA's Known Exploited Vulnerabilities catalogue
func (f *Fetcher) Exploited(ctx context.Context) (map[string]bool, error) {
	if err := f.refreshKEV(ctx); err != nil && len(f.KEV.CVEs) == 0 {
		return nil, err
	}
	set := make(map[string]bool, len(f.KEV.CVEs))
	for _, cve := range f.KEV.CVEs {
		set[cve] = true
	}
	return set, nil
}

func (f *Fetcher) refreshKEV(ctx context.Context) error {
	res, err := f.get(ctx, f.KEVURL, f.KEV.ETag, "application/json")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotModified {
		return nil
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("CISA said %s", res.Status)
	}
	var catalogue struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(res.Body).Decode(&catalogue); err != nil {
		return fmt.Errorf("reading the KEV catalogue: %w", err)
	}
	f.KEV = KEVCache{ETag: res.Header.Get("ETag")}
	for _, v := range catalogue.Vulnerabilities {
		f.KEV.CVEs = append(f.KEV.CVEs, v.CVE)
	}
	return nil
}
