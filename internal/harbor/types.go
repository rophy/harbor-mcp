package harbor

import "time"

type Project struct {
	ProjectID    int       `json:"project_id"`
	Name         string    `json:"name"`
	RepoCount    int       `json:"repo_count"`
	CreationTime time.Time `json:"creation_time"`
	Metadata     struct {
		Public   string `json:"public"`
		AutoScan string `json:"auto_scan,omitempty"`
		Severity string `json:"severity,omitempty"`
	} `json:"metadata"`
}

type Repository struct {
	Name           string    `json:"name"`
	RepositoryName string    `json:"repository_name,omitempty"`
	ArtifactCount  int       `json:"artifact_count"`
	PullCount      int       `json:"pull_count"`
	ProjectID      int       `json:"project_id,omitempty"`
	CreationTime   time.Time `json:"creation_time"`
}

type Tag struct {
	Name     string    `json:"name"`
	PushTime time.Time `json:"push_time"`
}

type ScanOverview map[string]ScanSummary

type ScanSummary struct {
	Severity string         `json:"severity"`
	Complete bool           `json:"complete_percent"`
	Summary  map[string]int `json:"summary"`
}

type Artifact struct {
	Digest       string       `json:"digest"`
	Tags         []Tag        `json:"tags"`
	Size         int64        `json:"size"`
	PushTime     time.Time    `json:"push_time"`
	PullTime     time.Time    `json:"pull_time"`
	ScanOverview ScanOverview `json:"scan_overview"`
	ExtraAttrs   struct {
		OS           string `json:"os,omitempty"`
		Architecture string `json:"architecture,omitempty"`
	} `json:"extra_attrs"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

type VulnerabilityReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	Severity        string              `json:"severity"`
	Summary         map[string]int      `json:"summary"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type VulnerabilityItem struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	FixVersion  string `json:"fix_version,omitempty"`
	Description string `json:"description"`
}

type SearchResult struct {
	Projects     []Project    `json:"project"`
	Repositories []Repository `json:"repository"`
}

type ListOpts struct {
	Page     int
	PageSize int
	Query    string
}

type ListProjectsOpts struct {
	ListOpts
	Name string
}
