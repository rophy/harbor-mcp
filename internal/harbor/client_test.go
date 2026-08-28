package harbor_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rophy/harbor-mcp/internal/harbor"
)

func setupMockServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, harbor.Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := harbor.NewClient(srv.URL, "robot$test", "secret")
	return srv, client
}

func TestListProjects(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "robot$test" || pass != "secret" {
			t.Error("missing or wrong basic auth")
		}
		json.NewEncoder(w).Encode([]harbor.Project{
			{ProjectID: 1, Name: "library", RepoCount: 5},
		})
	})

	projects, err := client.ListProjects(context.Background(), harbor.ListProjectsOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("got %d projects, want 1", len(projects))
	}
	if projects[0].Name != "library" {
		t.Errorf("Name = %q, want %q", projects[0].Name, "library")
	}
}

func TestGetProject(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects/library" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(harbor.Project{ProjectID: 1, Name: "library", RepoCount: 5})
	})

	project, err := client.GetProject(context.Background(), "library")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if project.Name != "library" {
		t.Errorf("Name = %q, want %q", project.Name, "library")
	}
}

func TestListRepositories(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects/library/repositories" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]harbor.Repository{
			{Name: "library/nginx", ArtifactCount: 3},
		})
	})

	repos, err := client.ListRepositories(context.Background(), "library", harbor.ListOpts{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repos) != 1 || repos[0].Name != "library/nginx" {
		t.Errorf("unexpected repos: %+v", repos)
	}
}

func TestListArtifacts(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects/library/repositories/nginx/artifacts" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]harbor.Artifact{
			{Digest: "sha256:abc123", Size: 12345},
		})
	})

	artifacts, err := client.ListArtifacts(context.Background(), "library", "nginx", harbor.ListOpts{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(artifacts) != 1 || artifacts[0].Digest != "sha256:abc123" {
		t.Errorf("unexpected artifacts: %+v", artifacts)
	}
}

func TestGetArtifact(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects/library/repositories/nginx/artifacts/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(harbor.Artifact{Digest: "sha256:abc123", Size: 12345})
	})

	artifact, err := client.GetArtifact(context.Background(), "library", "nginx", "latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if artifact.Digest != "sha256:abc123" {
		t.Errorf("Digest = %q, want sha256:abc123", artifact.Digest)
	}
}

func TestGetVulnerabilities(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/projects/library/repositories/nginx/artifacts/latest/additions/vulnerabilities" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(harbor.VulnerabilityReport{
			Severity: "High",
			Summary:  map[string]int{"High": 1},
		})
	})

	report, err := client.GetVulnerabilities(context.Background(), "library", "nginx", "latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Severity != "High" {
		t.Errorf("Severity = %q, want High", report.Severity)
	}
}

func TestListProjectsWithPagination(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "2" {
			t.Errorf("page = %q, want 2", r.URL.Query().Get("page"))
		}
		if r.URL.Query().Get("page_size") != "5" {
			t.Errorf("page_size = %q, want 5", r.URL.Query().Get("page_size"))
		}
		if r.URL.Query().Get("name") != "test" {
			t.Errorf("name = %q, want test", r.URL.Query().Get("name"))
		}
		json.NewEncoder(w).Encode([]harbor.Project{})
	})

	_, err := client.ListProjects(context.Background(), harbor.ListProjectsOpts{
		ListOpts: harbor.ListOpts{Page: 2, PageSize: 5},
		Name:     "test",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIError(t *testing.T) {
	_, client := setupMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, err := client.GetProject(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestWithHTTPClient(t *testing.T) {
	var capturedUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		json.NewEncoder(w).Encode(harbor.Project{ProjectID: 1, Name: "test"})
	}))
	t.Cleanup(srv.Close)

	customClient := &http.Client{Transport: &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
		req.Header.Set("User-Agent", "custom-test-client")
		return http.DefaultTransport.RoundTrip(req)
	}}}

	client := harbor.NewClient(srv.URL, "robot$test", "secret", harbor.WithHTTPClient(customClient))
	_, err := client.GetProject(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedUA != "custom-test-client" {
		t.Fatalf("expected custom User-Agent, got %q", capturedUA)
	}
}

type roundTripFunc struct {
	fn func(*http.Request) (*http.Response, error)
}

func (f *roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.fn(req)
}
