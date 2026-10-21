package admin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestAdminNodesUI(t *testing.T) {
	node, err := exec.LookPath("node")
	if errors.Is(err, exec.ErrNotFound) {
		t.Skip("Node.js is required for the admin JavaScript regression tests")
	}
	if err != nil {
		t.Fatal(err)
	}
	// Stat the script so Go's test cache invalidates when it changes; node reads it in a subprocess.
	const script = "testdata/nodes_ui_test.cjs"
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, node, "--test", script).CombinedOutput(); err != nil {
		t.Fatalf("admin nodes UI tests failed: %v\n%s", err, output)
	}
}
