package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// NFT is the nft binary used by Apply.
var NFT = "nft"

// Apply loads a ruleset produced by Render with `nft -f`. nft applies the
// whole file as one transaction: if anything in it is rejected, nothing
// changes and the previous ruleset stays in effect.
func Apply(ctx context.Context, ruleset string) error {
	cmd := exec.CommandContext(ctx, NFT, "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}
