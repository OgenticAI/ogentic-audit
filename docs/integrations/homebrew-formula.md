# Homebrew formula

Stub for the future `ogentic-audit` Homebrew formula. Lives here until we create the dedicated `OgenticAI/homebrew-tap` repo; that creation is tracked in [OGE-439 (C4)](https://linear.app/ogenticai/issue/OGE-439) AC 6 ("Homebrew formula stub in a separate `homebrew-tap` repo (creation can be deferred but tracked)").

## Formula (draft)

When the tap repo exists at `github.com/OgenticAI/homebrew-tap`, copy this file to `Formula/ogentic-audit.rb` and the user installs via:

```sh
brew tap ogenticai/tap
brew install ogentic-audit
```

```ruby
class OgenticAudit < Formula
  desc "HMAC-SHA256 chained, append-only audit log (CLI for the ogentic-audit format)"
  homepage "https://github.com/OgenticAI/ogentic-audit"
  license "Apache-2.0"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/OgenticAI/ogentic-audit/releases/download/v#{version}/ogentic-audit-macos-arm64.tar.gz"
      sha256 "REPLACED_BY_RELEASE_WORKFLOW"
    else
      url "https://github.com/OgenticAI/ogentic-audit/releases/download/v#{version}/ogentic-audit-macos-x86_64.tar.gz"
      sha256 "REPLACED_BY_RELEASE_WORKFLOW"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/OgenticAI/ogentic-audit/releases/download/v#{version}/ogentic-audit-linux-aarch64.tar.gz"
      sha256 "REPLACED_BY_RELEASE_WORKFLOW"
    else
      url "https://github.com/OgenticAI/ogentic-audit/releases/download/v#{version}/ogentic-audit-linux-x86_64.tar.gz"
      sha256 "REPLACED_BY_RELEASE_WORKFLOW"
    end
  end

  def install
    bin.install "ogentic-audit"
  end

  test do
    output = shell_output("#{bin}/ogentic-audit version")
    assert_match "ogentic-audit", output
    assert_match "format v0x0001", output
  end
end
```

## Open question

The SHA-256 placeholders need to be filled in after the C4 release workflow uploads the tarballs to the v0.1.0 GitHub Release. Options:

1. **Manual** — copy SHAs from the Release page; commit + push to the tap repo. Solid but tedious.
2. **Workflow** — extend C4's `release-cli.yml` to compute SHAs, render this template, and open a PR against the tap repo. Better; ~30 LOC of bash + `gh pr create`.

Defer to a v0.2 polish PR. v0.1.0 ships with manual brew formula updates.
