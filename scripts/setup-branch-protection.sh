#!/bin/bash

# Setup Branch Protection for vmware-vsphere-8-cis-benchmark
# Requires GitHub CLI (gh) to be installed and authenticated

set -e

REPO="uldyssian-sh/vmware-vsphere-8-cis-benchmark"
BRANCH="main"

echo "🔒 Setting up branch protection for $REPO:$BRANCH"

# Check if GitHub CLI is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed"
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Not authenticated with GitHub CLI"
    echo "Run: gh auth login"
    exit 1
fi

# Apply branch protection rules
gh api repos/$REPO/branches/$BRANCH/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["PowerShell Script Analysis","Markdown Linting","Security Scanning","Repository Structure Validation","PowerShell Syntax Validation"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":1,"dismiss_stale_reviews":true,"require_code_owner_reviews":true,"require_last_push_approval":true}' \
  --field restrictions=null \
  --field allow_force_pushes=false \
  --field allow_deletions=false \
  --field block_creations=false \
  --field required_conversation_resolution=true \
  --field lock_branch=false \
  --field allow_fork_syncing=true

echo "✅ Branch protection rules applied successfully!"
echo ""
echo "Protection includes:"
echo "  • Required status checks before merge"
echo "  • Required pull request reviews (1 approval)"
echo "  • Dismiss stale reviews when new commits are pushed"
echo "  • Require code owner reviews"
echo "  • Require approval of most recent push"
echo "  • Enforce rules for administrators"
echo "  • Block force pushes and deletions"
echo "  • Require conversation resolution before merge"