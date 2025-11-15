# Git Repository Synchronization Script



## The Problem: Corrupted Repository Recovery

### 🚨 The Original Issue

This script was specifically developed to solve a critical problem: **synchronizing repositories when the source repository contains corrupted files that prevent normal Git operations.**

### The Specific Scenario

1. **Source Repository Corruption**: The original source repository contained malformed or corrupted files
2. **GitHub Push Restrictions**: GitHub's security measures blocked direct pushes of the corrupted content
3. **File Rewriting Required**: All corrupted files had to be manually rewritten and repaired
4. **Divergent Histories**: This rewriting caused complete divergence in commit hashes between source and destination repositories
5. **Merge Conflict Nightmare**: Traditional `git merge` operations resulted in endless merge conflicts due to the rewritten file histories

### Why Standard Git Operations Failed

```bash
# These would always fail with conflicts:
git pull upstream master
git merge upstream/master
git rebase upstream/master
```

**Result**: Manual conflict resolution for dozens/hundreds of files, making synchronization practically impossible.



## How It Works

### 1. Commit Detection

- Fetches commits via GitHub API
- Compares commit messages between source and destination
- Auto-adjusts search depth until stable difference count

This script implements an **intelligent cherry-picking strategy** that completely avoids the merge conflict issues caused by repository corruption and file rewriting.

```bash
# Instead of merging (which compares file histories):
git merge upstream/master  # ❌ FAILS - endless conflicts

# This script uses:
git fetch upstream --depth=X  # ✅ Gets only recent commits
git cherry-pick <specific_commits>  # ✅ Applies changes without history comparison
```

By **comparing commit messages** instead of file histories or commit hashes, the script can identify equivalent changes between the corrupted source and cleaned destination repositories, then apply them cleanly.

### 2. Git Operations

```bash
git fetch upstream --depth=<calculated_depth>
git checkout -b temp-upstream upstream/master
git cherry-pick <commit_hashes_in_order>
git push --force origin
```



## Prerequisites

### System Requirements

- **Bash** (version 4.0+)
- **Git** (version 2.0+)
- **curl** (for API calls)
- **jq** (recommended) or fallback parsing

### Repository Setup

1. Local clones of all target repositories
2. `upstream` remote pointing to source repository
3. `origin` remote pointing to destination fork
4. Push access to destination repositories

## Configuration

Edit the `REPOSITORIES` array in the script:

```bash
REPOSITORIES=(
    # Format: "local_folder|source_repo|source_branch|destination_repo|destination_branch"
    
    # Example 1: Main project synchronization
    "my-project|https://github.com/original/project.git|main|https://github.com/yourusername/project-fork.git|main"
    
    # Example 2: Version-specific synchronization  
    "project-legacy|https://github.com/original/project.git|legacy|https://github.com/yourusername/project-legacy.git|develop"
    
    # Example 3: Feature branch synchronization
    "project-feature|https://github.com/original/project.git|feature/new-ui|https://github.com/yourusername/project.git|integration"
    
    # Add more repositories as needed
)
```



## Usage

```bash
./repo-sync.sh
```

The script processes all configured repositories sequentially with no additional arguments needed.



## Specific Use Cases

### Primary Use Case: Repository Recovery

- Synchronizing from corrupted source to clean destination
- Maintaining forks when upstream has problematic history
- Recovering from repository corruption incidents

### Secondary Use Cases

- **Large-Scale Refactoring**: When files have been significantly restructured

- **History Rewriting**: After `git filter-branch` or `git rebase` operations

- **Cross-Fork Synchronization**: Between repositories with different governance rules

- **Legacy Code Migration**: Moving from old to new version control practices

  

### Handles Rewritten Histories

- Works when `git push --force` has been used on either side
- Accommodates completely different commit trees
- Maintains functionality through repository surgery

### Safe and Controlled

- **Incremental**: Processes small batches of commits
- **Verifiable**: Shows exactly what will be applied
- **Recoverable**: Preserves state on failure
- **Repeatable**: Can be run multiple times safely



## Troubleshooting

### Common Issues

**SSH Key Prompts**

- Ensure SSH key is loaded and added to GitHub

**Repository Not Found**

- Verify local folder exists in configuration

**Merge Conflicts**

- Script aborts and preserves state for manual resolution
- Use `git cherry-pick --abort` and `git reset --hard origin/master` to recover

## Important Notes

### Safety Features

- Force push requires confirmation
- Maximum 400 commit depth limit
- State preservation on failure
- Clear progress indicators

### Best Practices

1. Backup important work before running
2. Test configuration without confirmation first
3. Run frequently to avoid large commit batches
4. Monitor for conflicts and handle promptly



## 🔮 Future Applications

This script demonstrates a pattern that could be applied to other challenging synchronization scenarios:

- **Cross-platform codebases** (Windows/Linux/macOS specific changes)

- **Multi-vendor integrations** (different code styles and conventions)

- **Legacy system modernization** (incremental updates to ancient codebases)

- **Regulatory compliance** (maintaining audit trails through transformations)

  

## 💡 Key Takeaway

This script isn't just a convenience tool—it's a **necessary workaround** for a fundamental limitation in Git when dealing with corrupted or forcibly rewritten repositories. It turns an otherwise impossible synchronization task into a simple, automated process.



## Issues and bugs

Please report any issues and bugs found at the [Issue Tracker](https://github.com/electrobutterfly/code-snippets-and-scripts/issues)



## Authors and acknowledgment

© 2025 Klaus Simon.



## License

This project is licensed under the [MIT License](https://opensource.org/license/MIT).

**You are free to:**

- Do anything with this software - just keep my name in it.
- No restrictions except attribution.

*See the [LICENSE](./LICENSE) file for full terms.*

------

**The bottom line**: When repository histories diverge due to corruption or necessary rewriting, traditional Git merges fail. This script provides the only practical way to maintain synchronization without manual conflict resolution hell.

------

<img src="https://electrobutterfly.com/images/logo-small-github.png" alt="Logo" style="float:left; margin-right:10px; width:150px;">
