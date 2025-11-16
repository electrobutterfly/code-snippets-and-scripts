#!/bin/bash

#########################################################
## repo-sync.sh
## Copyright (c) 2025 Klaus Simon
## https://github.com/electrobutterfly
## github@electrobutterfly.com
## This script is licensed under the MIT License.
## Full license text: https://opensource.org/licenses/MIT
#########################################################

# Automated Github repository synchronization with configurable targets

###############################################################################
# CONFIGURATION - Edit these arrays to match your repositories
###############################################################################

# Define your repositories here
# Format: "local_folder|source_repo|source_branch|destination_repo|destination_branch"

REPOSITORIES=(
    "my-project|https://github.com/original/project.git|main|https://github.com/yourusername/project-fork.git|main"
    "project-legacy|https://github.com/original/project.git|legacy|https://github.com/yourusername/project-legacy.git|develop"

)

###############################################################################
# FUNCTIONS - Don't edit below unless you know what you're doing
###############################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${PURPLE}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                   Repository Synchronization                   ║"
    echo "║                    Automated Cherry-Picking                    ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_repo_info() {
    local idx=$1
    local total=$2
    local folder=$3
    local src_repo=$4
    local src_branch=$5
    local dest_repo=$6
    local dest_branch=$7
    
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║ Repository ${YELLOW}$((idx+1))${CYAN} of ${YELLOW}$total${CYAN}: ${GREEN}$folder${NC}"
    echo -e "${CYAN}║ Source:      ${BLUE}$src_repo${NC} (${YELLOW}$src_branch${NC})"
    echo -e "${CYAN}║ Destination: ${BLUE}$dest_repo${NC} (${YELLOW}$dest_branch${NC})"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Use jq for reliable JSON parsing
compare_commits_jq() {
    local source_repo="$1"
    local source_branch="$2"
    local dest_repo="$3" 
    local dest_branch="$4"
    
    # Get commits from source using jq (only first line of commit message)
    local source_commits=$(curl -s "https://api.github.com/repos/$source_repo/commits?sha=$source_branch&per_page=10" | \
        jq -r '.[].commit.message | split("\n")[0]' 2>/dev/null)
    
    # Get commits from destination using jq (only first line of commit message)
    local dest_commits=$(curl -s "https://api.github.com/repos/$dest_repo/commits?sha=$dest_branch&per_page=10" | \
        jq -r '.[].commit.message | split("\n")[0]' 2>/dev/null)
    
    # Find commits in source that are not in destination
    local unique_commits=()
    
    while IFS= read -r source_commit; do
        if [ -n "$source_commit" ]; then
            local found=0
            while IFS= read -r dest_commit; do
                if [ "$source_commit" = "$dest_commit" ]; then
                    found=1
                    break
                fi
            done <<< "$dest_commits"
            
            if [ $found -eq 0 ]; then
                unique_commits+=("$source_commit")
            else
                # Stop when we find the first matching commit (sync point)
                break
            fi
        fi
    done <<< "$source_commits"
    
    printf '%s\n' "${unique_commits[@]}"
}

process_repository() {
    local local_folder="$1"
    local source_repo="$2"
    local source_branch="$3"
    local dest_repo="$4"
    local dest_branch="$5"
    
    local current_dir=$(pwd)
    
    if [ ! -d "$local_folder" ]; then
        print_error "Local repository directory '$local_folder' does not exist"
        return 1
    fi
    
    cd "$local_folder"
    
    echo ""
    print_info "=== Processing: $local_folder ==="
    
    # Extract repo names for API
    local source_repo_name=$(echo "$source_repo" | sed 's|https://github.com/||' | sed 's|.git$||')
    local dest_repo_name=$(echo "$dest_repo" | sed 's|https://github.com/||' | sed 's|.git$||')
    
    print_info "Source: $source_repo_name ($source_branch)"
    print_info "Destination: $dest_repo_name ($dest_branch)"
    
    # Get unique commits using jq
    print_info "Finding unique commits..."
    local unique_commits=()
    while IFS= read -r line; do
        [ -n "$line" ] && unique_commits+=("$line")
    done < <(compare_commits_jq "$source_repo_name" "$source_branch" "$dest_repo_name" "$dest_branch")
    
    local unique_count=${#unique_commits[@]}
    
    if [ $unique_count -eq 0 ]; then
        print_success "Repositories are in sync!"
        cd "$current_dir"
        return 0
    fi
    
    # Show what we found
    echo ""
    print_info "Found $unique_count new commits:"
    for commit in "${unique_commits[@]}"; do
        echo -e "  ${GREEN}•${NC} $commit"
    done
    
    # Ask for confirmation
    echo ""
    read -p "$(echo -e ${YELLOW}"Proceed with cherry-picking? (y/N): "${NC})" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Operation cancelled"
        cd "$current_dir"
        return 0
    fi
    
    # Execute git operations
    print_info "Executing git operations..."
    
    # Fetch from upstream with exact number needed + 1 for grafted
    local fetch_depth=$((unique_count + 1))
    print_info "Fetching from upstream (depth=$fetch_depth)..."
    git fetch upstream $source_branch --depth=$fetch_depth
    
    # Create temporary branch
    print_info "Creating temporary branch..."
    git branch -D temp-upstream 2>/dev/null || true
    git checkout -b temp-upstream upstream/$source_branch
    
    # Show what we'll cherry-pick
    print_info "Commits in temp-upstream:"
    git log --oneline -$fetch_depth
    
    # Switch back to destination branch
    print_info "Switching back to $dest_branch branch..."
    git checkout $dest_branch
    
    # Get commit hashes in correct order - Take the NEWEST commits
    local commit_hashes=($(git log temp-upstream --oneline -$fetch_depth | head -n $unique_count | cut -d' ' -f1))
    
    print_info "Cherry-picking $unique_count commits..."
    for ((i=${#commit_hashes[@]}-1; i>=0; i--)); do
        local hash="${commit_hashes[$i]}"
        local commit_msg=$(git log -1 --format="%s" "$hash")
        print_info "Cherry-picking: ${hash:0:8} - $commit_msg"
        if ! git cherry-pick "$hash"; then
            print_error "Cherry-pick failed!"
            print_warning "Resolve conflicts and run: git cherry-pick --continue"
            print_warning "Or abort with: git cherry-pick --abort"
            cd "$current_dir"
            return 1
        fi
    done
    
    # Push changes
    print_info "Pushing to origin..."
    git push --force origin
    
    # Clean up
    git branch -D temp-upstream
    
    print_success "Successfully synchronized $local_folder"
    
    cd "$current_dir"
}

###############################################################################
# MAIN EXECUTION
###############################################################################

print_header

# Check if REPOSITORIES array is defined and not empty
if [ ${#REPOSITORIES[@]} -eq 0 ]; then
    print_error "No repositories configured. Please edit the REPOSITORIES array in the script."
    exit 1
fi

print_info "Found ${#REPOSITORIES[@]} repository configuration(s)"
echo ""

# Process each repository
for i in "${!REPOSITORIES[@]}"; do
    IFS='|' read -r local_folder source_repo source_branch dest_repo dest_branch <<< "${REPOSITORIES[$i]}"
    
    print_repo_info "$i" "${#REPOSITORIES[@]}" "$local_folder" "$source_repo" "$source_branch" "$dest_repo" "$dest_branch"
    
    process_repository "$local_folder" "$source_repo" "$source_branch" "$dest_repo" "$dest_branch"
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    Repository Complete                         ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
done

print_success "All repositories processed!"
echo ""
