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
    # Example 1
    "my-project|https://github.com/original/project.git|main|https://github.com/yourusername/project-fork.git|main"
    
    # Example 2
    "project-legacy|https://github.com/original/project.git|legacy|https://github.com/yourusername/project-legacy.git|develop"
    
    # Add more repositories below as needed:
    # "local-folder|source-repo|source-branch|dest-repo|dest-branch"
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

# Extract owner/repo from URLs
extract_repo_info() {
    local url="$1"
    if [[ "$url" =~ https://github.com/([^/]+)/([^/.]+) ]]; then
        echo "${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
    elif [[ "$url" =~ git@github.com:([^/]+)/([^/.]+) ]]; then
        echo "${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
    else
        print_error "Invalid GitHub URL: $url"
        return 1
    fi
}

# Function to get commits via API for a given count
get_commits_for_count() {
    local repo_info="$1"
    local branch="$2"
    local count=$3
    
    local temp1=$(mktemp)
    
    # Get commits using GitHub API
    curl -s -H "Accept: application/vnd.github.v3+json" \
      "https://api.github.com/repos/$repo_info/commits?sha=$branch&per_page=$count" > "$temp1"
    
    # Extract commit messages and hashes
    if command -v jq >/dev/null 2>&1; then
        jq -r '.[] | "\(.sha)|\(.commit.message | split("\n")[0])"' "$temp1" > "$temp1.commits"
    else
        grep -E '"sha"|"message"' "$temp1" | \
        sed 's/"sha":/"hash"/g' | \
        sed 's/"message":"//g' | \
        sed 's/",//g' | \
        sed 's/^ *//g' | \
        paste -d "|" - - | \
        sed 's/"hash": "\([^"]*\)"/\1/g' | \
        head -n "$count" > "$temp1.commits"
    fi
    
    cat "$temp1.commits"
    rm -f "$temp1" "$temp1.commits"
}

# Process a single repository
process_repository() {
    local local_folder="$1"
    local source_repo="$2"
    local source_branch="$3"
    local dest_repo="$4"
    local dest_branch="$5"
    
    # Store current directory
    local current_dir=$(pwd)
    
    # Check if local folder exists
    if [ ! -d "$local_folder" ]; then
        print_error "Local repository directory '$local_folder' does not exist"
        return 1
    fi
    
    # Change to target repo
    cd "$local_folder"
    
    print_info "Working in: $(pwd)"
    
    # Extract repo info for API calls
    local source_repo_info=$(extract_repo_info "$source_repo") || return 1
    local dest_repo_info=$(extract_repo_info "$dest_repo") || return 1
    
    print_info "Comparing: $source_repo_info ($source_branch) → $dest_repo_info ($dest_branch)"
    
    # Auto-adjust search depth based on differences found
    print_info "Auto-adjusting search depth..."
    local count=25
    local unique_commits=()
    local max_count=400  # Safety limit
    
    while [ $count -le $max_count ]; do
        # Get commits from source repo
        local source_commits=$(get_commits_for_count "$source_repo_info" "$source_branch" "$count")
        
        # Get commits from destination repo (only messages for comparison)
        local dest_commits_temp=$(mktemp)
        get_commits_for_count "$dest_repo_info" "$dest_branch" "$count" | cut -d'|' -f2 > "$dest_commits_temp"
        
        # Find unique commits
        local current_unique=()
        while IFS='|' read -r hash message; do
            if [ -n "$message" ] && ! grep -q -F "$message" "$dest_commits_temp"; then
                current_unique+=("$hash|$message")
            fi
        done <<< "$source_commits"
        
        rm -f "$dest_commits_temp"
        
        local current_count=${#current_unique[@]}
        
        if [ $current_count -eq 0 ]; then
            print_success "No unique commits found in last $count commits"
            break
        elif [ $current_count -lt $count ]; then
            print_success "Stable count reached: $current_count unique commits in last $count commits"
            unique_commits=("${current_unique[@]}")
            break
        else
            print_warning "Found $current_count differences in last $count commits, increasing search depth..."
            local old_count=$count
            count=$((count * 2))
            
            if [ $count -gt $max_count ]; then
                count=$max_count
                print_warning "Reached maximum search depth of $max_count commits"
                unique_commits=("${current_unique[@]}")
                break
            fi
        fi
    done
    
    local unique_count=${#unique_commits[@]}
    
    if [ $unique_count -eq 0 ]; then
        print_success "Repositories are in sync!"
        cd "$current_dir"
        return 0
    fi
    
    # Display found commits
    echo ""
    print_info "Found $unique_count commits to cherry-pick:"
    for commit in "${unique_commits[@]}"; do
        IFS='|' read -r hash message <<< "$commit"
        echo -e "  ${GREEN}•${NC} ${hash:0:8}: $message"
    done
    
    # Ask for confirmation
    echo ""
    read -p "$(echo -e ${YELLOW}"Proceed with cherry-picking? (y/N): "${NC})" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Operation cancelled for $local_folder"
        cd "$current_dir"
        return 0
    fi
    
    # Execute git operations
    print_info "Executing git operations..."
    
    # Fetch from upstream
    local fetch_depth=$((unique_count + 1))
    print_info "Fetching from upstream (depth=$fetch_depth)..."
    git fetch upstream --depth=$fetch_depth
    
    # Create temporary branch
    print_info "Creating temporary branch..."
    git branch -D temp-upstream 2>/dev/null || true
    git checkout -b temp-upstream upstream/master
    
    # Show recent commits
    print_info "Recent commits in temp-upstream:"
    git log --oneline -$fetch_depth
    
    # Switch back to master
    print_info "Switching back to master..."
    git checkout master
    
    # Cherry-pick in reverse order (oldest first)
    print_info "Cherry-picking $unique_count commits (oldest first)..."
    
    local commit_hashes=()
    for ((i=unique_count-1; i>=0; i--)); do
        IFS='|' read -r hash message <<< "${unique_commits[$i]}"
        commit_hashes+=("$hash")
    done
    
    for hash in "${commit_hashes[@]}"; do
        print_info "Cherry-picking: ${hash:0:8}"
        if ! git cherry-pick "$hash"; then
            print_error "Cherry-pick failed for ${hash:0:8}"
            print_warning "Manual resolution required. temp-upstream branch preserved."
            cd "$current_dir"
            return 1
        fi
    done
    
    # Push to origin
    print_info "Pushing to origin..."
    git push --force origin
    
    print_success "Successfully processed $local_folder - $unique_count commits cherry-picked"
    
    # Return to original directory
    cd "$current_dir"
    echo ""
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
