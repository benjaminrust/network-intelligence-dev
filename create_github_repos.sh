#!/bin/bash

# Network Intelligence - GitHub Repository Creation Script
# This script helps create GitHub repositories and push code

set -e

echo "🚀 Network Intelligence - GitHub Repository Setup"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if GitHub CLI is installed
if command -v gh &> /dev/null; then
    print_success "GitHub CLI found!"
    USE_GH_CLI=true
else
    print_warning "GitHub CLI not found. Will use manual setup."
    USE_GH_CLI=false
fi

# Function to create repository with GitHub CLI
create_repo_with_gh() {
    local repo_name=$1
    local description=$2
    local visibility=${3:-public}
    
    print_status "Creating repository: $repo_name"
    gh repo create "$repo_name" --description "$description" --$visibility --source=. --remote=origin --push
    print_success "Repository $repo_name created and code pushed!"
}

# Function to create repository manually
create_repo_manually() {
    local repo_name=$1
    local description=$2
    
    print_status "Manual setup for repository: $repo_name"
    echo "Please follow these steps:"
    echo "1. Go to: https://github.com/new"
    echo "2. Repository name: $repo_name"
    echo "3. Description: $description"
    echo "4. Visibility: Public (or Private if preferred)"
    echo "5. DO NOT initialize with README (we already have code)"
    echo "6. Click 'Create repository'"
    echo ""
    echo "After creating the repository, run:"
    echo "git remote add origin https://github.com/benjaminrust/$repo_name.git"
    echo "git push -u origin main"
    echo ""
    read -p "Press Enter when you've created the repository..."
}

# Function to setup repository
setup_repository() {
    local repo_name=$1
    local description=$2
    local local_path=$3
    
    print_status "Setting up $repo_name..."
    
    # Change to the local directory
    cd "$local_path"
    
    if [ "$USE_GH_CLI" = true ]; then
        create_repo_with_gh "$repo_name" "$description"
    else
        create_repo_manually "$repo_name" "$description"
        
        # Add remote and push
        print_status "Adding GitHub remote..."
        git remote add origin "https://github.com/benjaminrust/$repo_name.git"
        
        print_status "Pushing code to GitHub..."
        git push -u origin main
        
        print_success "Repository $repo_name setup complete!"
    fi
}

# Main execution
echo ""
print_status "Starting repository creation process..."

# Create repositories
setup_repository "network-intelligence-dev" "Network Intelligence Development App" "/Users/brust/bin/network-intelligence-dev"
setup_repository "network-intelligence-stage" "Network Intelligence Staging App" "/Users/brust/bin/network-intelligence-stage"
setup_repository "network-intelligence-prod" "Network Intelligence Production App" "/Users/brust/bin/network-intelligence-prod"

echo ""
print_success "All repositories have been created!"
echo ""
echo "📋 Next Steps for Collaborative Development:"
echo "1. Set up branch protection rules on GitHub"
echo "2. Configure CI/CD workflows"
echo "3. Add collaborators to repositories"
echo "4. Set up issue templates and project boards"
echo "5. Configure automated testing"
echo ""
echo "🔗 Repository URLs:"
echo "- Development: https://github.com/benjaminrust/network-intelligence-dev"
echo "- Staging: https://github.com/benjaminrust/network-intelligence-stage"
echo "- Production: https://github.com/benjaminrust/network-intelligence-prod"
echo ""
print_success "Network Intelligence suite is ready for collaborative development!" 