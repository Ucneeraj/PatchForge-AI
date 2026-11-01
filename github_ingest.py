import tempfile
from git import Repo

def clone_repository(repo_url):
    # Create a temporary directory to hold the downloaded code
    temp_dir = tempfile.mkdtemp(prefix="patchforge_")
    print(f"Downloading repository from {repo_url}...")
    
    # Clone the GitHub repository into the temporary folder
    Repo.clone_from(repo_url, temp_dir)
    print(f"Success! Code is saved temporarily at: {temp_dir}")
    
    return temp_dir