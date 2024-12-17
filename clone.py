import subprocess
import os 

class Cloner:
    def __init__(self, projects_dir : str = "projects"):
        self.path = "repo"
        self.projects_dir = projects_dir
        
    def clone(self, url : str, path : str = 'repo') -> None:
        self.path = path
        subprocess.run(["git", "clone", url, os.path.join(self.projects_dir, path)])
    
    def checkout_to_vulnerable(self, commit_id : str) -> None:
        subprocess.run(f"cd {os.path.join(self.projects_dir, self.path)} && git checkout {commit_id}  && git checkout HEAD^", shell=True)
    
    def checkout_to_benign(self,  commit_id : str) -> None:
        subprocess.run(f"cd {os.path.join(self.projects_dir, self.path)} && git checkout {commit_id}", shell=True)
        
    def remove_repo(self) -> None:
        try:            
            subprocess.run(f"rm -rf {os.path.join(self.projects_dir, self.path)}", shell=True)
        except Exception as e:
            print("Repository doesn't exist")