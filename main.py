import json
from clone import Cloner 
from split import Chunker
import os
from pprint import pprint 
from difflib import SequenceMatcher

def load_jsonl(file_path):
    data = []
    with open(file_path, 'r') as file:
        for line in file:
            data.append(json.loads(line.strip()))
    return data

def load_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def create_dataset(data, cwe, commit_id, vulnerable_function):
    with open(f'./benchmark/{cwe}.jsonl', 'w') as file:
        for entry in data:
            file_path, function_signature, callees, function_body = entry
            
            similarity = SequenceMatcher(None,function_body.replace(" ", ""), vulnerable_function.replace(" ", "")).ratio()
            if similarity > 0.9:
                print('vulnerable function')
                vulnerable_entry = {
                    'file_path': file_path,
                    'function_signature': function_signature,
                    'callees': callees,
                    'function_body': function_body,
                    'cwe': cwe,
                    'commit_id': commit_id,
                    'vulnerable' : 1
                }
                continue
            
            new_entry = {
                'file_path': file_path,
                'function_signature': function_signature,
                'callees': callees,
                'function_body': function_body,
                'cwe': cwe,
                'commit_id': commit_id,
                'vulnerable' : 0
            }
            
            file.write(json.dumps(new_entry) + '\n')
        file.write(json.dumps(vulnerable_entry) + '\n')
    
        

def main():
    file_path = './new_benchmark.jsonl'
    data = load_jsonl(file_path)
    
    file_path = './mapping.json'
    mapping = load_json(file_path)
    
    cloner = Cloner()
    chunker = Chunker()
    
    for entry in data:
        if entry["cwe"] != "CWE-77":
            continue
        project = entry['project']
        url = mapping[project]
        commit_id = entry['commit_id']
        vulnerable_function = entry['function']
        
        print("cloning", project)
        
        # cloner.remove_repo()
        # cloner.clone(url)
        
        # cloner.checkout_to_vulnerable(entry['commit_id'])
        
        processed_data = chunker.read_and_parse_documents_with_callees(os.path.join(cloner.projects_dir, cloner.path))
        
        create_dataset(processed_data, entry['cwe'], commit_id, vulnerable_function)
        
        
        
        


if __name__ == '__main__':
    main()