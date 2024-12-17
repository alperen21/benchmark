import sys
import json
import os
from clone import Cloner 
from split import Chunker
from difflib import SequenceMatcher


def read_jsonl(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            yield json.loads(line)
            
def create_map(data):
    callees_map = dict()
    for entry in data:
        file_path, function_signature, callees, function_body = entry
        function_name = get_function_name(function_signature)
        callees_map[function_name] = callees
    
    callers_map = dict()
    for key, value in callees_map.items():
        for callee in value:
            if callee not in callers_map:
                callers_map[callee] = list()
            callers_map[callee].append(key)
    
    mappings = dict()

    for entry in data:
        file_path, function_signature, callees, function_body = entry
        function_name = get_function_name(function_signature)
        
        
        mappings[function_name] = {
            'function_signature': function_signature,
            'function_body': function_body,
            'callees': callees_map.get(function_name, []),
            'callers': callers_map.get(function_name, [])
        }
       
    return mappings

def get_data() -> list:
    data = []
    
    datasets = ["train", "test", "valid"]
    
    for dataset in datasets:
        path = os.path.join("functional", f"primevul_{dataset}.jsonl")
        data.extend(list(read_jsonl(path)))
    return data 

def filter(data: list) -> list:
    return [item for item in data if item.get('target') == 1]


def load_mapping_json():
    with open("mapping.json", 'r') as file:
        return json.load(file)

def normalize_function_body(function_body):
    return function_body.replace("  ", "").strip()

def check_if_same_function(function1, function2):
    similarity = SequenceMatcher(None,normalize_function_body(function1), normalize_function_body(function2)).ratio()
    return similarity > 0.9
    
def find_vulnerable_function(data, vulnerable_function):
    retrieved_functions = []
    for entry in data:
        file_path, function_signature, callees, function_body = entry
        if check_if_same_function(function_body, vulnerable_function):
            retrieved_functions.append(entry)
    return retrieved_functions

def extract_callers(data, function_name):
    callers = []
    for entry in data:
        file_path, function_signature, callees, function_body = entry
        if function_name in callees:
            callers.append({"file_path": file_path, "function_signature": function_signature, "function_body": function_body})
    return callers

def get_function_name(function_signature):
    return function_signature.split('(')[0].strip()

def process(vulnerable_function, cloner, chunker, project_name, commit_id):
    
    processed_data = chunker.read_and_parse_documents_with_callees(os.path.join(cloner.projects_dir, cloner.path))
    vulnerable_function_candidates = find_vulnerable_function(processed_data, vulnerable_function)
    
    if len(vulnerable_function_candidates) != 1:
        return None
    file_path, function_signature, callees, function_body = vulnerable_function_candidates[0]
    
    # extract bodies of callee functions 
    name_to_body = create_map(processed_data)
    
    try:
        callees = [{"name": callee, "function" : name_to_body.get(callee, "")} for callee in callees]
    except Exception:
        print(callees)
        input()
    
    # extract functions calling the vulnerable function
    function_name = get_function_name(function_signature)
    callers = extract_callers(processed_data, function_name)
    print(callers)
    
    # print("done")
    # input()
    
    # extract bodies of caller functions
    try:
        callers = [{"name": caller, "function": name_to_body.get(caller["function_signature"],"")} for caller in callers]
    except Exception:
        print(callers)
        input()
    
    
    return {
        "project" : project_name,
        "commit_id" : commit_id,
        "function" : vulnerable_function,
        "callers" : str(callers),
        "callees" : str(callees) 
    }

def main():
    # get data
    data = get_data()
    # filter based on vulnerabilty
    data = filter(data)
    # find repository
    function_repo_mapping = load_mapping_json()
    
    
    for idx, entry in enumerate(data):
        try:
            project_name = entry["project"]
            url = function_repo_mapping.get(project_name)
            commit_id = entry['commit_id']
            vulnerable_function = entry['func']
            
            if url is None:
                continue
        
            # clone repository

            chunker = Chunker()
            cloner = Cloner()
            cloner.remove_repo()
            cloner.clone(url)
            
            
            # checkout to vulnerable
            cloner.checkout_to_vulnerable(entry['commit_id'])
            vulnerable_entry = process(vulnerable_function, cloner, chunker, project_name, commit_id)

            if vulnerable_entry is None:
                continue
            
            # checkout to non-vulnerable
            cloner.checkout_to_benign(entry["commit_id"])
            benign_entry = process(vulnerable_function, cloner, chunker, project_name, commit_id)
            
            if benign_entry is None:
                continue
            # extract functions calling the vulnerable function
            # extract bodies of caller functions
            # extract functions called by the vulnerable function
            # extract bodies of callee functions 
            
            # delete the repository 
            # construct json object
            # write to the jsonl file
            
            entry = {
                "vulnerable" : vulnerable_entry,
                "benign" : benign_entry
            }
            
            with open("paired.jsonl", 'a') as file:
                file.write(json.dumps(entry) + "\n")
        except KeyboardInterrupt as e:
            print("\nlast index:", idx)
            raise e
            
        
if __name__ == '__main__':
    main()