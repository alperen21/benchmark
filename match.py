import json
import glob

def read_jsonl(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            yield json.loads(line)

def get_function_name(function_signature):
    return function_signature.split('(')[0].strip()

def create_map(jsonl_file):
    data = read_jsonl(jsonl_file)
    
    callees_map = dict()
    for entry in data:
        function_signature = entry['function_signature']
        function_name = get_function_name(function_signature)
        callees = entry['callees']
        callees_map[function_name] = callees
    
    callers_map = dict()
    for key, value in callees_map.items():
        for callee in value:
            if callee not in callers_map:
                callers_map[callee] = list()
            callers_map[callee].append(key)
    
    mappings = dict()
    data = read_jsonl(jsonl_file)

    for entry in data:
        function_signature = entry['function_signature']
        function_name = get_function_name(function_signature)
        function_body = entry['function_body']
        
        mappings[function_name] = {
            'function_signature': function_signature,
            'function_body': function_body,
            'callees': callees_map.get(function_name, []),
            'callers': callers_map.get(function_name, [])
        }
       
    return mappings

def find_jsonl_files(directory):
    return glob.glob(f"{directory}/*.jsonl")

def main():
    jsonl_files = find_jsonl_files('./benchmark')

    for jsonl_file in jsonl_files:
        file_name = jsonl_file.split('/')[-1].split('.')[0]
        print(f"Processing file: {file_name}")
        map = create_map(jsonl_file)
        with open(f'./benchmark/{file_name}_mapping.json', 'w') as outfile:
            json.dump(map, outfile, indent=4)

if __name__ == '__main__':
    main()
