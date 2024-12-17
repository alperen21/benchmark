
from tree_sitter import Parser
from tree_sitter_languages import get_parser
import os 

class Chunker:
    def __init__(self):
        self.__parsers = {
        '.py': get_parser('python'),
        '.js': get_parser('javascript'),
        '.java': get_parser('java'),
        '.cpp': get_parser('cpp'),
        '.cc': get_parser('cpp'),
        '.c': get_parser('c'),
        '.h': get_parser('c'),
        '.cs': get_parser('c_sharp'),
    }
        
        
    def __get_all_files(self, repo_path):
        file_paths = []
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                file_paths.append(os.path.join(root, file))
        return file_paths
    
    def __is_code_file(self, file_path):
        return os.path.splitext(file_path)[1] in self.__parsers
    
    def __extract_chunks(self, file_path):
        
        ext = os.path.splitext(file_path)[1]
        parser = self.__parsers[ext]
        
        with open(file_path, 'rb') as f:
            content = f.read()
            
        tree = parser.parse(content)

        chunks = []
        cursor = tree.walk()
        stack = [cursor.node]
        

        while stack:
            node = stack.pop()
            if node.is_named:
                # Customize the node types to extract
                if node.type in ('function_definition'):
                    start_byte = node.start_byte
                    end_byte = node.end_byte
                    
                    function_signature = self.get_function_signature(node, content.decode('utf-8', errors='replace'))
                    chunks.append((content[start_byte:end_byte], function_signature))
                    # print(self.find_callees(node, content.decode('utf-8', errors='replace')))
                else:
                    stack.extend(node.children)
        return chunks
    
    def extract_callees_and_body(self, file_path):
        ext = os.path.splitext(file_path)[1]
        parser = self.__parsers[ext]
        
        with open(file_path, 'rb') as f:
            content = f.read()
            
        tree = parser.parse(content)

        chunks = []
        cursor = tree.walk()
        stack = [cursor.node]
        

        while stack:
            node = stack.pop()
            if node.is_named:
                # Customize the node types to extract
                if node.type in ('function_definition'):
                    start_byte = node.start_byte
                    end_byte = node.end_byte
                    
                    function_signature = self.get_function_signature(node, content.decode('utf-8', errors='replace'))
                    
                    callees = self.find_callees(node, content.decode('utf-8', errors='replace'))
                    chunks.append((file_path, function_signature, callees, content[start_byte:end_byte].decode('utf-8', errors='replace')))
                    
                else:
                    stack.extend(node.children)
        return chunks
        
    
    def read_and_parse_documents(self, repo_path):
        code_files = [
            f for f in self.__get_all_files(repo_path) if self.__is_code_file(f)
        ]
        documents = []
        
        for file_path in code_files:
                chunks = self.__extract_chunks(file_path)
                
                for chunk in chunks:
                    function_body, function_signature = chunk   
                    function_body = function_body.decode('utf-8', errors='replace')
                    documents.append((function_body, function_signature))
        
        return documents
    
    def read_and_parse_documents_with_callees(self, repo_path):
        code_files = [
            f for f in self.__get_all_files(repo_path) if self.__is_code_file(f)
        ]
        documents = []
        
        for file_path in code_files:
                chunks = self.extract_callees_and_body(file_path)
                
                for chunk in chunks:
                    file_path, function_signature, callees, function_body = chunk   
                    documents.append((file_path, function_signature, callees, function_body))
        
        return documents
        
    


    def get_node_text(self, node, source_code):
        start_byte = node.start_byte
        end_byte = node.end_byte
        return source_code[start_byte:end_byte]
    
    def debug_print_node(self, node, source_code, indent=0):
        prefix = '  ' * indent
        print(f"{prefix}{node.type}: {source_code[node.start_byte:node.end_byte]}")
        for c in node.children:
            self.debug_print_node(c, source_code, indent + 1)

    # Function to extract the signature from a function_definition node
    def get_function_signature(self, node, source_code):
        signature_parts = []

        # Handle storage class specifiers and other modifiers (e.g., static, virtual)
        storage_specifiers = []
        for child in node.children:
            if child.type in ('storage_class_specifier', 'type_qualifier'):
                storage_specifiers.append(self.get_node_text(child, source_code))

        if storage_specifiers:
            signature_parts.extend(storage_specifiers)

        # Handle return type
        return_type_node = None
        for child in node.children:
            if child.type == 'type_descriptor':
                return_type_node = child
                break

        if return_type_node:
            return_type = self.get_node_text(return_type_node, source_code)
            signature_parts.append(return_type)

        # Handle function declarator
        function_declarator_node = None
        for child in node.children:
            if child.type == 'function_declarator':
                function_declarator_node = child
                break

        if function_declarator_node:
            # Extract function name and parameters
            # Function name might be nested within pointers or references
            identifier_node = None
            parameters_node = None

            # Use a recursive function to find the identifier and parameters
            def find_identifier_and_parameters(node):
                nonlocal identifier_node, parameters_node
                for child in node.children:
                    if child.type == 'identifier' and identifier_node is None:
                        identifier_node = child
                    elif child.type == 'parameter_list' and parameters_node is None:
                        parameters_node = child
                    else:
                        find_identifier_and_parameters(child)

            find_identifier_and_parameters(function_declarator_node)

            if identifier_node:
                function_name = self.get_node_text(identifier_node, source_code)
                signature_parts.append(function_name)

            if parameters_node:
                parameters_text = self.get_node_text(parameters_node, source_code)
                signature_parts.append(parameters_text)

        # Handle trailing return type (C++11)
        trailing_return_type_node = None
        for child in node.children:
            if child.type == 'trailing_return_type':
                trailing_return_type_node = child
                break

        if trailing_return_type_node:
            trailing_return_type = self.get_node_text(trailing_return_type_node, source_code)
            signature_parts.append(trailing_return_type)

        # Handle function specifiers (e.g., noexcept, const)
        function_specifiers = []
        for child in node.children:
            if child.type in ('noexcept', 'type_qualifier'):
                function_specifiers.append(self.get_node_text(child, source_code))

        if function_specifiers:
            signature_parts.extend(function_specifiers)

        # Handle template declarations
        template_node = None
        parent_node = node.parent
        if parent_node and parent_node.type == 'template_declaration':
            template_node = parent_node.child_by_field_name('parameters')
            if template_node:
                template_text = self.get_node_text(template_node, source_code)
                signature_parts.insert(0, f"template{template_text}")

        # Combine the parts into the signature
        signature = ' '.join(signature_parts)
        return signature.strip()
    
    
    def find_function_calls(self, node, source_code):
        function_calls = []

        # If the node is a call_expression, extract the function name
        if node.type == 'call_expression':
            function_name_node = node.child_by_field_name('function')
            if function_name_node:
                function_name = self.get_node_text(function_name_node, source_code)
                function_calls.append(function_name)
        else:
            # Recursively search child nodes
            for child in node.children:
                function_calls.extend(self.find_function_calls(child, source_code))
        return function_calls

# Main function to find callees within a function_definition node
    def find_callees(self, function_node, source_code):
        # Find the compound_statement node (function body)
        body_node = None
        for child in function_node.children:
            if child.type == 'compound_statement':
                body_node = child
                break
        if not body_node:
            return []

        # Find all function calls within the body
        callees = self.find_function_calls(body_node, source_code)
        return callees