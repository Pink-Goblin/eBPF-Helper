import sys
import os
import re
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

def solved_file(response, og_filename):
    try:
        pattern = r'Solution Code:\s*(.*?)(?=\n(?:\s*Source:|Kernel Version:|Additional Remarks:|$))'
        match = re.search(pattern, response, re.DOTALL)
        
        if not match:
            print("\n Could not extract solution code from response.")
            return
        
        code_section = match.group(1).strip()

        code_section = re.sub(r'^```(?:c|cpp|ebpf)?\n', '', code_section)
        code_section = re.sub(r'\n```$', '', code_section)
        code_section = code_section.strip()
        
        if not code_section or len(code_section) < 50:
            print("\n  Solution code seems too short or empty.")
            return
        
        # filename 
        base_name = os.path.splitext(os.path.basename(og_filename))[0]
        filename = f"{base_name}_corrected.bpf.c"
        filename2 = f"{base_name}_teste.txt"
        counter = 1
        while os.path.exists(filename):
            filename = f"{base_name}_corrected_{counter}.bpf.c"
            counter += 1
        while os.path.exists(filename2):
            filename2 = f"{base_name}_teste_{counter}.txt"
            counter += 1
        
        # save
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(code_section)

        with open(filename2, 'w', encoding='utf-8') as f:
            f.write(response)
        
        print(f"\n Corrected code saved to: {filename}")
        
    except Exception as e:
        print(f"\n  Error saving code: {str(e)}")


def analyze_ebpf_error(file_path, program_path):
    try:
        #Read the file content
        with open(file_path, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        if not log_content.strip():
            print("Error: The file is empty.")
            return     

        client = OpenAI(
        # API keys for the Singapore and Beijing regions are different. To get an API key, see https://www.alibabacloud.com/help/en/model-studio/get-api-key
        # If you have not configured an environment variable, replace the next line with your Model Studio API key: api_key="sk-xxx",
        api_key=os.getenv("LLM_API_KEY"),
        # The following base_url is for the Singapore region. If you use a model in the Beijing region, replace the base_url with: https://dashscope.aliyuncs.com/compatible-mode/v1
        base_url="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
)
        
        if (program_path != ''):
            print("pim")
            #Read the file content
            with open(program_path, 'r', encoding='utf-8') as f:
                log_content2 = f.read()
            
            if not log_content2.strip():
                print("Error: The file is empty.")
                return
            
            prompt = f"""I have an eBPF verifier error log. Could you analyze it and provide the information in this format:
                        Cause Description: 
                        Cause Code: 
                        Verifier Error Log: 
                        Solution Description: 
                        Solution Code: 
                        Source: 
                        Kernel Version: 
                        Clang Version: 
                        Additional Remarks:

                        IMPORTANT: For the "Solution Code:" section, please provide the COMPLETE corrected eBPF C code that fixes the verifier error. Include all necessary headers, structures, and the full program. The code should be fully functional while keeping the intent of the original program.

                        Here is the error log and original program:

                        {log_content} /// {log_content2}"""
        else:
            print("pum")
            prompt = f"""I have an eBPF verifier error log. Could you analyze it and provide the information in this format:
                    Cause Description: 
                    Cause Code: 
                    Verifier Error Log: 
                    Solution Description: 
                    Solution Code: 
                    Source: 
                    Kernel Version: 
                    Clang Version: 
                    Additional Remarks:

                    IMPORTANT: For the "Solution Code:" section, please provide the COMPLETE corrected eBPF C code that fixes the verifier error. Include all necessary headers, structures, and the full program. The code should be fully functional while keeping the intent of the original program.

                    Here is the error log:

                    {log_content}"""
        
        print("Analyzing eBPF verifier error...\n")
        
        # Send to qwen
        completion = client.chat.completions.create(
            model="qwen3-coder-plus", 
            messages=[
                {'role': 'system', 'content': 'You are a helpful assistant.'},
                {'role': 'user', 'content': prompt}],
            )
        
        # Extract and print the response
        response = completion.choices[0].message.content

        print("="*20+"Response"+"="*20)
        print(response)
        print("="*20+"Token Usage"+"="*20)
        print(f"In T: {completion.usage.prompt_tokens}")
        print(f"Out T: {completion.usage.completion_tokens}")
        print(f"Total T: {completion.usage.total_tokens}")
        

        solved_file(response, file_path)
        
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when trying to read '{file_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


def main():
    file_path = sys.argv[1]

    if len(sys.argv) == 2:
        program_path = ''
        analyze_ebpf_error(file_path, program_path)

    elif len(sys.argv) == 3:
        program_path = sys.argv[2]
        analyze_ebpf_error(file_path, program_path)

    else:
        print("Usage: python eBPF_Helper.py <error_log_file> or python eBPF_Helper.py <error_log_file> <original_program_file>")
        print("Example: python eBPF_Helper.py output.log")
        sys.exit(1)


if __name__ == "__main__":
    main()