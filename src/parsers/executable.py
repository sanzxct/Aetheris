import pefile
import datetime
import math

class ExecutableParser:
    def __init__(self, file_path):
        self.file_path = file_path

    def calculate_entropy(self,data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    def extract_pe_info(self):
        results = {}

        try:
            pe = pefile.PE(self.file_path)
            compile_time = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            results['Compile_Time'] = compile_time.strftime('%Y-%m-%d %H:%M:%S')

            results['Machine'] = hex(pe.FILE_HEADER.Machine)

            results['Sections'] = []
            for section in pe.sections:
                s_name = section.Name.decode().strip('\x00')
                s_entropy = self.calculate_entropy(section.get_data())
                results['Sections'].append(f"{s_name} ({round(s_entropy, 2)})")

            suspicious_functions = ['ShellExecute', 'HttpSendRequest', 'GetKeyboardState', 'CreateRemoteThread']
            found_suspicious = []

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                total_imports = 0
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    total_imports+= len(entry.imports)
                
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8')
                            if any (f in name for f in suspicious_functions):
                                found_suspicious.append(name)
                
                results['Total_Imports'] = total_imports

                if found_suspicious:
                    results['Suspicious_API'] = ", ".join(list(set(found_suspicious)))

            pe.close()
            return results
        except Exception as e:
            return {
                'error' : f"Not a valid PE file or {str(e)}"
            }
