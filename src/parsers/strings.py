import re 

class StringsExtractor:
    def __init__(self,file_path):
        self.file_path = file_path

    def extract_strings(self, min_length=4):
        results = {
            'ips': [],
            'urls': [],
            'interesting_files': []
        }

        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()

            ascii_strings = re.findall(rb'[ -~]{' + bytes(str(min_length), 'utf-8') + rb',}', content)
            decoded_strings = [s.decode('utf-8', errors='ignore') for s in ascii_strings]

            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
            file_pattern = r'\b[\w\.-]+\.(?:exe|dll|bat|sys|conf|log|txt)\b'

            for s in decoded_strings:
                ips = re.findall(ip_pattern, s)
                if ips:
                    results['ips'].extend(ips)

                urls = re.findall(url_pattern, s)
                if urls:
                    results['urls'].extend(urls)

                files = re.findall(file_pattern, s, re.IGNORECASE)
                if files:
                    results['interesting_files'].extend(files)

            results['ips'] = list(set(results['ips']))
            results['urls'] = list(set(results['urls']))
            results['interesting_files'] = list(set(results['interesting_files']))

            return results

        except Exception as e:
            return  {
                'error': str(e)
            }
