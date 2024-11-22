from fame.core.module import ProcessingModule,ModuleInitializationError, ModuleExecutionError

from email import policy
from email.parser import BytesParser
import re
import os
import requests

class LinkAnalyser(ProcessingModule):
    name = "linkanalyser"
    description = "Extracts links from EML files and queries VirusTotal."
    acts_on = ["eml"]

    # Configuration options
    config = [
        {
            'name': 'api_key',
            'type': 'str',
            'default': '',
            'description': 'VirusTotal API key.'
        },
        {
            'name': 'attributes_to_extract',
            'type': 'text',
            'default': '',
            'description': 'Attributes to extract from VirusTotal response, one per line.'
        },
        {
            'name': 'config_file',
            'type': 'str',
            'default': '',
            'description': 'Optional path to a config file with attributes to extract.'
        }
    ]

    def initialize(self):
        # Check for required dependencies
        try:
            import requests
        except ImportError:
            raise ModuleInitializationError(self, "Missing dependency: requests")

        # Ensure API key is provided
        if not self.api_key:
            raise ModuleInitializationError(self, "VirusTotal API key is not configured.")

        # Prepare attributes to extract
        self.attributes_to_extract = []
        if self.attributes_to_extract:
            self.attributes_to_extract = [attr.strip() for attr in self.attributes_to_extract.split('\n') if attr.strip()]
        elif self.config_file:
            self.attributes_to_extract = self.load_config(self.config_file)

        # Set up headers for VirusTotal API
        self.base_url = "https://www.virustotal.com/api/v3/search"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def each(self, target):
        try:
            # Extract and clean links from the EML file
            links = self.clean_links(self.extract_links_from_eml(target))

            if not links:
                self.results = {"message": "No links found in the EML file."}
                return True

            result_data = {}
            for link in links:
                vt_data = self.request_vt_api(link)
                if vt_data:
                    result_data[link] = vt_data
                    # Add IOCs to the analysis
                    self.add_ioc(link, tags=["url"])
                else:
                    result_data[link] = "No data found or request failed."

            # Store results
            self.results = result_data

            return True  # Return True if processing was successful

        except Exception as e:
            raise ModuleExecutionError(self, f"Error processing EML file: {e}")

    def load_config(self, config_file):
        """Load attributes to extract from the configuration file."""
        attributes = []
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                attributes = [line.strip() for line in f if line.strip()]
        return attributes

    @staticmethod
    def extract_links_from_eml(file_path):
        with open(file_path, "rb") as eml_file:
            msg = BytesParser(policy=policy.default).parse(eml_file)

        links = []

        def find_links(text):
            return re.findall(r'(https?://\S+)', text)

        if msg.is_multipart():
            for part in msg.iter_parts():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    part_content = part.get_content()
                    links.extend(find_links(part_content))
        else:
            part_content = msg.get_content()
            links.extend(find_links(part_content))
        return links

    @staticmethod
    def clean_links(links):
        cleaned_links = []
        urldefense_pattern = re.compile(r'https://urldefense\.com/v\d/__([^;]+);')

        for link in links:
            if "urldefense" in link:
                match = urldefense_pattern.search(link)
                if match:
                    cleaned_link = match.group(1).replace('__', '')
                    cleaned_links.append(cleaned_link)
                else:
                    cleaned_links.append(link)
            else:
                cleaned_links.append(link)
        return cleaned_links

    def request_vt_api(self, query):
        params = {"query": query}
        response = requests.get(self.base_url, headers=self.headers, params=params)
        if response.status_code == 200:
            data = response.json()
            return self.filter_vt_response(data)
        else:
            # Log the error
            self.log('error', f"VirusTotal API request failed for {query}: {response.status_code} - {response.text}")
            return None  # Return None if the request fails

    def filter_vt_response(self, data):
        """Filter the VirusTotal response based on the attributes to extract."""
        filtered_item = {}
        for item in data.get('data', []):
            for attribute in self.attributes_to_extract:
                value = self.get_nested_value(item, attribute.split('.'))
                if value is not None:
                    filtered_item[attribute] = value
        return filtered_item if filtered_item else data  # Return the entire data if no specific attributes are found

    def get_nested_value(self, data_dict, keys):
        """Retrieve the nested value from a dictionary based on a list of keys."""
        for key in keys:
            if isinstance(data_dict, dict) and key in data_dict:
                data_dict = data_dict[key]
            else:
                return None
        return data_dict
