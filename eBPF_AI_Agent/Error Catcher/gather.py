import os
import re
import logging
import requests
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
github_token = os.getenv('GITHUB_TOKEN')
mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
mongo_db = os.getenv('MONGO_DB', 'eBPF_Errors')
mongo_collection = os.getenv('MONGO_COLLECTION', 'verifier_errors_explained')

#connect
uri = mongo_uri
mongo_client = MongoClient(uri)
mongo_db = mongo_client[mongo_db]
collection = mongo_db[mongo_collection]


class GitHubIssueFetcher:
    def __init__(self, github_token, collection):
        self.github_token = github_token
        self.collection = collection
        
    def get_headers(self):
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'GitHubIssueFetcher'
            }
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            return headers

    def parse(self, body):
        if not body:
            return{}
        sections = {
            "Cause Description": r"## Cause Description\s*```[\w]*\s*(.*?)```",
            "Cause Code": r"## Cause Code\s*```[\w]*\s*(.*?)```",
            "Verifier Error Log": r"## Verifier Error Log\s*```[\w]*\s*(.*?)```",
            "Solution Description": r"## Solution Description\s*```[\w]*\s*(.*?)```",
            "Solution Code": r"## Solution Code\s*```[\w]*\s*(.*?)```",
            "Source": r"## Source\s*(.*?)(?=##|\Z)",
            "Kernel Version": r"## Kernel Version\s*(.*?)(?=##|\Z)",
            "Clang Version": r"## Clang Version\s*(.*?)(?=##|\Z)",
            "Additional Remarks": r"## Additional Remarks\s*```[\w]*\s*(.*?)```"
        }

        parsed_data = {}

        for section_name, pattern in sections.items():
            match = re.search(pattern, body, re.DOTALL | re.IGNORECASE)
            if match:
                content = match.group(1).strip()
                parsed_data[section_name] = content if content else None
            else:
                parsed_data[section_name] = None
            
        return parsed_data

    def fetch_all_issues(self):
            page = 1
            per_page = 30
            issue_count = 0
            max_issues = 200  

            while issue_count < max_issues:
                api_url = "https://api.github.com/repos/parttimenerd/ebpf-verifier-errors/issues"
                params = {"state": "all", "labels": "submission", "page": page, "per_page": per_page}
                response = requests.get(api_url, headers=self.get_headers(), params=params)

                if response.status_code != 200:
                    logging.error(f"API error ({response.status_code}): {response.text}")
                    break

                issues = response.json()
                if not issues:
                    break

                for issue in issues:
                    # Skip pull requests
                    if 'pull_request' in issue:
                        continue

                    self.process_issue(issue)
                    issue_count += 1
                    if issue_count >= max_issues:
                        logging.info(f"Reached limit of {max_issues} errors")
                        return

                page += 1



    def process_issue(self, issue_data):
        description = issue_data.get('body', '') or ''
        parsed_sections = self.parse(description)

        issue_doc = {
            "title": issue_data.get('title', 'No title'),
            "Cause Description": parsed_sections.get("Cause Description"),
            "Cause Code": parsed_sections.get("Cause Code"),
            "Verifier Error Log": parsed_sections.get("Verifier Error Log"),
            "Solution Description": parsed_sections.get("Solution Description"),
            "Solution Code": parsed_sections.get("Solution Code"),
            "Source": parsed_sections.get("Source"),
            "Kernel Version": parsed_sections.get("Kernel Version"),
            "Clang Version": parsed_sections.get("Clang Version"),
            "Additional Remarks": parsed_sections.get("Additional Remarks"),
            "issue_status": "Closed" if issue_data.get('state') == 'closed' else "Open",
            "created_at": datetime.now(),
            "github_id": issue_data.get('id'),
            "issue_number": issue_data.get('number'),
            "url": issue_data.get('html_url')
        }

        # Check for existing issue
        existing = self.collection.find_one({
            "$or": [
                {"github_id": issue_doc["github_id"]},
                {"issue_number": issue_doc["issue_number"]}
            ]
        })
        
        if existing:
            self.collection.update_one(
                {"_id": existing["_id"]},
                {"$set": issue_doc}
            )
            logging.info(f"Updated issue #{issue_doc['issue_number']}: {issue_doc['title']}")
        else:
            self.collection.insert_one(issue_doc)
            logging.info(f"Inserted issue #{issue_doc['issue_number']}: {issue_doc['title']}")


def main():
    try:
        fetcher = GitHubIssueFetcher(github_token, collection)
        logging.info("Starting to fetch GitHub issues...")
        fetcher.fetch_all_issues()
        logging.info("Finished fetching issues")
    except Exception as e:
        logging.error(f"Error in main execution: {e}")
    finally:
        mongo_client.close()
        logging.info("MongoDB connection closed")


if __name__ == "__main__":
    main()
