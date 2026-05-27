import requests
from dotenv import load_dotenv
from datetime import date
import os
import urllib.parse
import argparse

# Load .env file
load_dotenv()


class DependabotFinder():
    def __init__(self, org, label=None):
        # Constants
        self.ORGANIZATION = org
        self.LABEL = label or org
        self.GITHUB_TOKEN = os.getenv(f'{org}.GITHUB_TOKEN')
        self.URL_REPOS = os.getenv(f'{org}.URL_REPOS')
        self.URL_ALERTS = os.getenv(f'{org}.URL_ALERTS')
        self.URL_PROPS = os.getenv(f'{org}.URL_PROPS')
        self.HEADERS = {'Authorization': f'token {self.GITHUB_TOKEN}'}

    def get_repositories(self):
        """Fetch all repositories in the given organization."""
        repos = []
        url = self.URL_REPOS.format(self.ORGANIZATION)
        while url:
            response = requests.get(url, headers=self.HEADERS)
            data = response.json()
            repos.extend([repo['name'] for repo in data])
            url = response.links.get('next', {}).get('url')  # Pagination
        return repos

    def get_vulnerabilities(self, repo):
        """Fetch critical and high vulnerabilities for a
        given repository with pagination."""
        url = self.URL_ALERTS.format(self.ORGANIZATION, repo)
        vulnerabilities = []

        while url:
            response = requests.get(url, headers=self.HEADERS)
            # Check if the response is successful (2xx status code)
            if response.status_code >= 200 and response.status_code < 300:
                # Add the current page's results to the vulnerabilities list
                vulnerabilities.extend(response.json())

                # Parse the "Link" header to find the next page URL,
                # if it exists
                links = response.headers.get('Link', '')
                next_url = None
                if links:
                    for link in links.split(','):
                        if 'rel="next"' in link:
                            next_url = link[link.find('<') + 1:link.find('>')]
                            break

                # Set the URL to the next page or None if there's no next page
                url = next_url
            else:
                return []

        # Filter vulnerabilities
        return [
            v for v in vulnerabilities
            if 'security_advisory' in v
            and v['security_advisory'].get('severity') in ['critical', 'high']
            and v['state'] == 'open'
        ]

    def get_repository_property(self, repo, property_name):
        """
        Fetch a custom property from a file within a GitHub repository.

        Args:
        property_name (str): The name of the property to retrieve from
        the file.

        Returns:
        str: The value of the property or 'not-found' if not present.
        """
        url = self.URL_PROPS.format(self.ORGANIZATION, repo)

        try:
            response = requests.get(url, headers=self.HEADERS)
            # Raises an HTTPError for bad responses
            response.raise_for_status()
            data = response.json()
            for item in data:
                if item["property_name"] == property_name:
                    return item["value"]
        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error: {e}")
            return 'not-found'
        except requests.exceptions.RequestException as e:
            print(f"Request Error: {e}")
            return 'not-found'
        except ValueError as e:
            print(f"JSON Error: {e}")
            return 'not-found'
        return "not-found"

    def get_base_url(self, url):
        # Parse the URL into components
        parsed_url = urllib.parse.urlparse(url)

        # Split the path on '/' and remove the last element
        path_parts = parsed_url.path.split('/')
        if len(path_parts) > 1:  # Ensure there is something to remove
            new_path = '/'.join(path_parts[:-1])
        else:
            new_path = ''

        # Construct the new URL without the last path element
        new_url = parsed_url._replace(path=new_path).geturl()
        return new_url

    def do_work(self):
        output_dir = os.getenv('OUTPUT_DIR', '.')
        os.makedirs(output_dir, exist_ok=True)
        datestamp = date.today().strftime('%Y-%m-%d')
        output_path = os.path.join(
            output_dir, f'{datestamp}-{self.LABEL}.csv')

        repos = self.get_repositories()
        with open(output_path, 'w') as f:
            f.write("Portfolio,Repository,Critical,High,URL\n")
            for repo in repos:
                vulnerabilities = self.get_vulnerabilities(repo)
                portfolio = self.get_repository_property(repo, 'Portfolio')
                if vulnerabilities:
                    url = ""
                    critical = 0
                    high = 0
                    for v in vulnerabilities:
                        if url == "":
                            url = self.get_base_url(v['html_url'])

                        severity = v['security_advisory'].get('severity')
                        if severity == 'critical':
                            critical = critical + 1
                        if severity == 'high':
                            high = high + 1

                    f.write(
                        f"{portfolio},{repo},{critical},{high},{url}\n")
        print(f"Wrote {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Report dependabot vulnerabilities")
    # This flag will be False by default,
    #  and True if '--flag' is provided on the command line
    parser.add_argument('--huit',
                        action='store_true',
                        help='If set, inspect HUIT Github; else github.com')

    args = parser.parse_args()

    if args.huit:
        org = "LTS"
        label = "huit"
    else:
        org = "harvard-lts"
        label = "lts"
    finder = DependabotFinder(org, label)
    finder.do_work()


if __name__ == "__main__":
    main()
