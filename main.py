import requests
from dotenv import load_dotenv
import os
import argparse


# Load the environment variables from the .env file
load_dotenv()

# Get the API key and secret from environment variables
ENDOR_NAMESPACE = os.getenv("ENDOR_NAMESPACE")
API_URL = 'https://api.endorlabs.com/v1'

def get_token():
    api_key = os.getenv("API_KEY")
    api_secret = os.getenv("API_SECRET")
    url = f"{API_URL}/auth/api-key"
    payload = {
        "key": api_key,
        "secret": api_secret
    }
    headers = {
        "Content-Type": "application/json",
        "Request-Timeout": "60"
    }

    response = requests.post(url, json=payload, headers=headers, timeout=60)
    
    if response.status_code == 200:
        token = response.json().get('token')
        return token
    else:
        raise Exception(f"Failed to get token: {response.status_code}, {response.text}")

API_TOKEN = get_token()
HEADERS = {
    "User-Agent": "curl/7.68.0",
    "Accept": "*/*",
    "Authorization": f"Bearer {API_TOKEN}",
    "Request-Timeout": "600"  # Set the request timeout to 60 seconds
}

def get_secrets_findings():
    print("Fetching secrets findings...")
    query_data = {
        "tenant_meta": {
            "namespace": ""
        },
        "meta": {
            "name": "Get all secrets findings"
        },
        "spec": {
            "query_spec": {
                "kind": "Finding",
                "list_parameters": {
                    "filter": "spec.finding_categories contains 'FINDING_CATEGORY_SECRETS'",
                    "mask": "uuid,spec.finding_categories,meta.description,tenant_meta",
                    "traverse": True
                }
            }
        }
    }

    # Define the queries endpoint URL
    url = f"{API_URL}/namespaces/{ENDOR_NAMESPACE}/queries"
    print(f"POST Request to URL: {url}")
    print(f"Using filter: {query_data['spec']['query_spec']['list_parameters']['filter']}")

    secrets_findings = []
    next_page_id = None

    try:
        while True:
            if next_page_id:
                query_data["spec"]["query_spec"]["list_parameters"]["page_token"] = next_page_id

            # Make the POST request to the queries endpoint
            response = requests.post(url, headers=HEADERS, json=query_data, timeout=600)

            if response.status_code != 200:
                print(f"Failed to fetch secrets findings. Status Code: {response.status_code}, Response: {response.text}")
                return []

            # Parse the response data
            response_data = response.json()
            findings = response_data.get("spec", {}).get("query_response", {}).get("list", {}).get("objects", [])

            # Process the results
            for finding in findings:
                finding_uuid = finding.get("uuid")
                tenant_name = finding.get("tenant_meta", {}).get("namespace")
                finding_categories = finding.get("spec", {}).get("finding_categories", [])
                description = finding.get("meta", {}).get("description", "")
                secrets_findings.append(finding)
                print(f"UUID: {finding_uuid}, Description: {description}, Categories: {finding_categories}")

            # Check for next page
            next_page_id = response_data.get("spec", {}).get("query_response", {}).get("list", {}).get("response", {}).get("next_page_token")
            if not next_page_id:
                break

        return list(secrets_findings)

    except requests.RequestException as e:
        print(f"An error occurred while fetching secrets findings: {e}")
        return []


def delete_secrets_findings(secrets_findings):
    print("Attempting to delete secrets findings...")
    for finding in secrets_findings:
        finding_uuid = finding.get("uuid")
        tenant_name = finding.get("tenant_meta", {}).get("namespace")

        if finding_uuid and tenant_name:
            url = f"{API_URL}/namespaces/{tenant_name}/findings/{finding_uuid}"
            try:
                print(f"Deleting secrets finding with UUID: {finding_uuid}")
                response = requests.delete(url, headers=HEADERS, timeout=60)
                if response.status_code == 200:
                    print(f"Successfully deleted finding with UUID: {finding_uuid}")
                else:
                    print(f"Failed to delete finding with UUID: {finding_uuid}. Status Code: {response.status_code}, Response: {response.text}")
            except requests.RequestException as e:
                print(f"An error occurred while deleting finding with UUID: {finding_uuid}: {e}")
        else:
            print(f"Skipping finding: Missing UUID or tenant name. Finding details: {finding}")


def main():
    parser = argparse.ArgumentParser(description="Fetch and potentially delete secrets findings.")
    parser.add_argument('--no-dry-run', action='store_true', help="Fetch and delete all identified secrets findings.")
    args = parser.parse_args()

    secrets_findings = get_secrets_findings()
    print(f"Found {len(secrets_findings)} secrets findings.")

    if args.no_dry_run:
        delete_secrets_findings(secrets_findings)
    else:
        print("Dry run mode: No findings will be deleted. To delete all identified secrets findings, run the script with the --no-dry-run flag.")

if __name__ == "__main__":
    main()