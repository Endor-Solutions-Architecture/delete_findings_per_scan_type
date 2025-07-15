## Delete Secrets Findings
This script identifies and deletes findings that are categorized as secrets. It operates on the Endor Labs namespace (and its child namespaces if `traverse` is enabled in API calls) specified in the `.env` file.

The script uses the following filter to identify secrets findings:
`spec.finding_categories contains 'FINDING_CATEGORY_SECRETS'`

This means findings with the category "FINDING_CATEGORY_SECRETS" will be targeted for deletion.

## SETUP

Step 1: Create a `.env` file in the same directory as the script and add the following, replacing the placeholders with your actual credentials and namespace. Ensure the API key has permissions to read and delete package versions.

```
API_KEY=<your_api_key_here>
API_SECRET=<your_api_secret_here>
ENDOR_NAMESPACE=<your_namespace>
```

Step 2: Set up a Python virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\\Scripts\\activate`
pip install -r requirements.txt
```

Step 3: Run the script

*   **Dry Run (default behavior):** To see which secrets findings would be deleted without actually deleting them:
    ```bash
    python3 main.py
    ```
    The script will list the secrets findings found and state that it's in dry-run mode.

*   **Actual Deletion:** To delete all identified secrets findings:
    ```bash
    python3 main.py --no-dry-run
    ```
    **Caution:** This will permanently delete findings. Ensure you have reviewed the output of a dry run first.

## No Warranty

Please be advised that this software is provided on an "as is" basis, without warranty of any kind, express or implied. The authors and contributors make no representations or warranties of any kind concerning the safety, suitability, lack of viruses, inaccuracies, typographical errors, or other harmful components of this software. There are inherent dangers in the use of any software, and you are solely responsible for determining whether this software is compatible with your equipment and other software installed on your equipment.

By using this software, you acknowledge that you have read this disclaimer, understand it, and agree to be bound by its terms and conditions. You also agree that the authors and contributors of this software are not liable for any damages you may suffer as a result of using, modifying, or distributing this software.
