#from google.cloud import iam
from google.cloud import bigquery
from google.oauth2 import service_account
import google.api_core.exceptions
from googleapiclient.discovery import build
from google.cloud.bigquery.dataset import Dataset
from google.cloud.bigquery.dataset import AccessEntry
from google.cloud.bigquery import DatasetReference
from googleapiclient.errors import HttpError
from google.cloud import storage
from google.api_core.exceptions import Conflict, NotFound
import os

import sys
import json


#1. Create Service Account
def create_service_account(credentials, project_id, service_account_name, display_name):
    """Creates a service account using the IAM API if it doesn't already exist."""
    service = build('iam', 'v1', credentials=credentials)
    print(f"Service client created successfully")
    
    # First check if the service account already exists
    sa_email = f"{service_account_name}@{project_id}.iam.gserviceaccount.com"
    sa_path = f"projects/{project_id}/serviceAccounts/{sa_email}"
    
    try:
        existing_sa = service.projects().serviceAccounts().get(
            name=sa_path
        ).execute()
        print(f"Service account already exists: {sa_email}")
        return existing_sa
    except HttpError as e:
        if e.resp.status == 404:
            print(f"Service account does not exist, will create new one: {sa_email}")
            # This is expected - continue with creation
        else:
            print(f"Error checking for existing service account: {e}")
            raise
    except Exception as e:
        print(f"Unexpected error checking for service account: {e}")
        raise
    
    # Create the service account
    print(f"Creating new service account: {sa_email}")
    
    try:
        request = service.projects().serviceAccounts().create(
            name=f"projects/{project_id}",
            body={
                'accountId': service_account_name,
                'serviceAccount': {
                    'displayName': display_name,
                    'description': 'BigQuery Admin for testds dataset'
                }
            }
        )
        response = request.execute()
        print(f"Successfully created new service account: {response['email']}")
        return response
    except HttpError as e:
        if "Service account already exists" in str(e):
            print(f"Service account was created by another process: {sa_email}")
            return service.projects().serviceAccounts().get(
                name=sa_path
            ).execute()
        print(f"Error creating service account: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error creating service account: {e}")
        raise

from google.cloud import bigquery
from google.oauth2 import service_account

def copy_missing_table_schemas(
    service_account_path: str,
    project_id: str,
    source_dataset_id: str,
    target_dataset_id: str,
    dataset_location: str = "us-central1"
):
    # Authenticate using the service account key file
    credentials = service_account.Credentials.from_service_account_file(service_account_path)
    client = bigquery.Client(credentials=credentials, project=project_id)

    # Define fully qualified dataset references
    source_dataset_ref = f"{project_id}.{source_dataset_id}"
    target_dataset_ref = f"{project_id}.{target_dataset_id}"

    # Ensure the target dataset exists
    try:
        client.get_dataset(target_dataset_ref)
        print(f"Target dataset '{target_dataset_ref}' already exists.")
    except Exception:
        # Create target dataset
        dataset = bigquery.Dataset(target_dataset_ref)
        dataset.location = dataset_location
        client.create_dataset(dataset)
        print(f"Created target dataset '{target_dataset_ref}' in location '{dataset_location}'.")

    # Get existing tables in target dataset
    target_tables = {table.table_id for table in client.list_tables(target_dataset_ref)}

    # Get all tables from source dataset
    source_tables = list(client.list_tables(source_dataset_ref))

    for table in source_tables:
        table_id = table.table_id
        if table_id in target_tables:
            print(f"Table '{table_id}' already exists in '{target_dataset_id}', skipping.")
            continue

        source_table_full_id = f"{project_id}.{source_dataset_id}.{table_id}"
        target_table_full_id = f"{project_id}.{target_dataset_id}.{table_id}"

        # Get source table schema
        source_table = client.get_table(source_table_full_id)

        # Create new table with same schema, partitioning, and clustering
        new_table = bigquery.Table(target_table_full_id, schema=source_table.schema)
        new_table.time_partitioning = source_table.time_partitioning
        new_table.clustering_fields = source_table.clustering_fields
        new_table.range_partitioning = source_table.range_partitioning

        try:
            client.create_table(new_table)
            print(f"Created table: {target_table_full_id}")
        except Exception as e:
            print(f"Failed to create table '{target_table_full_id}': {e}")


########

def assign_dataset_role(credentials, project_id, dataset_id, service_account_email):
    """Assigns BigQuery dataset permissions using dataset access controls."""
    try:
        client = bigquery.Client(project=project_id, credentials=credentials)
        
        # Get the dataset reference
        dataset = client.get_dataset(f"{project_id}.{dataset_id}")
        
        # Remove access entries. Prevent inherited policies.
        #dataset.access_entries = []

        # Add the service account as a dataset viewer (minimum required)
        entries = list(dataset.access_entries)
        entries.append(
            bigquery.AccessEntry(
                role="OWNER",  # Can be "READER", "WRITER", or "OWNER"
                entity_type="userByEmail",
                entity_id=service_account_email
            )
        )
        dataset.access_entries = entries
        
        # Update the dataset
        client.update_dataset(dataset, ["access_entries"])
        
        print(f"✅ Granted WRITER access to {service_account_email} for dataset {dataset_id}")
    except Exception as e:
        print(f"❌ Error assigning dataset role: {e}")
        sys.exit(1)

#Load the credentials for the account used to perform all the operations
def load_credentials(key_file_path):
    """Load service account credentials from key file."""
    try:
        credentials = service_account.Credentials.from_service_account_file(
            key_file_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        return credentials
    except Exception as e:
        print(f"Error loading credentials: {e}")
        raise

#### Create Bucket

def create_bucket(project_id, bucket_name, location="us-central1", credentials=None):
    """
    Creates a new GCS bucket only if it doesn't exist.
    
    Args:
        project_id: GCP project ID
        bucket_name: Globally unique bucket name
        location: Bucket location (default: 'us-central1')
        credentials: Optional credentials object
    
    Returns:
        The created or existing bucket object
    
    Raises:
        Exception: If bucket creation fails for reasons other than already existing
    """
    client = storage.Client(project=project_id, credentials=credentials)
    
    # First check if bucket exists
    try:
        bucket = client.get_bucket(bucket_name)
        print(f"✅ Bucket already exists: gs://{bucket_name}")
        return bucket
    except NotFound:
        pass  # Bucket doesn't exist - proceed to create
    except Exception as e:
        print(f"⚠️ Error checking bucket existence: {e}")
        raise
    
    # Create new bucket if it doesn't exist
    try:
        bucket = client.create_bucket(bucket_name, location=location)
        print(f"✅ Successfully created bucket: gs://{bucket_name} in {location}")
        return bucket
    except Conflict:
        print(f"⚠️ Bucket was created by another process: gs://{bucket_name}")
        return client.get_bucket(bucket_name)
    except Exception as e:
        print(f"❌ Failed to create bucket: {e}")
        raise

##

#### Assign Rights to Bucket
def add_roles_for_member(bucket_name, service_account_email, roles_to_add, credentials=None):
    """
    Efficiently assigns multiple IAM roles to a service account for a GCS bucket.

    This function performs a single read-modify-write cycle, making it safer
    and more efficient. It correctly adds the member to roles without
    overwriting existing members.
    """
    # Create the full member string
    member = f"serviceAccount:{service_account_email}"
    
    # Initialize the client
    client = storage.Client(credentials=credentials)
    bucket = client.get_bucket(bucket_name)

    # Get the policy once
    policy = bucket.get_iam_policy(requested_policy_version=3)

    # Add the service account to each role
    for role in roles_to_add:
        # The library's policy object lets you do this easily.
        # It handles creating the role binding if it doesn't exist,
        # or adding the member to the set if it does.
        policy.bindings.append({"role": role, "members": {member}})
        print(f"Prepared to assign {role} to {member} for gs://{bucket_name}")

    # Set the modified policy once
    bucket.set_iam_policy(policy)
    
    print(f"\nSuccessfully updated IAM policy for gs://{bucket_name}.")

###


### Assign multiple roles to a grant_iam_roles
def grant_iam_roles_with_key_file(
    project_id: str,
    target_service_account_email: str,
    roles: list[str],
    key_file_path: str
):
    """Grants IAM roles to a service account on a project using a JSON key file.

    This function authenticates using the provided service account key file and then
    grants the specified roles to the target service account.

    Args:
        project_id (str): The ID of the GCP project to modify.
        target_service_account_email (str): The email of the service account
                                            to grant permissions TO.
        roles (list[str]): A list of full IAM role names to grant
                           (e.g., 'roles/bigquery.jobUser').
        key_file_path (str): The file path to the JSON service account key for
                             authentication. The service account for this key MUST
                             have 'resourcemanager.projectIamAdmin' permission.
    """
    try:
        # Define the necessary API scope for resource manager
        SCOPES = ['https://www.googleapis.com/auth/cloud-platform']

        # --- Authentication using the JSON key file ---
        print(f"Authenticating using key file: {key_file_path}")
        if not os.path.exists(key_file_path):
            raise FileNotFoundError(f"Service account key file not found at: {key_file_path}")
            
        credentials = service_account.Credentials.from_service_account_file(
            key_file_path,
            scopes=SCOPES
        )

        # Build the Cloud Resource Manager API client
        service = build('cloudresourcemanager', 'v1', credentials=credentials)

        # The member identity must be prefixed for the target service account
        member = f"serviceAccount:{target_service_account_email}"

        print(f"Fetching current IAM policy for project '{project_id}'...")

        # 1. GET the current IAM policy
        policy_request = service.projects().getIamPolicy(resource=project_id, body={})
        policy = policy_request.execute()
        bindings = policy.get("bindings", [])

        # 2. MODIFY the policy in-memory
        for role in roles:
            role_binding = next((b for b in bindings if b["role"] == role), None)
            
            if role_binding:
                # Role binding exists, add member if not present
                if member not in role_binding["members"]:
                    role_binding["members"].append(member)
                    print(f"Added '{member}' to existing role '{role}'.")
                else:
                    print(f"'{member}' already has the role '{role}'. Skipping.")
            else:
                # Role binding does not exist, create a new one
                new_binding = {"role": role, "members": [member]}
                bindings.append(new_binding)
                print(f"Created new binding for role '{role}' with member '{member}'.")
        
        policy["bindings"] = bindings

        # 3. SET the new IAM policy
        print("Setting the updated IAM policy...")
        body = {"policy": policy}
        updated_policy = service.projects().setIamPolicy(resource=project_id, body=body).execute()

        print("\nSuccessfully updated IAM policy!")
        return updated_policy

    except FileNotFoundError as e:
        print(f"Error: {e}")
        return None
    except HttpError as error:
        print(f"An API error occurred: {error.reason}")
        print("Please ensure the service account for the key file has 'resourcemanager.projectIamAdmin' permissions on the project.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def infra_private_creation(source_dataset_id, target_dataset_id, KEY_FILE_PATH):
    KEY_FILE_PATH = KEY_FILE_PATH
    with open(KEY_FILE_PATH, "r") as f:
        key = json.load(f)


    #PROJECT_ID = "iamtestproject-456312"
    PROJECT_ID = key["project_id"]  # Use the project ID from the key file
    SERVICE_ACCOUNT_NAME = target_dataset_id  # No @ or domain
    DISPLAY_NAME = target_dataset_id
    DATASET_ID = target_dataset_id
    BUCKET_NAME = target_dataset_id
    source_dataset_id = source_dataset_id  # Source dataset to copy schemas from
    ADMIN_SERVICE_ACCOUNT = key["client_email"]  # Admin service account email from the key file
    

    
    try:
        # Load credentials
        credentials = load_credentials(KEY_FILE_PATH)
        print(f"Authenticated as: {credentials.service_account_email}")
        
        # Create service account
        sa = create_service_account(credentials, PROJECT_ID, SERVICE_ACCOUNT_NAME, DISPLAY_NAME)
        
        #Create DataSet
        # client= create_bigquery_dataset(PROJECT_ID, DATASET_ID, KEY_FILE_PATH, ADMIN_SERVICE_ACCOUNT)

        #  # Create AAinstance table in the new dataset
        # create_tables(client, PROJECT_ID, DATASET_ID)
        copy_missing_table_schemas(
            service_account_path=KEY_FILE_PATH,
            project_id=PROJECT_ID,
            source_dataset_id=source_dataset_id,
            target_dataset_id=DATASET_ID
        )
     
        # Assign BigQuery Admin role to the dataset
        assign_dataset_role(credentials, PROJECT_ID, DATASET_ID, sa['email'])

        ### for temporary use in langchain---------------------
        copy_missing_table_schemas(
            service_account_path=KEY_FILE_PATH,
            project_id=PROJECT_ID,
            source_dataset_id=f"{source_dataset_id}_temp",
            target_dataset_id=f"{DATASET_ID}_temp"
        )
        # Assign BigQuery Admin role to the dataset
        assign_dataset_role(credentials, PROJECT_ID, f"{DATASET_ID}_temp", sa['email'])
        # ----------------------------------------------------------------------------

        # Create GCS bucket
                #Create Bucket
        bucket = create_bucket(PROJECT_ID, BUCKET_NAME,"us-central1",credentials)
        
        #print(f"Bucket details: {bucket}")
        print(f"Account: {sa['email']}")        

        #Assign Rights to Bucket
        roles_to_assign = [
        "roles/storage.legacyBucketOwner",  # Legacy full control
        "roles/storage.objectUser"          # Object read access
        ]
        # Call the improved function
        add_roles_for_member(BUCKET_NAME, sa['email'], roles_to_assign, credentials)

        # The roles you want to grant to the target service account
        ROLES_TO_GRANT = [
            "roles/bigquery.jobUser",  # BigQuery Job User
            "roles/aiplatform.user"    # Vertex AI User
        ]
        grant_iam_roles_with_key_file(
                                        project_id=PROJECT_ID,
                                        target_service_account_email=sa['email'],
                                        roles=ROLES_TO_GRANT,
                                        key_file_path=KEY_FILE_PATH
                                    )

        print("Script completed successfully")
    except Exception as e:
        print(f"Script failed: {e}")


def main():
    
    # target_dataset_id= "alembic9898private"
    # source_dataset_id= "drreddy6563private" 
    ## Sharable
    # target_dataset_id= "alembic9898sharable"
    # source_dataset_id= "drreddy6563sharable" 
    KEY_FILE_PATH = "C:/Users/Admin/Desktop/main_reblue/agent script table create/InfraCreation/private-data-store-prod-resourcecreator.json"  # Private Project
    infra_private_creation(source_dataset_id, target_dataset_id, KEY_FILE_PATH)

if __name__ == "__main__":
    main()

