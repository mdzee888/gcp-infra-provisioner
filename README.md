# gcp-infra-provisioner
This code automates the creation of GCP infrastructure by setting up service accounts, BigQuery datasets, and Cloud Storage buckets with proper IAM permissions. It copies table schemas from source datasets to target datasets while preserving partitioning and clustering configurations for data pipeline workflows.



# GCP Infrastructure Provisioner

**Automates GCP infrastructure creation by setting up service accounts, BigQuery datasets, and Cloud Storage buckets with proper IAM permissions. Copies table schemas from source datasets while preserving partitioning and clustering configurations for data pipeline workflows.**

## 🚀 Features

- **Service Account Management**: Automated creation with proper naming and permissions
- **BigQuery Dataset Operations**: Schema replication with partition/cluster preservation  
- **Cloud Storage Integration**: Bucket creation with optimized IAM configurations
- **Permission Management**: Granular access control at project, dataset, and bucket levels
- **Idempotent Operations**: Safe to re-run without conflicts

## 📋 Prerequisites

- Google Cloud Project with enabled APIs:
  - BigQuery API
  - Cloud Storage API  
  - IAM Service Account Credentials API
  - Cloud Resource Manager API
- Service account key file with administrative permissions
- Python 3.7+

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/your-username/gcp-infra-provisioner.git
cd gcp-infra-provisioner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up your service account key file and update the path in the script.

## 📖 Usage

### Basic Configuration

```python
# Update these variables in the main() function
source_dataset_id = "your_source_dataset"
target_dataset_id = "your_target_dataset" 
KEY_FILE_PATH = "path/to/your-service-account-key.json"
```

### Run the Script

```bash
python gcp_infra_setup.py
```

### What It Creates

1. **Service Account**: Named after your target dataset
2. **BigQuery Datasets**: 
   - Main dataset: `{target_dataset_id}`
   - Temp dataset: `{target_dataset_id}_temp`
3. **Cloud Storage Bucket**: Named `{target_dataset_id}`
4. **IAM Permissions**:
   - Dataset OWNER access
   - BigQuery Job User role
   - Vertex AI User role
   - Storage bucket permissions

## 🛠️ Core Functions

| Function | Purpose |
|----------|---------|
| `create_service_account()` | Creates service account with existence check |
| `copy_missing_table_schemas()` | Replicates table structures with configurations |
| `assign_dataset_role()` | Grants dataset-level permissions |
| `create_bucket()` | Creates GCS bucket with location settings |
| `grant_iam_roles_with_key_file()` | Assigns project-level IAM roles |

## 📁 Project Structure

```
gcp-infra-provisioner/
├── gcp_infra_setup.py      # Main automation script
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── examples/
    └── service-account-key-template.json
```

## ⚙️ Configuration Options

- **Default Location**: `us-central1`
- **Dataset Access Level**: `OWNER`
- **Storage Roles**: Legacy Bucket Owner + Object User
- **Compute Permissions**: BigQuery Job User + Vertex AI User

## 🔐 Security Features

- Service account-based authentication
- Resource-level access controls
- Least-privilege permission model
- Secure credential handling

## 📝 Logging

The script provides detailed console output including:
- ✅ Successful resource creation
- ⚠️ Existing resource detection  
- ❌ Error conditions with guidance
- 📊 Permission assignment confirmations

## 🤝 Use Cases

- **Data Pipeline Bootstrap**: Quick environment setup for data workflows
- **Multi-tenant Architecture**: Isolated resource creation per client
- **Development Environments**: Rapid testing infrastructure provisioning
- **Schema Migration**: Cross-environment data structure replication

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For issues and questions:
1. Check existing [Issues](https://github.com/your-username/gcp-infra-provisioner/issues)
2. Create a new issue with detailed description
3. Include relevant log outputs and configuration details

---

**Note**: Ensure your service account key has sufficient permissions for resource creation and IAM management before running the script.
