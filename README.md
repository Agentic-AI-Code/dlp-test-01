# Large CSV DLP Inspection Pipeline

## 1. Overview

This Python script (`dlp-code.py`) is designed to inspect large CSV files stored in Google Cloud Storage (GCS) for sensitive data using Google Cloud Data Loss Prevention (DLP). Findings from the DLP inspection are stored in Google BigQuery.

The script implements a chunking mechanism to handle large files efficiently. It splits the input CSV into smaller, manageable chunks, processes each chunk individually through DLP, and then merges the inspection results from all chunks into a consolidated BigQuery table.

This solution is intended to be run in serverless environments like Google Cloud Run Jobs, where configuration is primarily managed through environment variables.

## 2. Features

- **File Chunking:** Automatically splits large CSV files from GCS into smaller chunks before processing.
- **DLP Inspection per Chunk:** Triggers individual DLP inspection jobs for each chunk, allowing for parallelizable workloads (though the current script processes sequentially).
- **BigQuery Integration:** Stores detailed DLP findings in BigQuery tables. Each chunk's findings are initially saved to a separate table.
- **Result Merging:** Consolidates findings from all chunk-specific BigQuery tables into a single, final BigQuery table.
- **Automated Cleanup:** Deletes temporary chunk files from GCS after processing is complete, whether successful or not.

## 3. Prerequisites

- **Google Cloud Platform (GCP) Project:** A GCP project to host all resources.
- **Enabled APIs:**
    - Google Cloud Storage API
    - Google Cloud DLP API
    - Google BigQuery API
- **GCS Bucket:** A Google Cloud Storage bucket to store the input CSV file(s) and to temporarily store the generated chunks.
- **DLP Inspection Template:** A pre-configured DLP inspection template. You will need its full resource name (e.g., `projects/YOUR_PROJECT_ID/locations/YOUR_LOCATION/inspectTemplates/YOUR_TEMPLATE_ID`).
- **BigQuery Dataset:** An existing BigQuery dataset to store the DLP findings tables.
- **IAM Permissions:** The service account or identity running the script requires the following roles or equivalent permissions:
    - **On the GCS Bucket (or specific input/output paths):**
        - `roles/storage.objectViewer` (to read the input CSV)
        - `roles/storage.objectCreator` (to write temporary chunks)
        - `roles/storage.objectAdmin` (to delete temporary chunks)
    - **On the DLP Project (or more granularly on DLP resources):**
        - `roles/dlp.user` (to create and get DLP jobs)
    - **On the BigQuery Project and Dataset:**
        - `roles/bigquery.dataEditor` (to create tables and write data within the specified dataset)
        - `roles/bigquery.jobUser` (to run BigQuery jobs, e.g., for merging tables)
    - **On the DLP Inspect Template (if fine-grained access is configured):**
        - Permission to use the template (e.g., as part of `roles/dlp.user` or a custom role).

## 4. Environment Variables

The script uses the following environment variables for configuration:

| Variable Name                | Description                                                                 | Mandatory | Default Value (if not set)        | Example                                                                                   |
|------------------------------|-----------------------------------------------------------------------------|-----------|-----------------------------------|-------------------------------------------------------------------------------------------|
| `GCS_BUCKET_NAME`            | Name of the GCS bucket for input and temporary chunks.                      | Yes       | `test_deidentification`           | `my-company-data-bucket`                                                                  |
| `GCS_INPUT_CSV_PATH`         | Full path (prefix + filename) of the input CSV file in GCS.                 | Yes       | `test_deidentification/PatientNote20241001_20241031.csv` | `sensitive_data/large_dataset.csv`                                                        |
| `CHUNK_SIZE_MB`              | Desired size of each chunk in Megabytes (MB).                               | No        | `60`                              | `100`                                                                                     |
| `DLP_PROJECT_ID`             | Google Cloud Project ID where DLP jobs will run.                            | Yes       | `gcp-playground1-uw1`             | `my-dlp-project`                                                                          |
| `DLP_INSPECT_TEMPLATE`       | Full resource name of the DLP inspect template to use.                      | Yes       | `projects/test-deidentification/locations/global/inspectTemplates/test-deidentification-template` | `projects/my-dlp-project/locations/us-west1/inspectTemplates/my-csv-template`             |
| `BIGQUERY_PROJECT_ID`        | Google Cloud Project ID for BigQuery operations.                            | Yes       | `gcp-playground1-uw1`             | `my-bq-project`                                                                           |
| `BIGQUERY_DATASET_ID`        | BigQuery Dataset ID where DLP findings tables will be created.              | Yes       | `23123`                           | `dlp_results_dataset`                                                                     |
| `BIGQUERY_TABLE_ID_PREFIX`   | Prefix for BigQuery tables created for each chunk's findings.               | No        | `dlp_findings_chunk_`             | `temp_dlp_chunk_`                                                                         |
| `MERGED_BIGQUERY_TABLE_ID`   | Name of the final BigQuery table after merging chunk findings.                | No        | `merged_dlp_findings`             | `final_patient_notes_dlp_findings`                                                        |
| `TEMP_GCS_CHUNK_PREFIX`      | GCS prefix (folder path) within the bucket for storing temporary chunk files. | No        | `temp_chunks/`                    | `dlp_pipeline/temp_chunks/`                                                               |

*Note: `CHUNK_SIZE_BYTES` is derived in the script from `CHUNK_SIZE_MB`.*

## 5. Script Workflow

The script executes the following steps:

1.  **Configuration Loading:** Fetches parameters from environment variables.
2.  **Client Initialization:** Initializes clients for GCS, DLP, and BigQuery services.
3.  **Input File Chunking:** Splits the large input CSV file from GCS into smaller temporary chunk files, also stored in GCS.
4.  **DLP Inspection per Chunk:** For each chunk:
    *   Triggers a DLP inspection job using the specified inspection template.
    *   Configures the DLP job to save findings to a unique BigQuery table (e.g., `BIGQUERY_TABLE_ID_PREFIX` + chunk number).
5.  **Polling for DLP Job Completion:** Waits for each DLP job to complete by polling its status.
6.  **Result Merging:** After all chunks are processed, it merges the individual BigQuery tables (containing DLP findings for each chunk) into a single, consolidated BigQuery table (`MERGED_BIGQUERY_TABLE_ID`).
7.  **Cleanup:** Deletes the temporary chunk files created in GCS.

## 6. Execution

This script is designed to be run as a serverless job, for example, a Google Cloud Run Job.

To deploy and run:

1.  Containerize the Python script (`dlp-code.py`) along with its dependencies (e.g., `google-cloud-storage`, `google-cloud-dlp`, `google-cloud-bigquery`).
2.  Push the container image to a registry like Google Artifact Registry.
3.  Deploy the container as a Cloud Run Job, configuring all the necessary environment variables as described in Section 4.

**Conceptual `gcloud` command for deployment:**

```bash
gcloud run jobs deploy my-dlp-inspection-job \
  --image YOUR_REGION-docker.pkg.dev/YOUR_PROJECT_ID/YOUR_REPO/YOUR_IMAGE_NAME:TAG \
  --tasks 1 \
  --set-env-vars GCS_BUCKET_NAME="your-bucket",GCS_INPUT_CSV_PATH="path/to/your/file.csv" \
  --set-env-vars DLP_PROJECT_ID="your-dlp-project",DLP_INSPECT_TEMPLATE="projects/your-dlp-project/inspectTemplates/your-template" \
  --set-env-vars BIGQUERY_PROJECT_ID="your-bq-project",BIGQUERY_DATASET_ID="your_bq_dataset" \
  --set-env-vars MERGED_BIGQUERY_TABLE_ID="final_dlp_results" \
  --region YOUR_GCP_REGION \
  --service-account YOUR_SERVICE_ACCOUNT_EMAIL
```

Replace placeholders (like `YOUR_PROJECT_ID`, `YOUR_IMAGE_NAME`, etc.) with your specific values. Ensure the specified service account has the IAM permissions listed in Section 3.

## 7. Production Considerations

-   **DLP Job Notifications:** The script currently polls for DLP job completion. For production environments, it is highly recommended to use Pub/Sub notifications for a more event-driven, efficient, and reliable way to handle DLP job status updates. This avoids long-running polling tasks.
-   **Chunk Size and Memory:** The `CHUNK_SIZE_MB` parameter should be chosen carefully. The current script downloads each chunk's content into memory before re-uploading to GCS (for chunk creation) and potentially during DLP processing (depending on how the DLP client library handles GCS objects). Ensure the execution environment (e.g., Cloud Run Job instance) has sufficient memory allocated to handle the specified chunk size. For extremely large files or memory-constrained environments, explore GCS native compose operations or streaming approaches for chunking if feasible, to reduce memory footprint.
-   **Error Handling & Monitoring:** While the script includes basic logging and error handling, integrate with Google Cloud's operations suite (Cloud Logging for detailed logs, Cloud Monitoring for metrics, and Cloud Error Reporting for exceptions) for robust monitoring and alerting in production.
-   **IAM Granularity:** Adhere to the principle of least privilege. Grant only the necessary permissions to the service account running this script, scoped to the specific resources (e.g., specific GCS bucket, BigQuery dataset).
-   **Idempotency:** Consider the implications if the job is run multiple times on the same input. The `CREATE OR REPLACE TABLE` for the merged BigQuery table makes the final merge step idempotent. However, DLP job creation and chunk creation might generate duplicate data or resources if not managed carefully (e.g., by cleaning up previous run artifacts or ensuring unique job/chunk identifiers per execution). The current script uses a UUID suffix for chunk names to help avoid collisions.

## 8. To Do / Future Improvements

-   **Implement Pub/Sub for DLP Job Completion:** Replace polling with Pub/Sub notifications for asynchronous and more efficient DLP job monitoring.
-   **Optimize Chunking for Memory:** Investigate using GCS compose operations (if applicable for byte ranges) or streaming reads/writes to reduce the memory footprint during the file chunking process.
-   **Add Comprehensive Testing:** Implement thorough unit tests (using mocking frameworks like `unittest.mock` for GCP service interactions with GCS, DLP, and BigQuery) and integration tests to ensure ongoing reliability and facilitate easier modifications. This should cover file chunking logic, DLP job submissions, BigQuery interactions, and error handling scenarios.
-   **Parallel Chunk Processing:** Modify the script and deployment strategy (e.g., using Cloud Run Jobs with multiple tasks, where each task processes a subset of chunks) to enable parallel processing of chunks for faster throughput on very large files.
-   **Dead Letter Queue for Failed Chunks:** Implement a mechanism to handle chunks that consistently fail DLP inspection, perhaps by moving them to a separate GCS location for investigation.
-   **Configuration for Retries:** Make retry logic for DLP jobs and GCS operations more configurable (e.g., number of retries, backoff strategy).
