# --- Overall Code Functionality ---
# This script implements a data pipeline to inspect a large CSV file stored in Google Cloud Storage (GCS)
# for sensitive data using Google Cloud Data Loss Prevention (DLP).
# The findings from the DLP inspection are stored in BigQuery.
# The pipeline is designed to handle large files by splitting them into manageable chunks,
# processing each chunk individually, and then merging the results.
# It's intended to be run in an environment like a Google Cloud Run Job,
# where configurations are passed via environment variables.

# --- Approach ---
# The script follows these main steps:
# 1. Configuration: Fetches necessary parameters (GCS paths, DLP project, BigQuery details, etc.)
#    from environment variables.
# 2. Initialization: Initializes clients for GCS, DLP, and BigQuery services.
# 3. File Chunking: Splits the large input CSV file from GCS into smaller temporary chunk files
#    also stored in GCS. This is done by downloading byte ranges and re-uploading them as new blobs.
# 4. DLP Inspection: For each chunk, it triggers a DLP inspection job.
#    - The DLP job uses a pre-defined inspection template to identify sensitive data.
#    - Findings for each chunk are saved to a separate table in BigQuery.
#    - The script polls the DLP service until each job completes or fails.
# 5. Result Merging: After all chunks are processed, the individual BigQuery tables containing
#    DLP findings are merged into a single consolidated BigQuery table.
# 6. Cleanup: Deletes the temporary chunk files created in GCS.
# 7. Logging: Basic logging messages are printed to stdout to track the process.
# 8. Error Handling: Includes try-except blocks to catch and log errors, and a finally block
#    for cleanup operations.

import os
import uuid # For generating unique identifiers for temporary resources
import math # For calculations like number of chunks
import time # For polling DLP job status
import logging # For structured logging
from google.cloud import storage # Client library for Google Cloud Storage
from google.cloud import dlp_v2 # Client library for Google Cloud Data Loss Prevention
from google.cloud import bigquery # Client library for Google Cloud BigQuery

# --- Logging Configuration ---
# Configure basic logging. This will make log messages include timestamp, level, and the message.
# In a Cloud Run environment, these logs will automatically be sent to Cloud Logging.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- Configuration (Fetched from Environment Variables in Cloud Run Job) ---
# These variables define the operational parameters for the script.
# They are expected to be set in the execution environment (e.g., Cloud Run Job).
# Default values are provided for some variables for local testing or fallback.
GCS_BUCKET_NAME        = os.environ.get('GCS_BUCKET_NAME')        or "test_deidentification" # Name of the GCS bucket containing the input file and for temporary chunks.
GCS_INPUT_CSV_PATH     = os.environ.get('GCS_INPUT_CSV_PATH')     or "test_deidentification/PatientNote20241001_20241031.csv" # Full path (prefix + filename) of the input CSV file in GCS.
CHUNK_SIZE_BYTES       = int(os.environ.get('CHUNK_SIZE_MB', 60)) * 1024 * 1024  # Desired size of each chunk in bytes. Default is 60MB.
DLP_PROJECT_ID         = os.environ.get('DLP_PROJECT_ID')         or "gcp-playground1-uw1" # Google Cloud Project ID where DLP jobs will run.
DLP_INSPECT_TEMPLATE   = os.environ.get('DLP_INSPECT_TEMPLATE')   or "projects/test-deidentification/locations/global/inspectTemplates/test-deidentification-template" # Full resource name of the DLP inspect template to use.
BIGQUERY_PROJECT_ID    = os.environ.get('BIGQUERY_PROJECT_ID')    or "gcp-playground1-uw1" # Google Cloud Project ID for BigQuery operations.
BIGQUERY_DATASET_ID    = os.environ.get('BIGQUERY_DATASET_ID')    or "23123" # BigQuery Dataset ID where DLP findings tables will be created.
BIGQUERY_TABLE_ID_PREFIX = os.environ.get('BIGQUERY_TABLE_ID_PREFIX', 'dlp_findings_chunk_') # Prefix for BigQuery tables created for each chunk's findings.
MERGED_BIGQUERY_TABLE_ID = os.environ.get('MERGED_BIGQUERY_TABLE_ID', 'merged_dlp_findings') # Name of the final BigQuery table after merging chunk findings.
TEMP_GCS_CHUNK_PREFIX    = os.environ.get('TEMP_GCS_CHUNK_PREFIX', 'temp_chunks/')  # GCS prefix within the bucket for storing temporary chunk files.


# --- Initialize Clients ---
# These clients are used to interact with Google Cloud services.
storage_client = storage.Client() # Client for interacting with Google Cloud Storage.
dlp_client = dlp_v2.DlpServiceClient() # Client for interacting with Google Cloud DLP.
bigquery_client = bigquery.Client(project=BIGQUERY_PROJECT_ID) # Client for interacting with BigQuery, configured for the specified project.

def log_message(message):
    """Helper function for logging informational messages."""
    # This function is now a wrapper around logging.info.
    # The "[PROCESS]" prefix is removed as the logger format already includes levelname.
    logging.info(message)

# --- Core Script Functions ---

def split_gcs_file_into_chunks(bucket_name, input_blob_name, chunk_size_bytes, temp_chunk_prefix):
    """
    Splits a large GCS file into smaller temporary chunk files in GCS.
    Returns a list of GCS URIs for the created chunks.

    Args:
        bucket_name (str): The name of the GCS bucket.
        input_blob_name (str): The full path/name of the source blob in GCS.
        chunk_size_bytes (int): The desired maximum size for each chunk in bytes.
        temp_chunk_prefix (str): The GCS prefix where temporary chunk files will be stored.

    Returns:
        list: A list of GCS URIs (e.g., "gs://bucket/path/to/chunk.csv") for the created chunks.
              Returns an empty list if the source file is empty or an error occurs.
    """
    log_message(f"Starting to chunk GCS file gs://{bucket_name}/{input_blob_name} into {chunk_size_bytes / (1024*1024)}MB chunks.")
    bucket = storage_client.bucket(bucket_name) # Get a GCS bucket object.
    source_blob = bucket.blob(input_blob_name) # Get a GCS blob object for the input file.

    try:
        source_blob.reload() # Fetch blob metadata, including its size.
    except Exception as e:
        logging.error(f"Error accessing source blob gs://{bucket_name}/{input_blob_name}: {e}", exc_info=True)
        raise # Re-raise the exception to be handled by the main pipeline.

    file_size = source_blob.size # Get the size of the source file in bytes.
    if not file_size:
        logging.warning(f"File gs://{bucket_name}/{input_blob_name} is empty or size could not be determined.")
        return [] # Return an empty list if the file is empty.

    # Calculate the number of chunks needed. math.ceil ensures the last chunk captures any remainder.
    num_chunks = math.ceil(file_size / chunk_size_bytes)
    log_message(f"Total size: {file_size} bytes. Number of chunks: {num_chunks}")
    chunk_gcs_uris = [] # List to store the GCS URIs of the created chunks.
    job_id_suffix = uuid.uuid4().hex[:8] # Generate a short unique suffix for chunk filenames to avoid collisions.

    bytes_processed = 0 # Keep track of bytes processed, mainly for logging/verification.
    for i in range(num_chunks):
        # Construct the name for the temporary chunk blob.
        # Ensures chunks from different runs or parallel processes have unique names if temp_chunk_prefix is shared.
        chunk_blob_name = f"{temp_chunk_prefix}chunk_{i+1}_of_{num_chunks}_{job_id_suffix}.csv"
        destination_blob = bucket.blob(chunk_blob_name) # Create a blob object for the new chunk.
        
        # Define the byte range for the current chunk.
        start_byte = i * chunk_size_bytes
        # end_byte is the minimum of (next chunk's start - 1) or (file_size - 1).
        end_byte = min(((i + 1) * chunk_size_bytes) - 1 , file_size - 1)
        current_chunk_size = end_byte - start_byte + 1

        log_message(f"Creating chunk {i+1}: {chunk_blob_name} (bytes {start_byte}-{end_byte})")

        # Download the byte range of the current chunk from the source blob.
        # This operation reads the specified part of the file into memory.
        # For very large chunks that might exceed instance memory, a streaming approach
        # or GCS compose/rewrite operations (if applicable to ranges) would be more robust.
        # However, `download_as_bytes` with `start` and `end` is suitable for moderately sized chunks.
        # WARNING: Ensure that the CHUNK_SIZE_BYTES is configured appropriately for the available memory
        # in your execution environment (e.g., Cloud Run instance). Processing very large chunks
        # directly in memory can lead to out-of-memory errors.
        chunk_data = source_blob.download_as_bytes(start=start_byte, end=end_byte)
        
        # Upload the downloaded chunk data to the new temporary blob in GCS.
        destination_blob.upload_from_string(chunk_data, content_type='text/csv')
        
        # Store the GCS URI of the newly created chunk.
        chunk_gcs_uris.append(f"gs://{bucket_name}/{chunk_blob_name}")
        log_message(f"Successfully created chunk: {chunk_gcs_uris[-1]}")
        bytes_processed += current_chunk_size

    log_message(f"Total bytes processed for chunking: {bytes_processed}. Should be {file_size}")
    return chunk_gcs_uris

def trigger_dlp_inspection(project_id, gcs_uri, inspect_template_name, bq_project_id, bq_dataset_id, bq_table_id):
    """
    Triggers a DLP inspection job for a GCS file and configures it to store results in BigQuery.
    It then polls the DLP job until completion.

    Args:
        project_id (str): The GCP Project ID for DLP.
        gcs_uri (str): The GCS URI of the file to inspect (e.g., "gs://bucket/file.csv").
        inspect_template_name (str): The full resource name of the DLP inspect template.
        bq_project_id (str): The GCP Project ID for the BigQuery destination.
        bq_dataset_id (str): The BigQuery Dataset ID for the destination table.
        bq_table_id (str): The BigQuery Table ID for storing findings.

    Returns:
        str: The BigQuery table ID where results were stored.

    Raises:
        Exception: If the DLP job fails, is canceled, or times out.
    """
    log_message(f"Triggering DLP for {gcs_uri}, output to BQ table {bq_project_id}:{bq_dataset_id}.{bq_table_id}")

    # Configure the storage location for DLP, pointing to the GCS file.
    storage_config = {
        "cloud_storage_options": {"file_set": {"url": gcs_uri}}
    }

    # Configure the DLP inspection job.
    # This includes the storage config, inspect template, and actions to take (save findings to BigQuery).
    inspect_job_config = {
        "storage_config": storage_config,
        "inspect_template_name": inspect_template_name, # Specifies the types of sensitive data to look for.
        "actions": [
            {
                "save_findings": { # Action to save the findings.
                    "output_config": {
                        "table": { # Specifies the BigQuery table destination.
                            "project_id": bq_project_id,
                            "dataset_id": bq_dataset_id,
                            "table_id": bq_table_id,
                        }
                    }
                }
            }
        ],
    }

    # Parent resource for creating the DLP job (project and location).
    # DLP jobs are regional; 'global' is used here to process data regardless of its GCS bucket region.
    # For data residency requirements, specify a region (e.g., 'us-west1').
    parent = f"projects/{project_id}/locations/global"

    try:
        # Create the DLP job.
        response = dlp_client.create_dlp_job(
            parent=parent, inspect_job=inspect_job_config
        )
        log_message(f"DLP Job created: {response.name}. Waiting for completion...")
        
        # --- Polling for DLP Job Completion ---
        # This is a basic polling mechanism. For production, consider using Pub/Sub notifications
        # for a more event-driven and efficient approach.
        # Using Pub/Sub is strongly recommended for production workloads to avoid long-running polling tasks
        # and to handle responses asynchronously and more reliably.
        job_done = False
        max_tries = 60 # Maximum number of polling attempts.
        tries = 0
        poll_interval_seconds = 30 # Time to wait between polls.

        while not job_done and tries < max_tries:
            time.sleep(poll_interval_seconds) # Wait before checking the job status again.
            job = dlp_client.get_dlp_job(name=response.name) # Get the current status of the DLP job.
            
            if job.state == dlp_v2.DlpJob.JobState.DONE:
                job_done = True
                logging.info(f"DLP Job {response.name} completed.")
            elif job.state in [dlp_v2.DlpJob.JobState.FAILED, dlp_v2.DlpJob.JobState.CANCELED]:
                error_message = f"DLP Job {response.name} failed or was canceled. State: {job.state}"
                if job.errors:
                    for error_detail in job.errors:
                        error_message += f" Details: {error_detail.details.message if error_detail.details else 'No details'}"
                logging.error(error_message)
                raise Exception(f"DLP Job {response.name} failed or canceled.")
            else:
                # Job is still pending or running.
                log_message(f"DLP Job {response.name} current state: {job.state}. Waiting...")
            tries += 1
        
        if not job_done:
            # Job did not complete within the allocated polling time.
            logging.error(f"DLP Job {response.name} timed out after {max_tries * poll_interval_seconds} seconds.")
            raise Exception(f"DLP Job {response.name} timed out.")

        return bq_table_id # Return the table ID upon successful completion.
    except Exception as e:
        logging.error(f"Error creating or monitoring DLP job for {gcs_uri}: {e}", exc_info=True)
        raise # Re-raise the exception.

def merge_bigquery_tables(source_project_id, source_dataset_id, table_id_prefix, num_tables, dest_table_id):
    """
    Merges multiple BigQuery tables (typically created from chunk processing) into a single destination table.
    The source tables are assumed to follow a naming pattern: prefix0, prefix1, ..., prefix(N-1).

    Args:
        source_project_id (str): GCP Project ID of the source and destination BigQuery tables.
        source_dataset_id (str): BigQuery Dataset ID of the source and destination tables.
        table_id_prefix (str): The prefix used for the individual chunk tables (e.g., "dlp_findings_chunk_").
        num_tables (int): The number of chunk tables to merge.
        dest_table_id (str): The ID of the destination table where merged data will be stored.
    """
    logging.info(f"Starting merge of tables with prefix '{table_id_prefix}' into '{source_project_id}.{source_dataset_id}.{dest_table_id}'.")
    
    if num_tables == 0:
        logging.info("No tables to merge.")
        return

    # Construct a list of SELECT statements, one for each source table.
    union_queries = []
    for i in range(num_tables):
        # Assumes table IDs are like: prefix0, prefix1, ...
        # The main loop provides table names like "prefix_0", "prefix_1", so this needs to match.
        # The current script generates table names like "BIGQUERY_TABLE_ID_PREFIX + str(i)"
        # e.g., "dlp_findings_chunk_0", "dlp_findings_chunk_1"
        table_name = f"{table_id_prefix}{i}"
        union_queries.append(f"SELECT * FROM `{source_project_id}.{source_dataset_id}.{table_name}`")

    # Construct the final SQL query using UNION ALL to combine all source tables.
    # CREATE OR REPLACE TABLE will overwrite the destination table if it exists.
    merge_sql = f"""
    CREATE OR REPLACE TABLE `{source_project_id}.{source_dataset_id}.{dest_table_id}` AS
    {' UNION ALL '.join(union_queries)}
    """
    logging.info(f"Executing BigQuery merge SQL: \n{merge_sql}")

    try:
        # Execute the merge query using the BigQuery client.
        query_job = bigquery_client.query(merge_sql)
        query_job.result() # Wait for the BigQuery job to complete.
        logging.info(f"Successfully merged tables into `{source_project_id}.{source_dataset_id}.{dest_table_id}`.")
    except Exception as e:
        logging.error(f"Error merging BigQuery tables: {e}", exc_info=True)
        raise # Re-raise the exception.

def cleanup_temp_chunks(bucket_name, temp_chunk_gcs_uris):
    """
    Deletes temporary chunk files from GCS.

    Args:
        bucket_name (str): The name of the GCS bucket containing the chunks.
        temp_chunk_gcs_uris (list): A list of GCS URIs of the temporary chunks to delete.
    """
    logging.info("Cleaning up temporary chunk files...")
    bucket = storage_client.bucket(bucket_name) # Get the GCS bucket object.
    for gcs_uri in temp_chunk_gcs_uris:
        # Extract the blob name from the GCS URI.
        blob_name = gcs_uri.replace(f"gs://{bucket_name}/", "")
        try:
            blob = bucket.blob(blob_name) # Get the blob object.
            blob.delete() # Delete the blob.
            logging.info(f"Deleted temp chunk: {gcs_uri}")
        except Exception as e:
            # Log a warning if a chunk cannot be deleted, but don't let it fail the whole process.
            logging.warning(f"Could not delete temp chunk {gcs_uri}: {e}", exc_info=True)

def main():
    """
    Main function to orchestrate the CSV de-identification pipeline.
    """
    logging.info("Starting CSV De-identification Pipeline.")

    # Validate that all required environment variables are set.
    required_env_vars = [
        GCS_BUCKET_NAME, GCS_INPUT_CSV_PATH, DLP_PROJECT_ID,
        DLP_INSPECT_TEMPLATE, BIGQUERY_PROJECT_ID, BIGQUERY_DATASET_ID
    ]
    if not all(required_env_vars):
        # Log an error and exit if any required configuration is missing.
        # This prevents the script from running with incomplete parameters.
        missing_vars_details = {
            "GCS_BUCKET_NAME": GCS_BUCKET_NAME, "GCS_INPUT_CSV_PATH": GCS_INPUT_CSV_PATH,
            "DLP_PROJECT_ID": DLP_PROJECT_ID, "DLP_INSPECT_TEMPLATE": DLP_INSPECT_TEMPLATE,
            "BIGQUERY_PROJECT_ID": BIGQUERY_PROJECT_ID, "BIGQUERY_DATASET_ID": BIGQUERY_DATASET_ID
        }
        logging.error(f"Missing one or more required environment variables. Current values: {missing_vars_details}")
        # In a Cloud Run Job, returning (or raising an unhandled exception) will mark the task as failed.
        return # Or raise ValueError(...)

    temp_chunk_uris = [] # To store URIs of temporary GCS chunk files.
    processed_table_ids = [] # To store BigQuery table IDs created for each chunk.

    try:
        log_message(f"Processing GCS file: gs://{GCS_BUCKET_NAME}/{GCS_INPUT_CSV_PATH}")
        
        # Step 1: Split the input CSV file into smaller chunks in GCS.
        # The GCS_INPUT_CSV_PATH is the full path within the bucket (e.g., 'folder/file.csv').
        temp_chunk_uris = split_gcs_file_into_chunks(
            GCS_BUCKET_NAME,
            GCS_INPUT_CSV_PATH,
            CHUNK_SIZE_BYTES,
            TEMP_GCS_CHUNK_PREFIX # e.g., 'temp_chunks/'
        )

        if not temp_chunk_uris:
            logging.warning("No chunks were created. This might be due to an empty input file or an error during chunking. Exiting.")
            return # Exit if no chunks were made.

        # Step 2-5: Trigger DLP inspection for each chunk and store findings in BigQuery.
        for i, chunk_gcs_uri in enumerate(temp_chunk_uris):
            # Generate a unique BigQuery table ID for the findings of the current chunk.
            # e.g., dlp_findings_chunk_0, dlp_findings_chunk_1
            bq_table_id_for_chunk = f"{BIGQUERY_TABLE_ID_PREFIX}{i}"
            log_message(f"Processing chunk {i+1}/{len(temp_chunk_uris)}: {chunk_gcs_uri}")
            
            # Trigger DLP inspection for the current chunk.
            # Results will be saved to the specified BigQuery table.
            trigger_dlp_inspection(
                DLP_PROJECT_ID,
                chunk_gcs_uri,
                DLP_INSPECT_TEMPLATE,
                BIGQUERY_PROJECT_ID,
                BIGQUERY_DATASET_ID,
                bq_table_id_for_chunk
            )
            processed_table_ids.append(bq_table_id_for_chunk) # Keep track of tables created.
        
        logging.info("All chunks processed by DLP.")

        # Step 6: Merge the individual BigQuery tables (containing DLP findings for each chunk)
        # into a single consolidated table.
        if processed_table_ids:
            merge_bigquery_tables(
                BIGQUERY_PROJECT_ID,
                BIGQUERY_DATASET_ID,
                BIGQUERY_TABLE_ID_PREFIX, # The base prefix for chunk tables.
                len(processed_table_ids), # The number of chunk tables to merge.
                MERGED_BIGQUERY_TABLE_ID # The name of the final merged table.
            )
        else:
            logging.info("No DLP findings tables to merge (e.g., if all chunks were empty or failed before BQ table creation).")

        logging.info("Pipeline completed successfully.")

    except Exception as e:
        # Catch any exceptions that occurred during the pipeline execution.
        logging.error(f"Pipeline failed: {e}", exc_info=True)
        # Re-raising the exception is important for Cloud Run Jobs,
        # as it signals that the job task failed.
        raise
    finally:
        # Step 7: Cleanup - Delete temporary GCS chunk files.
    # This block executes whether the pipeline succeeded or failed (if temp_chunk_uris is populated),
    # ensuring that temporary data does not persist unnecessarily.
        if temp_chunk_uris:
            cleanup_temp_chunks(GCS_BUCKET_NAME, temp_chunk_uris)
        logging.info("Exiting script.")


if __name__ == "__main__":
    # This is the entry point when the script is executed.
    # For Cloud Run Jobs, the job execution starts from here by invoking the main() function.
    # The script is designed to be run as a single task that processes the entire input file sequentially (chunk by chunk).
    #
    # Regarding Parallelism (Cloud Run Jobs):
    # If this script were to be used in a Cloud Run Job with task parallelism (CLOUD_RUN_TASK_COUNT > 1),
    # it would require modification. Currently, each task instance would attempt to process the *entire* input file,
    # leading to redundant work and potential conflicts (e.g., multiple tasks trying to create/delete the same GCS chunks
    # or write to the same BigQuery tables, though unique job_id_suffix for chunks helps mitigate some of this).
    #
    # To leverage Cloud Run Job task parallelism effectively, the script would need to:
    # 1. Identify the current task index (via CLOUD_RUN_TASK_INDEX environment variable).
    # 2. Determine the total number of tasks (via CLOUD_RUN_TASK_COUNT environment variable).
    # 3. Divide the workload (e.g., assign a specific subset of chunks to each task).
    #    This might involve:
    #    a. A preliminary step (or task 0) to list/create all chunks.
    #    b. Each task then processes only chunks where `chunk_index % CLOUD_RUN_TASK_COUNT == CLOUD_RUN_TASK_INDEX`.
    #    c. The merging of BigQuery tables and cleanup of chunks would likely need to be handled by a designated
    #       final task or managed carefully to avoid race conditions.
    main()
