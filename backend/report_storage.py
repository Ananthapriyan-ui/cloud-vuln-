"""
Supabase Storage Service for CloudVuln Reports
Handles uploading generated HTML & CSV reports to Supabase Storage and downloading them.
Never exposes service role key to frontend.
"""
import os
import logging
from typing import Optional, Tuple
import config

logger = logging.getLogger("SupabaseStorage")

_supabase_client = None

def get_supabase_client():
    """Initializes and caches the Supabase client using server-side service credentials."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    supabase_url = (config.settings.SUPABASE_URL or os.getenv("SUPABASE_URL") or "").strip()
    service_key = (config.settings.SUPABASE_SERVICE_ROLE_KEY or os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip()

    if not supabase_url or not service_key:
        logger.debug("Supabase URL or Service Role Key not configured; Supabase Storage integration disabled.")
        return None

    try:
        from supabase import create_client
        _supabase_client = create_client(supabase_url, service_key)
        return _supabase_client
    except Exception as e:
        logger.error(f"Failed to initialize Supabase Storage client: {e}")
        return None


def ensure_bucket_exists(bucket_name: Optional[str] = None):
    """Checks if the reports bucket exists, creating it if necessary."""
    bucket = bucket_name or config.settings.SUPABASE_STORAGE_BUCKET or "reports"
    client = get_supabase_client()
    if not client:
        return False
    try:
        buckets = client.storage.list_buckets()
        existing = [b.name for b in buckets] if buckets else []
        if bucket not in existing:
            client.storage.create_bucket(bucket, options={"public": False})
            logger.info(f"Created Supabase Storage bucket: {bucket}")
        return True
    except Exception as e:
        logger.warning(f"Could not verify/create bucket '{bucket}': {e}")
        return False


def upload_report_file(
    file_bytes: bytes,
    file_name: str,
    content_type: str = "text/html",
    bucket_name: Optional[str] = None,
) -> Optional[str]:
    """
    Uploads a report file (HTML or CSV) to Supabase Storage.
    Returns the storage path upon success, or None on failure.
    """
    client = get_supabase_client()
    if not client:
        return None

    bucket = bucket_name or config.settings.SUPABASE_STORAGE_BUCKET or "reports"
    storage_path = f"reports/{file_name}"

    try:
        # Upsert file into Supabase Storage bucket
        client.storage.from_(bucket).upload(
            path=storage_path,
            file=file_bytes,
            file_options={"content-type": content_type, "upsert": "true"},
        )
        logger.info(f"Report uploaded to Supabase Storage: {bucket}/{storage_path}")
        return storage_path
    except Exception as e:
        logger.error(f"Failed to upload report to Supabase Storage: {e}")
        return None


def download_report_file(
    storage_path: str,
    bucket_name: Optional[str] = None,
) -> Optional[bytes]:
    """
    Downloads a report file from Supabase Storage by its path.
    Returns file bytes, or None on failure.
    """
    client = get_supabase_client()
    if not client:
        return None

    bucket = bucket_name or config.settings.SUPABASE_STORAGE_BUCKET or "reports"
    try:
        data = client.storage.from_(bucket).download(storage_path)
        return data
    except Exception as e:
        logger.error(f"Failed to download report from Supabase Storage: {e}")
        return None
