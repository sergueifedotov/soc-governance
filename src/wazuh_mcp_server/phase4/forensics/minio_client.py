"""MinIO artifact storage for forensic case evidence.

Object layout in the ``forensic-evidence`` bucket:
    {incident_id}/{artifact_id}/{filename}

Usage::

    store = ArtifactStore("localhost:9000", "minioadmin", "minioadmin")
    meta  = store.upload("INC-2026-00001", "auth.log", b"...", "text/plain")
    url   = store.get_download_url(meta["object_name"])
    store.delete(meta["object_name"])
"""

from __future__ import annotations

import io
import logging
import uuid
from datetime import timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from minio import Minio          # type: ignore
    from minio.error import S3Error  # type: ignore
    _MINIO_AVAILABLE = True
except ImportError:                  # pragma: no cover
    _MINIO_AVAILABLE = False
    logger.warning("minio package not installed; ArtifactStore disabled")


FORENSIC_BUCKET = "forensic-evidence"


class ArtifactStore:
    """MinIO-backed evidence storage for forensic cases."""

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        secure: bool = False,
        bucket: str = FORENSIC_BUCKET,
    ) -> None:
        if not _MINIO_AVAILABLE:
            raise RuntimeError("minio package is not installed")
        self._client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
        self._bucket = bucket
        self._ensure_bucket()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_bucket(self) -> None:
        if not self._client.bucket_exists(self._bucket):
            self._client.make_bucket(self._bucket)
            logger.info("Created MinIO bucket: %s", self._bucket)

    def _object_name(self, incident_id: str, artifact_id: str, filename: str) -> str:
        return f"{incident_id}/{artifact_id}/{filename}"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def ping(self) -> bool:
        try:
            self._client.bucket_exists(self._bucket)
            return True
        except Exception:
            return False

    def upload(
        self,
        incident_id: str,
        filename: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict:
        """Upload artifact bytes; return artifact metadata dict.

        The returned dict contains ``artifact_id`` and ``object_name`` which
        are needed for download / delete operations.
        """
        artifact_id  = str(uuid.uuid4())
        object_name  = self._object_name(incident_id, artifact_id, filename)
        extra: Dict  = {}
        if metadata:
            extra["metadata"] = metadata

        self._client.put_object(
            bucket_name=self._bucket,
            object_name=object_name,
            data=io.BytesIO(data),
            length=len(data),
            content_type=content_type,
            **extra,
        )
        logger.info("Uploaded artifact %s (%d bytes)", object_name, len(data))
        return {
            "artifact_id": artifact_id,
            "object_name": object_name,
            "filename":    filename,
            "size_bytes":  len(data),
            "content_type": content_type,
            "incident_id": incident_id,
            "bucket":      self._bucket,
        }

    def download(self, object_name: str) -> bytes:
        """Download artifact bytes by full object_name."""
        response = self._client.get_object(self._bucket, object_name)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def get_download_url(self, object_name: str, expires_seconds: int = 3600) -> str:
        """Generate a presigned GET URL valid for ``expires_seconds``."""
        return self._client.presigned_get_object(
            self._bucket,
            object_name,
            expires=timedelta(seconds=expires_seconds),
        )

    def list_artifacts(self, incident_id: str) -> List[Dict]:
        """List all artifacts stored for an incident."""
        prefix  = f"{incident_id}/"
        objects = self._client.list_objects(self._bucket, prefix=prefix, recursive=True)
        results = []
        for obj in objects:
            parts = obj.object_name.split("/", 2)
            # parts = [incident_id, artifact_id, filename]
            artifact_id = parts[1] if len(parts) >= 3 else ""
            filename    = parts[2] if len(parts) >= 3 else obj.object_name
            results.append({
                "artifact_id":   artifact_id,
                "object_name":   obj.object_name,
                "filename":      filename,
                "size_bytes":    obj.size,
                "last_modified": obj.last_modified.isoformat() if obj.last_modified else None,
                "incident_id":   incident_id,
                "bucket":        self._bucket,
            })
        return results

    def delete(self, object_name: str) -> None:
        """Permanently delete an artifact object."""
        self._client.remove_object(self._bucket, object_name)
        logger.info("Deleted artifact %s", object_name)
