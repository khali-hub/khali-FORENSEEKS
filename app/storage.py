"""Evidence file storage: local disk (development) or S3-compatible (cloud)."""
import hashlib
import shutil
from functools import lru_cache

from .config import settings

CHUNK = 1024 * 1024


class TooLarge(Exception):
    pass


class HashingReader:
    """Wraps an upload so the SHA-256 and size are computed while the file is stored."""

    def __init__(self, fileobj, max_bytes: int):
        self._f, self._max, self._h, self.size = fileobj, max_bytes, hashlib.sha256(), 0

    def read(self, n=-1):
        chunk = self._f.read(n)
        self.size += len(chunk)
        if self.size > self._max:
            raise TooLarge()
        self._h.update(chunk)
        return chunk

    @property
    def sha256(self) -> str:
        return self._h.hexdigest()


class _Base:
    def sha256(self, key: str) -> str:
        h = hashlib.sha256()
        for chunk in self.stream(key):
            h.update(chunk)
        return h.hexdigest()


class LocalStorage(_Base):
    def __init__(self, root):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key):
        p = (self.root / key).resolve()
        if not p.is_relative_to(self.root):
            raise ValueError("Invalid storage key")
        return p

    def save(self, key, reader):
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(p, "xb") as out:
                shutil.copyfileobj(reader, out, CHUNK)
        except Exception:
            p.unlink(missing_ok=True)
            raise

    def stream(self, key):
        with open(self._path(key), "rb") as f:
            while chunk := f.read(CHUNK):
                yield chunk

    def delete(self, key):  # used only to clean up a failed registration
        self._path(key).unlink(missing_ok=True)


class S3Storage(_Base):
    def __init__(self):
        import boto3
        kwargs = {}
        if settings.s3_endpoint:
            kwargs["endpoint_url"] = settings.s3_endpoint
        if settings.s3_region:
            kwargs["region_name"] = settings.s3_region
        self.client = boto3.client("s3", **kwargs)
        self.bucket = settings.s3_bucket

    def save(self, key, reader):
        extra = {"ServerSideEncryption": "AES256"} if settings.s3_sse else None
        self.client.upload_fileobj(reader, self.bucket, key, ExtraArgs=extra)

    def stream(self, key):
        body = self.client.get_object(Bucket=self.bucket, Key=key)["Body"]
        yield from body.iter_chunks(CHUNK)

    def delete(self, key):
        self.client.delete_object(Bucket=self.bucket, Key=key)


@lru_cache
def get_storage():
    return S3Storage() if settings.storage_backend == "s3" else LocalStorage(settings.evidence_dir)
