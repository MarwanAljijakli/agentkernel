"""Pure, reviewed action normalization contracts and built-in normalizers."""

from agentkernel.adapters.base import NormalizerManifest
from agentkernel.normalization.base import AdmittedOperation, PureActionNormalizer
from agentkernel.normalization.filesystem import (
    FILESYSTEM_WRITE_FILES_NORMALIZER_MANIFEST,
    FilesystemNormalizerConfig,
    FilesystemWriteFilesNormalizer,
    WriteFilesArguments,
)
from agentkernel.normalization.registry import NormalizerRegistry

__all__ = [
    "FILESYSTEM_WRITE_FILES_NORMALIZER_MANIFEST",
    "AdmittedOperation",
    "FilesystemNormalizerConfig",
    "FilesystemWriteFilesNormalizer",
    "NormalizerManifest",
    "NormalizerRegistry",
    "PureActionNormalizer",
    "WriteFilesArguments",
]
