"""Trusted effect-adapter contracts and reference implementations."""

from agentkernel.adapters.base import (
    AdapterManifest,
    CommitContext,
    EffectAdapter,
    EffectPlan,
    OperationManifest,
    ReadOnlyContext,
    ReconcileReport,
    ReconcileStatus,
    RecoveryContext,
    StageContext,
    StagedEffect,
    StagedReceipt,
    VerifyContext,
)
from agentkernel.adapters.registry import AdapterRegistry

__all__ = [
    "AdapterManifest",
    "AdapterRegistry",
    "CommitContext",
    "EffectAdapter",
    "EffectPlan",
    "OperationManifest",
    "ReadOnlyContext",
    "ReconcileReport",
    "ReconcileStatus",
    "RecoveryContext",
    "StageContext",
    "StagedEffect",
    "StagedReceipt",
    "VerifyContext",
]
