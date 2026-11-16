from dataclasses import dataclass

MAX_PROOF_VULNERABILITIES = 5


@dataclass(frozen=True, order=True)
class AffectedAsset:
    asset_id: str
    host: str
    ip: str


@dataclass(frozen=True, order=True)
class AssetVulnerabilityProof:
    asset_id: str
    host: str
    vulnerability_id: str
    check_id: str
    status: str
    proof: str


@dataclass(frozen=True, order=True)
class Finding:
    hosts: tuple[str, ...]
    solution: str
    fix_details: str
    solution_id: str = ""
    proofs: tuple[AssetVulnerabilityProof, ...] = ()
    proof_note: str = ""
    vulnerability_count: int = 0
    affected_assets: tuple[AffectedAsset, ...] = ()


@dataclass(frozen=True)
class TransformStats:
    assets_seen: int
    findings_written: int
    assets_without_host: int
    vulnerability_ids_not_in_catalog: int
