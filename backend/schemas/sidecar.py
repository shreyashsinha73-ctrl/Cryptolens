from typing import Optional, Literal, Union
from pydantic import BaseModel, ConfigDict, Field


class IPsecSidecarConfig(BaseModel):
    """
    Strict schema for operator-supplied IPsec configuration sidecar.
    Supplies parameters that cannot be passively observed on the wire
    (e.g., encrypted IKEv2 Child SA transforms, PFS, SA lifetime).
    """
    model_config = ConfigDict(extra="forbid")

    ike_version: Optional[str] = Field(default=None, description="IKE protocol version (e.g. IKEv2, IKEv1)")
    encryption_algorithm: Optional[str] = Field(default=None, description="Child SA ESP symmetric cipher (e.g. AES-256-GCM, AES-128-CBC)")
    integrity_algorithm: Optional[str] = Field(default=None, description="Child SA integrity hash or AEAD (e.g. HMAC-SHA2-256, NONE, AEAD)")
    dh_group: Optional[Union[int, str]] = Field(default=None, description="Diffie-Hellman group number (e.g. 14, 19, 20)")
    pfs_enabled: Optional[bool] = Field(default=None, description="Whether Perfect Forward Secrecy is enabled for Child SAs")
    key_lifetime_seconds: Optional[int] = Field(default=None, ge=60, description="Security Association key lifetime in seconds (min 60s)")
    replay_protection_enabled: Optional[bool] = Field(default=None, description="Extended Sequence Numbers (ESN) / anti-replay enabled")
    operating_mode: Optional[str] = Field(default=None, description="IPsec operating mode: Tunnel or Transport")
    local_subnet: Optional[str] = Field(default=None, description="Local protected CIDR subnet")
    remote_subnet: Optional[str] = Field(default=None, description="Remote protected CIDR subnet")
