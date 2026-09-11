import pyshark
from pyshark.capture.capture import TSharkCrashException

def parse_pcap(file_path: str) -> dict:
    """
    Deterministic Control-Plane parser for IKEv2/IPsec PCAP files.
    Extracts IKE SA payload parameters using PyShark.
    """
    # Initialize the default return schema (matching ControlPlaneData Pydantic schema)
    control_plane_data = {
        "ike_version": "Unknown",
        "operating_mode": "Tunnel",  # Heuristic fallback: assuming Tunnel mode natively unless Transport is detected via ESP
        "encryption_algorithm": "Unknown",
        "integrity_algorithm": "Unknown",
        "dh_group": 0,
        "pfs_enabled": False,        # Heuristic fallback: defaulting to False unless explicit Phase 2 KE payload is parsed
        "key_lifetime_seconds": 0,
        "replay_protection_enabled": True  # Heuristic fallback: default True as per modern IPsec implementations
    }

    try:
        # Initialize FileCapture with strict ISAKMP display filter
        cap = pyshark.FileCapture(file_path, display_filter="isakmp", keep_packets=False)
        
        for pkt in cap:
            if not hasattr(pkt, 'isakmp'):
                continue

            # Extract IKE Version
            version = getattr(pkt.isakmp, 'version', getattr(pkt.isakmp, 'ike_version', None))
            if version and control_plane_data["ike_version"] == "Unknown":
                if "2.0" in version or "2" in version:
                    control_plane_data["ike_version"] = "IKEv2"
                elif "1.0" in version or "1" in version:
                    control_plane_data["ike_version"] = "IKEv1"

            # Traverse the packet layers to find ISAKMP payloads
            # PyShark extracts fields generically; we look for specific transform attributes
            
            # Transform Type 1: ENCR (Encryption)
            encr = getattr(pkt.isakmp, 'trans_encr', getattr(pkt.isakmp, 'tf_encr', getattr(pkt.isakmp, 'ike_trans_encr', None)))
            if encr and control_plane_data["encryption_algorithm"] == "Unknown":
                control_plane_data["encryption_algorithm"] = str(encr).replace(' (', '').replace(')', '')

            # Transform Type 3: INTEG (Integrity)
            integ = getattr(pkt.isakmp, 'trans_integ', getattr(pkt.isakmp, 'tf_integ', getattr(pkt.isakmp, 'ike_trans_integ', None)))
            if integ and control_plane_data["integrity_algorithm"] == "Unknown":
                control_plane_data["integrity_algorithm"] = str(integ)

            # Transform Type 4: D-H (Diffie-Hellman Group)
            dh = getattr(pkt.isakmp, 'trans_dh', getattr(pkt.isakmp, 'tf_dh', getattr(pkt.isakmp, 'ike_trans_dh', None)))
            if dh and control_plane_data["dh_group"] == 0:
                try:
                    dh_str = str(dh)
                    # Attempt to extract numeric group (e.g., "Group 14" -> 14)
                    nums = [int(s) for s in dh_str.split() if s.isdigit()]
                    if nums:
                        control_plane_data["dh_group"] = nums[0]
                    else:
                        control_plane_data["dh_group"] = dh_str
                except (ValueError, TypeError):
                    pass

            # Transform Type: Life Type/Duration
            lifetime = getattr(pkt.isakmp, 'tf_life_duration', getattr(pkt.isakmp, 'ike_trans_life_duration', None))
            if lifetime and control_plane_data["key_lifetime_seconds"] == 0:
                try:
                    control_plane_data["key_lifetime_seconds"] = int(lifetime)
                except (ValueError, TypeError):
                    pass

        cap.close()

    except FileNotFoundError:
        raise ValueError(f"PCAP file not found at path: {file_path}")
    except TSharkCrashException as e:
        raise ValueError(f"TShark process crashed during ISAKMP extraction: {str(e)}")
    except Exception as e:
        raise ValueError(f"Fatal error while parsing control plane PCAP data: {str(e)}")

    return control_plane_data
