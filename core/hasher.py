"""
Cryptographic hashing utilities built with Python's hashlib and os modules.

Provides streaming SHA-256 generation for full files alongside fixed-size
block hashing to pinpoint which byte region of a file changed.
"""

import hashlib
import os

READ_CHUNK_SIZE = 65536  # 64 KB chunks so large files never overload memory
MAX_BLOCKS = 16
MIN_BLOCK_SIZE = 64


def normalize_path(file_path: str) -> str:
    """Clean user input quotes and return an absolute normalized path."""
    cleaned = file_path.strip().strip('"').strip("'")
    expanded = os.path.expanduser(cleaned)
    abs_path = os.path.abspath(expanded)
    if os.name == "nt" and len(abs_path) >= 2 and abs_path[1] == ":":
        abs_path = abs_path[0].upper() + abs_path[1:]
    return abs_path


def path_key(file_path: str) -> str:
    """Return an OS-appropriate lookup key (case-insensitive on Windows)."""
    return os.path.normcase(normalize_path(file_path))


def compute_sha256(file_path: str) -> str:
    """
    Generate the hexadecimal SHA-256 digest of a file.
    Reads in binary chunks to safely handle both small text files and large binaries.
    """
    hasher = hashlib.sha256()
    with open(file_path, "rb") as file_obj:
        while True:
            chunk = file_obj.read(READ_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def get_file_metadata(file_path: str) -> dict:
    """Collect basic OS file attributes used alongside hash verification."""
    stat_info = os.stat(file_path)
    return {
        "size": stat_info.st_size,
        "mtime": round(stat_info.st_mtime, 3),
        "mode": stat_info.st_mode,
    }


def choose_block_size(file_size: int) -> int:
    """
    Pick a fixed byte size per block so a file is split into up to MAX_BLOCKS segments.
    Storing this block_size in the baseline lets us compare identical byte ranges later.
    """
    if file_size <= 0:
        return MIN_BLOCK_SIZE
    calculated = (file_size + MAX_BLOCKS - 1) // MAX_BLOCKS
    return max(MIN_BLOCK_SIZE, calculated)


def compute_block_map(file_path: str, block_size: int | None = None) -> tuple[int, list[str]]:
    """
    Compute short SHA-256 digests for fixed-size blocks across the file.
    Returns (block_size, list_of_short_digests).
    """
    file_size = os.path.getsize(file_path)
    if block_size is None or block_size <= 0:
        block_size = choose_block_size(file_size)

    if file_size == 0:
        return block_size, []

    block_hashes = []
    with open(file_path, "rb") as file_obj:
        while True:
            block_bytes = file_obj.read(block_size)
            if not block_bytes:
                break
            digest = hashlib.sha256(block_bytes).hexdigest()[:16]
            block_hashes.append(digest)

    return block_size, block_hashes


def compare_block_maps(
    file_path: str,
    ref_block_size: int,
    ref_blocks: list[str],
    ref_size: int,
) -> dict:
    """
    Compare current file blocks against stored baseline blocks using the original block_size.
    Produces a visual map showing intact, modified, appended, or truncated regions.
    """
    current_size = os.path.getsize(file_path)
    _, current_blocks = compute_block_map(file_path, block_size=ref_block_size)

    total_slots = max(len(ref_blocks), len(current_blocks))
    segments = []
    modified_count = 0
    appended_count = 0
    truncated_count = 0
    first_change_index = None

    for idx in range(total_slots):
        start_byte = idx * ref_block_size
        end_byte = min((idx + 1) * ref_block_size, max(ref_size, current_size))

        if idx < len(ref_blocks) and idx < len(current_blocks):
            if ref_blocks[idx] == current_blocks[idx]:
                state = "intact"
            else:
                state = "modified"
                modified_count += 1
                if first_change_index is None:
                    first_change_index = idx
        elif idx >= len(ref_blocks):
            state = "appended"
            appended_count += 1
            if first_change_index is None:
                first_change_index = idx
        else:
            state = "truncated"
            truncated_count += 1
            if first_change_index is None:
                first_change_index = idx

        segments.append(
            {
                "index": idx + 1,
                "state": state,
                "start_byte": start_byte,
                "end_byte": end_byte,
            }
        )

    # Condense display strip if a file grew dramatically (e.g. massive append)
    display_segments = _condense_segments(segments, limit=20)
    diagnosis = _build_diagnosis(
        ref_size=ref_size,
        current_size=current_size,
        ref_block_size=ref_block_size,
        ref_count=len(ref_blocks),
        modified_count=modified_count,
        appended_count=appended_count,
        truncated_count=truncated_count,
        first_change_index=first_change_index,
    )

    return {
        "block_size": ref_block_size,
        "total_blocks": total_slots,
        "modified_blocks": modified_count,
        "appended_blocks": appended_count,
        "truncated_blocks": truncated_count,
        "segments": display_segments,
        "diagnosis": diagnosis,
    }


def _condense_segments(segments: list[dict], limit: int = 20) -> list[dict]:
    """Keep the visual strip compact even if someone appends megabytes to a tiny file."""
    if len(segments) <= limit:
        return segments

    head = segments[: limit - 1]
    tail = segments[limit - 1 :]
    tail_states = {seg["state"] for seg in tail}
    priority = ["modified", "truncated", "appended", "intact"]
    merged_state = next((s for s in priority if s in tail_states), "modified")

    head.append(
        {
            "index": limit,
            "state": merged_state,
            "start_byte": tail[0]["start_byte"],
            "end_byte": tail[-1]["end_byte"],
        }
    )
    return head


def _build_diagnosis(
    ref_size: int,
    current_size: int,
    ref_block_size: int,
    ref_count: int,
    modified_count: int,
    appended_count: int,
    truncated_count: int,
    first_change_index: int | None,
) -> str:
    """Return a plain-English summary of how the file was modified."""
    if ref_size == 0 and current_size > 0:
        return f"Content written to previously empty file (+{current_size:,} bytes)"

    if ref_size > 0 and current_size == 0:
        return f"File content was completely cleared (-{ref_size:,} bytes)"

    if modified_count == 0 and appended_count > 0 and truncated_count == 0:
        delta = current_size - ref_size
        return f"Original blocks intact; new data appended at end (+{delta:,} bytes)"

    if modified_count == 0 and truncated_count > 0 and appended_count == 0:
        cut_offset = (ref_count - truncated_count) * ref_block_size
        return f"Leading bytes intact; file truncated starting near byte {cut_offset:,}"

    # Note: if data was appended into the partial tail of the final reference block,
    # the last reference block itself changes while all preceding blocks stay intact.
    if (
        ref_count > 0
        and current_size > ref_size
        and first_change_index == ref_count - 1
        and modified_count == 1
    ):
        last_block_start = (ref_count - 1) * ref_block_size
        return (
            f"Leading blocks intact; change/append starts in final block "
            f"(bytes {last_block_start:,}-{current_size:,})"
        )

    if first_change_index is not None:
        start_b = first_change_index * ref_block_size
        end_b = min((first_change_index + 1) * ref_block_size, max(ref_size, current_size))
        altered_total = modified_count + appended_count + truncated_count
        return (
            f"Tampering detected across {altered_total} block(s); "
            f"first divergence in Block {first_change_index + 1} (bytes {start_b:,}-{end_b:,})"
        )

    return "Cryptographic SHA-256 mismatch detected"

