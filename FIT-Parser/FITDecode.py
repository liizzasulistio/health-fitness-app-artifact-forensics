from __future__ import print_function

import sys
import os
import json
import hashlib
import struct
import subprocess
import gzip
import tempfile
import shutil
from datetime import datetime, date, time

try:
    import fitdecode
except ImportError:
    try:
        print("Installing required module: fitdecode", file=sys.stderr)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "fitdecode"])
        import fitdecode
        print("fitdecode successfully installed.", file=sys.stderr)
    except Exception as e:
        print(json.dumps({"error": "Failed to install fitdecode", "details": str(e)}))
        sys.exit(1)


COMMON_MESSAGE_TYPES = [
    "file_id", "file_creator", "software", "device_info", "device_settings",
    "user_profile", "sport", "zones_target", "event", "activity", "session",
    "lap", "length", "record", "hrv", "workout", "workout_step",
    "developer_data_id", "field_description"
]


def safe_float(val):
    try:
        if val is None or val == "":
            return None
        return float(val)
    except Exception:
        return None


def safe_int(val):
    try:
        if val is None or val == "":
            return None
        return int(val)
    except Exception:
        try:
            return int(float(val))
        except Exception:
            return None


def json_safe(value):
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, dict):
        return dict((str(k), json_safe(v)) for k, v in value.items())
    return str(value)


def clean_text(val):
    if val is None:
        return None
    try:
        val = str(val).strip()
        return val if val else None
    except Exception:
        return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def looks_like_gzip(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"\x1f\x8b"
    except Exception:
        return False


def prepare_fit_path(source_path):
    """
    Returns (parse_path, source_is_gzip, cleanup_path).
    If source_path is .gz or has gzip magic, it is decompressed into a temp FIT.
    """
    source_is_gzip = source_path.lower().endswith(".gz") or looks_like_gzip(source_path)
    if not source_is_gzip:
        return source_path, False, None

    fd, out_path = tempfile.mkstemp(prefix="autopsy_fit_", suffix=".fit")
    os.close(fd)
    with gzip.open(source_path, "rb") as gz_in:
        with open(out_path, "wb") as fit_out:
            shutil.copyfileobj(gz_in, fit_out)
    return out_path, True, out_path


def parse_fit_header(path):
    header = {}
    try:
        with open(path, "rb") as f:
            raw = f.read(14)

        if len(raw) < 12:
            return {"error": "File too small for FIT header"}

        header_size = raw[0]
        protocol_version = raw[1]
        profile_version = struct.unpack("<H", raw[2:4])[0]
        data_size = struct.unpack("<I", raw[4:8])[0]
        data_type = raw[8:12].decode("ascii", errors="replace")

        header.update({
            "header_size": header_size,
            "protocol_version_raw": protocol_version,
            "protocol_version_major": protocol_version >> 4,
            "protocol_version_minor": protocol_version & 0x0F,
            "profile_version_raw": profile_version,
            "profile_version_major": profile_version // 100,
            "profile_version_minor": profile_version % 100,
            "data_size_bytes": data_size,
            "data_type": data_type,
            "is_fit_signature": data_type == ".FIT"
        })

        if header_size >= 14 and len(raw) >= 14:
            header["header_crc"] = struct.unpack("<H", raw[12:14])[0]

        file_size = os.path.getsize(path)
        header["file_crc_offset"] = header_size + data_size
        if file_size >= header["file_crc_offset"] + 2:
            with open(path, "rb") as f:
                f.seek(header["file_crc_offset"])
                crc_raw = f.read(2)
                if len(crc_raw) == 2:
                    header["file_crc"] = struct.unpack("<H", crc_raw)[0]

        header["expected_file_size_from_header"] = header_size + data_size + 2
        header["actual_file_size"] = file_size
        header["size_matches_header"] = (header["expected_file_size_from_header"] == file_size)
    except Exception as e:
        header["error"] = str(e)
    return header


def maybe_degrees(value, coord_type):
    x = safe_float(value)
    if x is None:
        return None

    if coord_type == "lat" and -90.0 <= x <= 90.0:
        return x
    if coord_type == "lon" and -180.0 <= x <= 180.0:
        return x

    return x * (180.0 / 2147483648.0)


def get_first(messages, message_name):
    rows = messages.get(message_name) or []
    return rows[0] if rows else {}


def get_best_device(messages):
    device = {}
    creator_device = None

    candidates = []
    candidates.extend(messages.get("device_info", []))
    candidates.extend(messages.get("file_id", []))
    candidates.extend(messages.get("file_creator", []))

    for row in candidates:
        manufacturer = clean_text(row.get("manufacturer"))
        product = clean_text(row.get("product")) or clean_text(row.get("garmin_product"))
        software_version = row.get("software_version")
        serial_number = row.get("serial_number")

        if manufacturer or product or software_version or serial_number:
            device.update({
                "manufacturer": manufacturer,
                "product": product,
                "garmin_product": row.get("garmin_product"),
                "serial_number": serial_number,
                "software_version": software_version,
                "hardware_version": row.get("hardware_version"),
                "device_index": row.get("device_index"),
                "device_type": row.get("device_type"),
                "source_type": row.get("source_type"),
                "antplus_device_type": row.get("antplus_device_type"),
                "ant_device_number": row.get("ant_device_number")
            })
            parts = [p for p in [manufacturer, product] if p]
            creator_device = " ".join(parts) if parts else None
            break

    if creator_device:
        device["creator_device"] = creator_device
    return device


def add_if_present(target, key, source, source_key=None, converter=None):
    source_key = source_key or key
    val = source.get(source_key)
    if val is None:
        return
    if converter:
        try:
            val = converter(val)
        except Exception:
            pass
    target[key] = val


def extract_summary(messages):
    summary = {}

    file_id = get_first(messages, "file_id")
    session = get_first(messages, "session")
    activity = get_first(messages, "activity")
    sport_msg = get_first(messages, "sport")
    user_profile = get_first(messages, "user_profile")

    add_if_present(summary, "fit_file_type", file_id, "type")
    add_if_present(summary, "created_time", file_id, "time_created")
    add_if_present(summary, "manufacturer", file_id)
    add_if_present(summary, "product", file_id)
    add_if_present(summary, "serial_number", file_id)

    add_if_present(summary, "sport", session)
    add_if_present(summary, "sub_sport", session)
    if not summary.get("sport"):
        add_if_present(summary, "sport", sport_msg)

    add_if_present(summary, "start_time", session)
    add_if_present(summary, "start_position_lat", session)
    add_if_present(summary, "start_position_long", session)
    add_if_present(summary, "total_elapsed_time_sec", session, "total_elapsed_time", safe_float)
    add_if_present(summary, "total_timer_time_sec", session, "total_timer_time", safe_float)
    add_if_present(summary, "total_timer_time_min", session, "total_timer_time", lambda x: round(safe_float(x) / 60.0, 2))
    add_if_present(summary, "total_distance_m", session, "total_distance", safe_float)
    add_if_present(summary, "total_distance_km", session, "total_distance", lambda x: round(safe_float(x) / 1000.0, 3))
    add_if_present(summary, "total_calories", session)
    add_if_present(summary, "total_ascent_m", session, "total_ascent")
    add_if_present(summary, "total_descent_m", session, "total_descent")

    add_if_present(summary, "average_heart_rate", session, "avg_heart_rate")
    add_if_present(summary, "max_heart_rate", session, "max_heart_rate")
    add_if_present(summary, "min_heart_rate", session, "min_heart_rate")
    add_if_present(summary, "average_cadence_rpm_spm", session, "avg_cadence")
    add_if_present(summary, "max_cadence_rpm_spm", session, "max_cadence")
    add_if_present(summary, "average_speed_mps", session, "avg_speed", safe_float)
    add_if_present(summary, "max_speed_mps", session, "max_speed", safe_float)
    add_if_present(summary, "average_speed_kmh", session, "avg_speed", lambda x: round(safe_float(x) * 3.6, 2))
    add_if_present(summary, "max_speed_kmh", session, "max_speed", lambda x: round(safe_float(x) * 3.6, 2))
    add_if_present(summary, "average_power_w", session, "avg_power")
    add_if_present(summary, "max_power_w", session, "max_power")
    add_if_present(summary, "normalized_power_w", session, "normalized_power")
    add_if_present(summary, "total_work_j", session, "total_work")
    add_if_present(summary, "training_effect", session)
    add_if_present(summary, "anaerobic_training_effect", session)
    add_if_present(summary, "total_training_effect", session)
    add_if_present(summary, "total_anaerobic_training_effect", session)

    add_if_present(summary, "avg_temperature_c", session, "avg_temperature")
    add_if_present(summary, "max_temperature_c", session, "max_temperature")
    add_if_present(summary, "min_temperature_c", session, "min_temperature")
    add_if_present(summary, "avg_altitude_m", session, "avg_altitude")
    add_if_present(summary, "max_altitude_m", session, "max_altitude")
    add_if_present(summary, "min_altitude_m", session, "min_altitude")

    add_if_present(summary, "activity_total_timer_time_sec", activity, "total_timer_time", safe_float)
    add_if_present(summary, "activity_num_sessions", activity, "num_sessions")
    add_if_present(summary, "activity_type", activity, "type")
    add_if_present(summary, "event", activity)
    add_if_present(summary, "event_type", activity)

    add_if_present(summary, "gender", user_profile)
    add_if_present(summary, "age", user_profile)
    add_if_present(summary, "weight_kg", user_profile, "weight")
    add_if_present(summary, "height_m", user_profile, "height")

    total_km = safe_float(summary.get("total_distance_km"))
    total_min = safe_float(summary.get("total_timer_time_min"))
    if total_km and total_km > 0 and total_min and total_min > 0:
        summary["average_pace_min_per_km"] = round(total_min / total_km, 2)
        if not summary.get("average_speed_kmh"):
            summary["average_speed_kmh"] = round(total_km / (total_min / 60.0), 2)

    return summary


def numeric_stats(values):
    nums = [safe_float(v) for v in values]
    nums = [v for v in nums if v is not None]
    if not nums:
        return {}
    return {
        "count": len(nums),
        "min": round(min(nums), 4),
        "max": round(max(nums), 4),
        "avg": round(sum(nums) / float(len(nums)), 4)
    }


def compute_record_analytics(messages, summary):
    records = messages.get("record", []) or []
    laps = messages.get("lap", []) or []
    lengths = messages.get("length", []) or []
    hrv = messages.get("hrv", []) or []
    events = messages.get("event", []) or []

    analytics = {
        "record_count": len(records),
        "lap_count": len(laps),
        "length_count": len(lengths),
        "hrv_count": len(hrv),
        "event_count": len(events)
    }

    if not records:
        return analytics, {"gps_points_count": 0}

    sensor_map = {
        "speed_mps": "speed",
        "enhanced_speed_mps": "enhanced_speed",
        "heart_rate_bpm": "heart_rate",
        "cadence_rpm_spm": "cadence",
        "distance_m": "distance",
        "altitude_m": "altitude",
        "enhanced_altitude_m": "enhanced_altitude",
        "power_w": "power",
        "temperature_c": "temperature",
        "grade_percent": "grade",
        "vertical_speed_mps": "vertical_speed"
    }

    for out_name, field_name in sensor_map.items():
        stats = numeric_stats([r.get(field_name) for r in records])
        if stats:
            analytics[out_name + "_min"] = stats["min"]
            analytics[out_name + "_max"] = stats["max"]
            analytics[out_name + "_avg"] = stats["avg"]
            analytics[out_name + "_count"] = stats["count"]

    if "speed_mps_avg" in analytics:
        analytics["average_speed_kmh_from_records"] = round(analytics["speed_mps_avg"] * 3.6, 2)
    if "speed_mps_max" in analytics:
        analytics["max_speed_kmh_from_records"] = round(analytics["speed_mps_max"] * 3.6, 2)
        if analytics["speed_mps_max"] > 0:
            analytics["best_pace_min_per_km_from_records"] = round(1000.0 / (analytics["speed_mps_max"] * 60.0), 2)

    record_distances = [safe_float(r.get("distance")) for r in records if safe_float(r.get("distance")) is not None]
    if record_distances:
        analytics["last_record_distance_m"] = round(record_distances[-1], 3)
        analytics["last_record_distance_km"] = round(record_distances[-1] / 1000.0, 3)

    timestamps = [r.get("timestamp") for r in records if r.get("timestamp")]
    if timestamps:
        analytics["first_record_time"] = timestamps[0]
        analytics["last_record_time"] = timestamps[-1]
        try:
            t0 = datetime.fromisoformat(str(timestamps[0]).replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(str(timestamps[-1]).replace("Z", "+00:00"))
            analytics["record_duration_sec"] = round((t1 - t0).total_seconds(), 3)
            analytics["record_duration_min"] = round(analytics["record_duration_sec"] / 60.0, 2)
        except Exception:
            pass

    points = []
    for r in records:
        lat_raw = r.get("position_lat")
        lon_raw = r.get("position_long")
        if lat_raw is None or lon_raw is None:
            continue

        lat = maybe_degrees(lat_raw, "lat")
        lon = maybe_degrees(lon_raw, "lon")
        if lat is None or lon is None:
            continue
        if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            continue

        points.append({
            "timestamp": r.get("timestamp"),
            "lat": round(lat, 8),
            "lon": round(lon, 8),
            "distance_m": r.get("distance"),
            "altitude_m": r.get("enhanced_altitude") if r.get("enhanced_altitude") is not None else r.get("altitude"),
            "heart_rate": r.get("heart_rate"),
            "speed_mps": r.get("enhanced_speed") if r.get("enhanced_speed") is not None else r.get("speed")
        })

    gps = {"gps_points_count": len(points)}
    if points:
        lats = [p["lat"] for p in points]
        lons = [p["lon"] for p in points]
        gps.update({
            "start_lat": points[0]["lat"],
            "start_lon": points[0]["lon"],
            "start_gps_time": points[0].get("timestamp"),
            "end_lat": points[-1]["lat"],
            "end_lon": points[-1]["lon"],
            "end_gps_time": points[-1].get("timestamp"),
            "min_lat": min(lats),
            "max_lat": max(lats),
            "min_lon": min(lons),
            "max_lon": max(lons),
            "track_points_sample": points[:10],
            "track_points": points
        })

    analytics["gps_points_count"] = len(points)

    if not summary.get("total_distance_km") and analytics.get("last_record_distance_km"):
        summary["total_distance_km"] = analytics.get("last_record_distance_km")
        summary["total_distance_m"] = analytics.get("last_record_distance_m")
    if not summary.get("total_timer_time_min") and analytics.get("record_duration_min"):
        summary["total_timer_time_min"] = analytics.get("record_duration_min")
        summary["total_timer_time_sec"] = analytics.get("record_duration_sec")

    total_km = safe_float(summary.get("total_distance_km"))
    total_min = safe_float(summary.get("total_timer_time_min"))
    if total_km and total_km > 0 and total_min and total_min > 0:
        summary["average_pace_min_per_km"] = round(total_min / total_km, 2)
        if not summary.get("average_speed_kmh"):
            summary["average_speed_kmh"] = round(total_km / (total_min / 60.0), 2)

    return analytics, gps


def extract_fit(source_path):
    parse_path, source_is_gzip, cleanup_path = prepare_fit_path(source_path)

    try:
        file_meta = {
            "path": source_path,
            "file_name": os.path.basename(source_path),
            "size_bytes": os.path.getsize(source_path) if os.path.exists(source_path) else None,
            "sha256": sha256_file(source_path) if os.path.exists(source_path) else None,
            "source_is_gzip": source_is_gzip,
            "decoded_size_bytes": os.path.getsize(parse_path) if os.path.exists(parse_path) else None
        }

        fit_header = parse_fit_header(parse_path)

        messages = dict((name, []) for name in COMMON_MESSAGE_TYPES)
        message_counts = {}
        field_inventory = {}

        with fitdecode.FitReader(parse_path) as fit:
            for frame in fit:
                if frame.frame_type != fitdecode.FIT_FRAME_DATA:
                    continue

                msg_name = frame.name or "unknown_message"
                if msg_name not in messages:
                    messages[msg_name] = []

                row = {}
                field_meta = {}

                for field in frame.fields:
                    field_name = field.name or "field_{}".format(getattr(field, "def_num", "unknown"))
                    value = json_safe(field.value)
                    row[field_name] = value

                    meta = {}
                    if hasattr(field, "units") and field.units:
                        meta["units"] = json_safe(field.units)
                    if hasattr(field, "raw_value"):
                        meta["raw_value"] = json_safe(field.raw_value)
                    if hasattr(field, "def_num"):
                        meta["def_num"] = json_safe(field.def_num)
                    if meta:
                        field_meta[field_name] = meta

                    field_inventory.setdefault(msg_name, set()).add(field_name)

                dev_fields = []
                if hasattr(frame, "developer_fields"):
                    dev_fields = frame.developer_fields or []
                elif hasattr(frame, "get_developer_fields"):
                    dev_fields = frame.get_developer_fields() or []

                for dev_field in dev_fields:
                    dev_name = getattr(dev_field, "name", None) or "developer_field_{}".format(getattr(dev_field, "def_num", "unknown"))
                    row[dev_name] = json_safe(getattr(dev_field, "value", None))
                    field_inventory.setdefault(msg_name, set()).add(dev_name)

                if field_meta:
                    row["_field_meta"] = field_meta

                messages[msg_name].append(row)
                message_counts[msg_name] = message_counts.get(msg_name, 0) + 1

        field_inventory = dict((k, sorted(list(v))) for k, v in field_inventory.items())

        summary = extract_summary(messages)
        device_meta = get_best_device(messages)
        summary.update(dict((k, v) for k, v in device_meta.items() if v is not None))

        analytics, gps = compute_record_analytics(messages, summary)

        return {
            "file": file_meta,
            "fit_header": fit_header,
            "summary": summary,
            "gps": gps,
            "analytics": analytics,
            "message_counts": message_counts,
            "available_message_types": sorted(message_counts.keys()),
            "field_inventory": field_inventory,
            "messages": messages
        }
    finally:
        if cleanup_path:
            try:
                os.remove(cleanup_path)
            except Exception:
                pass


def make_compact(parsed):
    compact = dict(parsed)
    if "messages" in compact:
        compact["messages"] = {
            "note": "Full messages omitted in --compact mode.",
            "available_message_types": compact.get("available_message_types", []),
            "message_counts": compact.get("message_counts", {})
        }
    gps = compact.get("gps") or {}
    if "track_points" in gps:
        gps["track_points_total"] = len(gps.get("track_points") or [])
        gps.pop("track_points", None)
    compact["gps"] = gps
    return compact

def decode_fit(file_path):
    return extract_fit(file_path)


def compute_analytics(parsed):
    return parsed


if __name__ == "__main__":
    compact_mode = False
    args = sys.argv[1:]
    if "--compact" in args:
        compact_mode = True
        args.remove("--compact")

    if len(args) < 1:
        print(json.dumps({"error": "Usage: python FitDecode.py [--compact] <fit_or_fit_gz_file>"}))
        sys.exit(1)

    fit_path = args[0]
    try:
        parsed = extract_fit(fit_path)
        if compact_mode:
            parsed = make_compact(parsed)
        print(json.dumps(parsed, indent=2, default=json_safe))
    except Exception as e:
        error_info = {
            "file": fit_path,
            "error": str(e),
            "type": e.__class__.__name__
        }
        try:
            import traceback
            error_info["traceback"] = traceback.format_exc()
        except Exception:
            pass
        print(json.dumps(error_info, indent=2))
        sys.exit(0)
