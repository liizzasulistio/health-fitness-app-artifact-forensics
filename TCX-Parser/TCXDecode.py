from __future__ import print_function

import sys
import os
import json
import gzip
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime


def safe_float(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except Exception:
        return None


def safe_int(value):
    try:
        if value is None or value == "":
            return None
        return int(float(value))
    except Exception:
        return None


def json_safe(value):
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, dict):
        return dict((str(k), json_safe(v)) for k, v in value.items())
    try:
        return value.isoformat()
    except Exception:
        return str(value)


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


def clean_tcx(file_path):
    source_is_gzip = file_path.lower().endswith(".gz") or looks_like_gzip(file_path)

    if source_is_gzip:
        with gzip.open(file_path, "rb") as f:
            data = f.read()
    else:
        with open(file_path, "rb") as f:
            data = f.read()

    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]

    data = data.lstrip()
    return data, source_is_gzip


def text_of(node):
    if node is None or node.text is None:
        return None
    text = node.text.strip()
    return text if text != "" else None


def find_text(parent, paths, ns):
    for path in paths:
        try:
            node = parent.find(path, ns)
            val = text_of(node)
            if val is not None:
                return val
        except Exception:
            pass
    return None


def find_float(parent, paths, ns):
    val = find_text(parent, paths, ns)
    return safe_float(val)


def find_int(parent, paths, ns):
    val = find_text(parent, paths, ns)
    return safe_int(val)


def find_all(root, name):
    # Namespace-agnostic search.
    return root.findall(".//{*}" + name)


def first(root, name):
    rows = find_all(root, name)
    return rows[0] if rows else None


def stats(values):
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


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        try:
            # Python versions without fromisoformat timezone support fallback.
            return datetime.strptime(str(value).replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None


def parse_trackpoint(tp, ns):
    timestamp = find_text(tp, [
        "tcx:Time",
        "{*}Time"
    ], ns)

    altitude_m = find_float(tp, [
        "tcx:AltitudeMeters",
        "{*}AltitudeMeters"
    ], ns)

    distance_m = find_float(tp, [
        "tcx:DistanceMeters",
        "{*}DistanceMeters"
    ], ns)

    heart_rate = find_int(tp, [
        "tcx:HeartRateBpm/tcx:Value",
        "{*}HeartRateBpm/{*}Value"
    ], ns)

    cadence = find_int(tp, [
        "tcx:Cadence",
        "{*}Cadence"
    ], ns)

    lat = find_float(tp, [
        "tcx:Position/tcx:LatitudeDegrees",
        "{*}Position/{*}LatitudeDegrees"
    ], ns)

    lon = find_float(tp, [
        "tcx:Position/tcx:LongitudeDegrees",
        "{*}Position/{*}LongitudeDegrees"
    ], ns)

    ext = tp.find("tcx:Extensions", ns)
    if ext is None:
        ext = tp.find("{*}Extensions")

    speed_mps = None
    watts = None
    run_cadence = None

    if ext is not None:
        try:
            sp = ext.find(".//{*}Speed")
            if sp is not None:
                speed_mps = safe_float(text_of(sp))
        except Exception:
            pass

        try:
            wt = ext.find(".//{*}Watts")
            if wt is not None:
                watts = safe_float(text_of(wt))
        except Exception:
            pass

        try:
            rc = ext.find(".//{*}RunCadence")
            if rc is not None:
                run_cadence = safe_int(text_of(rc))
        except Exception:
            pass

        if lat is None or lon is None:
            try:
                lat2 = ext.find(".//{*}LatitudeDegrees")
                lon2 = ext.find(".//{*}LongitudeDegrees")
                if lat2 is not None and lon2 is not None:
                    lat = safe_float(text_of(lat2))
                    lon = safe_float(text_of(lon2))
            except Exception:
                pass

    return {
        "timestamp": timestamp,
        "lat": lat,
        "lon": lon,
        "altitude_m": altitude_m,
        "distance_m": distance_m,
        "heart_rate_bpm": heart_rate,
        "cadence": cadence,
        "run_cadence": run_cadence,
        "speed_mps": speed_mps,
        "speed_kmh": round(speed_mps * 3.6, 2) if speed_mps is not None else None,
        "power_w": watts
    }


def parse_lap(lap, ns):
    start_time = lap.get("StartTime") or lap.get("startTime")
    return {
        "start_time": start_time,
        "total_time_sec": find_float(lap, ["tcx:TotalTimeSeconds", "{*}TotalTimeSeconds"], ns),
        "distance_m": find_float(lap, ["tcx:DistanceMeters", "{*}DistanceMeters"], ns),
        "maximum_speed_mps": find_float(lap, ["tcx:MaximumSpeed", "{*}MaximumSpeed"], ns),
        "calories": find_int(lap, ["tcx:Calories", "{*}Calories"], ns),
        "average_heart_rate": find_int(lap, ["tcx:AverageHeartRateBpm/tcx:Value", "{*}AverageHeartRateBpm/{*}Value"], ns),
        "max_heart_rate": find_int(lap, ["tcx:MaximumHeartRateBpm/tcx:Value", "{*}MaximumHeartRateBpm/{*}Value"], ns),
        "intensity": find_text(lap, ["tcx:Intensity", "{*}Intensity"], ns),
        "trigger_method": find_text(lap, ["tcx:TriggerMethod", "{*}TriggerMethod"], ns),
        "cadence": find_int(lap, ["tcx:Cadence", "{*}Cadence"], ns)
    }


def parse_creator(activity, root, ns):
    creator = {}
    creator_node = None

    if activity is not None:
        creator_node = activity.find("tcx:Creator", ns)
        if creator_node is None:
            creator_node = activity.find("{*}Creator")

    if creator_node is None:
        creator_node = first(root, "Creator")

    if creator_node is not None:
        creator["name"] = find_text(creator_node, ["tcx:Name", "{*}Name"], ns)
        creator["unit_id"] = find_text(creator_node, ["tcx:UnitId", "{*}UnitId"], ns)
        creator["product_id"] = find_text(creator_node, ["tcx:ProductID", "{*}ProductID"], ns)

        version_node = creator_node.find("tcx:Version", ns)
        if version_node is None:
            version_node = creator_node.find("{*}Version")

        if version_node is not None:
            creator["version_major"] = find_text(version_node, ["tcx:VersionMajor", "{*}VersionMajor"], ns)
            creator["version_minor"] = find_text(version_node, ["tcx:VersionMinor", "{*}VersionMinor"], ns)
            creator["build_major"] = find_text(version_node, ["tcx:BuildMajor", "{*}BuildMajor"], ns)
            creator["build_minor"] = find_text(version_node, ["tcx:BuildMinor", "{*}BuildMinor"], ns)

        if creator.get("name"):
            creator["device"] = creator.get("name")

    return dict((k, v) for k, v in creator.items() if v is not None)


def parse_tcx(file_path):
    xml_bytes, source_is_gzip = clean_tcx(file_path)

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        return {
            "file": {
                "path": file_path,
                "file_name": os.path.basename(file_path),
                "size_bytes": os.path.getsize(file_path) if os.path.exists(file_path) else None,
                "source_is_gzip": source_is_gzip,
                "decoded_size_bytes": len(xml_bytes)
            },
            "parse_status": "FAILED",
            "error": "TCX parse failed: " + str(e)
        }

    ns = {
        "tcx": "http://www.garmin.com/xmlschemas/TrainingCenterDatabase/v2",
        "ns2": "http://www.garmin.com/xmlschemas/ActivityExtension/v2",
        "ns3": "http://www.garmin.com/xmlschemas/ActivityExtension/v2",
        "ns1": "http://www.garmin.com/xmlschemas/ExerciseIntensity/v2"
    }

    activity = root.find(".//tcx:Activity", ns)
    if activity is None:
        activity = root.find(".//{*}Activity")

    sport = None
    activity_id = None
    if activity is not None:
        sport = activity.get("Sport") or activity.get("sport")
        activity_id = find_text(activity, ["tcx:Id", "{*}Id"], ns)

    creator = parse_creator(activity, root, ns)

    laps = []
    lap_nodes = root.findall(".//tcx:Lap", ns)
    if not lap_nodes:
        lap_nodes = root.findall(".//{*}Lap")

    for lap in lap_nodes:
        laps.append(parse_lap(lap, ns))

    trackpoints = []
    tp_nodes = root.findall(".//tcx:Trackpoint", ns)
    if not tp_nodes:
        tp_nodes = root.findall(".//{*}Trackpoint")

    for tp in tp_nodes:
        trackpoints.append(parse_trackpoint(tp, ns))

    gps_points = []
    for p in trackpoints:
        lat = safe_float(p.get("lat"))
        lon = safe_float(p.get("lon"))
        if lat is None or lon is None:
            continue
        if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0:
            gps_points.append({
                "timestamp": p.get("timestamp"),
                "lat": round(lat, 8),
                "lon": round(lon, 8),
                "altitude_m": p.get("altitude_m"),
                "distance_m": p.get("distance_m"),
                "heart_rate_bpm": p.get("heart_rate_bpm"),
                "cadence": p.get("cadence"),
                "speed_mps": p.get("speed_mps"),
                "speed_kmh": p.get("speed_kmh")
            })

    total_time_sec = 0.0
    total_distance_m = 0.0
    total_calories = 0
    has_calories = False

    lap_avg_hr = []
    lap_max_hr = []
    lap_cadence = []
    lap_max_speed = []

    start_time = activity_id
    if laps:
        if not start_time:
            start_time = laps[0].get("start_time")
        for lap in laps:
            if lap.get("total_time_sec") is not None:
                total_time_sec += lap.get("total_time_sec")
            if lap.get("distance_m") is not None:
                total_distance_m += lap.get("distance_m")
            if lap.get("calories") is not None:
                total_calories += lap.get("calories")
                has_calories = True
            if lap.get("average_heart_rate") is not None:
                lap_avg_hr.append(lap.get("average_heart_rate"))
            if lap.get("max_heart_rate") is not None:
                lap_max_hr.append(lap.get("max_heart_rate"))
            if lap.get("cadence") is not None:
                lap_cadence.append(lap.get("cadence"))
            if lap.get("maximum_speed_mps") is not None:
                lap_max_speed.append(lap.get("maximum_speed_mps"))

    # Fallback values from trackpoints.
    if total_distance_m <= 0:
        distances = [p.get("distance_m") for p in trackpoints if p.get("distance_m") is not None]
        if distances:
            total_distance_m = max(distances)

    if total_time_sec <= 0:
        times = [p.get("timestamp") for p in trackpoints if p.get("timestamp")]
        if len(times) >= 2:
            t0 = parse_time(times[0])
            t1 = parse_time(times[-1])
            if t0 and t1:
                total_time_sec = max(0.0, (t1 - t0).total_seconds())

    hr_values = [p.get("heart_rate_bpm") for p in trackpoints if p.get("heart_rate_bpm") is not None]
    cadence_values = []
    for p in trackpoints:
        if p.get("cadence") is not None:
            cadence_values.append(p.get("cadence"))
        elif p.get("run_cadence") is not None:
            cadence_values.append(p.get("run_cadence"))

    speed_values = [p.get("speed_mps") for p in trackpoints if p.get("speed_mps") is not None and p.get("speed_mps") > 0]
    altitude_values = [p.get("altitude_m") for p in trackpoints if p.get("altitude_m") is not None]

    average_hr = None
    max_hr = None
    if hr_values:
        average_hr = round(sum(hr_values) / float(len(hr_values)), 1)
        max_hr = max(hr_values)
    else:
        if lap_avg_hr:
            average_hr = round(sum(lap_avg_hr) / float(len(lap_avg_hr)), 1)
        if lap_max_hr:
            max_hr = max(lap_max_hr)

    average_cadence = None
    if cadence_values:
        average_cadence = round(sum(cadence_values) / float(len(cadence_values)), 1)
    elif lap_cadence:
        average_cadence = round(sum(lap_cadence) / float(len(lap_cadence)), 1)

    average_speed_kmh = None
    max_speed_kmh = None
    if speed_values:
        average_speed_kmh = round((sum(speed_values) / float(len(speed_values))) * 3.6, 2)
        max_speed_kmh = round(max(speed_values) * 3.6, 2)
    elif lap_max_speed:
        max_speed_kmh = round(max(lap_max_speed) * 3.6, 2)

    total_distance_km = round(total_distance_m / 1000.0, 3) if total_distance_m > 0 else None
    total_timer_time_min = round(total_time_sec / 60.0, 2) if total_time_sec > 0 else None

    average_pace_min_per_km = None
    if total_distance_km and total_timer_time_min and total_distance_km > 0:
        average_pace_min_per_km = round(total_timer_time_min / total_distance_km, 2)
        if average_speed_kmh is None and total_timer_time_min > 0:
            average_speed_kmh = round(total_distance_km / (total_timer_time_min / 60.0), 2)

    gps = {
        "gps_points_count": len(gps_points)
    }

    if gps_points:
        lats = [p.get("lat") for p in gps_points]
        lons = [p.get("lon") for p in gps_points]
        gps.update({
            "start_lat": gps_points[0].get("lat"),
            "start_lon": gps_points[0].get("lon"),
            "start_gps_time": gps_points[0].get("timestamp"),
            "end_lat": gps_points[-1].get("lat"),
            "end_lon": gps_points[-1].get("lon"),
            "end_gps_time": gps_points[-1].get("timestamp"),
            "min_lat": min(lats),
            "max_lat": max(lats),
            "min_lon": min(lons),
            "max_lon": max(lons),
            "track_points_sample": gps_points[:10],
            "track_points": gps_points
        })

    analytics = {
        "lap_count": len(laps),
        "trackpoint_count": len(trackpoints),
        "gps_points_count": len(gps_points)
    }

    for out_key, source_key in [
        ("heart_rate_bpm", "heart_rate_bpm"),
        ("cadence", "cadence"),
        ("speed_mps", "speed_mps"),
        ("altitude_m", "altitude_m"),
        ("distance_m", "distance_m"),
        ("power_w", "power_w")
    ]:
        s = stats([p.get(source_key) for p in trackpoints])
        if s:
            analytics[out_key + "_min"] = s.get("min")
            analytics[out_key + "_max"] = s.get("max")
            analytics[out_key + "_avg"] = s.get("avg")
            analytics[out_key + "_count"] = s.get("count")

    if altitude_values:
        analytics["altitude_gain_estimate_m"] = None
        gain = 0.0
        loss = 0.0
        prev = None
        for alt in altitude_values:
            if prev is not None:
                diff = alt - prev
                if diff > 0:
                    gain += diff
                elif diff < 0:
                    loss += abs(diff)
            prev = alt
        analytics["altitude_gain_estimate_m"] = round(gain, 2)
        analytics["altitude_loss_estimate_m"] = round(loss, 2)

    file_meta = {
        "path": file_path,
        "file_name": os.path.basename(file_path),
        "size_bytes": os.path.getsize(file_path) if os.path.exists(file_path) else None,
        "sha256": sha256_file(file_path) if os.path.exists(file_path) else None,
        "source_is_gzip": source_is_gzip,
        "decoded_size_bytes": len(xml_bytes)
    }

    summary = {
        "sport": sport,
        "activity_id": activity_id,
        "creator": creator.get("name"),
        "device": creator.get("device"),
        "start_time": start_time,
        "total_timer_time_sec": round(total_time_sec, 3) if total_time_sec > 0 else None,
        "total_timer_time_min": total_timer_time_min,
        "total_distance_m": round(total_distance_m, 3) if total_distance_m > 0 else None,
        "total_distance_km": total_distance_km,
        "total_calories": total_calories if has_calories else None,
        "average_heart_rate": average_hr,
        "max_heart_rate": max_hr,
        "average_speed_kmh": average_speed_kmh,
        "max_speed_kmh": max_speed_kmh,
        "average_pace_min_per_km": average_pace_min_per_km,
        "average_cadence_spm": average_cadence,
        "lap_count": len(laps)
    }

    return {
        "parse_status": "SUCCESS",
        "file": file_meta,
        "summary": summary,
        "creator": creator,
        "gps": gps,
        "analytics": analytics,
        "laps": laps,
        "trackpoints": trackpoints
    }


def make_compact(parsed):
    compact = dict(parsed)

    gps = dict(compact.get("gps") or {})
    if "track_points" in gps:
        gps["track_points_total"] = len(gps.get("track_points") or [])
        gps.pop("track_points", None)
    compact["gps"] = gps

    if "trackpoints" in compact:
        compact["trackpoints"] = {
            "note": "Full TCX trackpoints are saved in the JSON output file. Omitted from stdout compact mode.",
            "trackpoint_count": compact.get("analytics", {}).get("trackpoint_count"),
            "gps_points_count": compact.get("analytics", {}).get("gps_points_count")
        }

    if "laps" in compact and isinstance(compact.get("laps"), list):
        compact["laps_sample"] = compact.get("laps", [])[:5]
        compact.pop("laps", None)

    return compact


def write_json(path, data, pretty=True):
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2 if pretty else None, ensure_ascii=False, default=json_safe)


def _cli_main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    output_json = None
    pretty = False
    compact = False
    args = []

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--output":
            if i + 1 >= len(argv):
                print(json.dumps({"error": "Missing value after --output"}))
                return 1
            output_json = argv[i + 1]
            i += 2
        elif arg == "--pretty":
            pretty = True
            i += 1
        elif arg == "--compact":
            compact = True
            i += 1
        else:
            args.append(arg)
            i += 1

    if len(args) < 1:
        print(json.dumps({"error": "Usage: python TCXDecode.py [--output parsed.json] [--pretty] [--compact] <tcx_or_tcx_gz_file>"}))
        return 1

    file_path = args[0]

    try:
        parsed = parse_tcx(file_path)
        if output_json:
            write_json(output_json, parsed, pretty=True if pretty else False)
        out = make_compact(parsed) if compact else parsed
        print(json.dumps(out, indent=2, ensure_ascii=False, default=json_safe))
        return 0
    except Exception as e:
        error_info = {
            "file": file_path,
            "parse_status": "FAILED",
            "error": str(e),
            "type": e.__class__.__name__
        }
        try:
            import traceback
            error_info["traceback"] = traceback.format_exc()
        except Exception:
            pass
        if output_json:
            try:
                write_json(output_json, error_info, pretty=True)
            except Exception:
                pass
        print(json.dumps(error_info, indent=2, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
