from __future__ import print_function

import argparse
import binascii
import datetime
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
import uuid

# Apple Health timestamps are seconds since 2001-01-01 00:00:00 UTC.
APPLE_EPOCH = datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)

DATA_TYPE_NAMES = {
    0: "Body Mass Index",
    2: "Height",
    3: "Body Mass",
    5: "Heart Rate",
    7: "Step Count",
    8: "Distance Walking/Running",
    9: "Energy / Exercise Quantity",
    10: "Energy Burned Quantity",
    12: "Flights / Activity Quantity",
    61: "Cardio Fitness / VO2-related Quantity",
    63: "Sleep Analysis",
    67: "Dietary Energy Consumed",
    70: "Mindful Session / Category",
    75: "Stand Hour / Activity Category",
    79: "Workout",
    102: "Workout Route",
    104: "Blood Pressure Systolic",
    105: "Blood Pressure Diastolic",
    116: "Audio Exposure Event / Category",
    118: "Respiratory Rate",
    124: "Body Temperature",
    137: "Walking Heart Rate Average",
    139: "VO2 Max",
    173: "Heart Rate Variability SDNN",
    182: "Walking Asymmetry / Mobility",
    183: "Dietary Water",
    186: "Mindful Minute / Duration",
    187: "Walking Double Support Percentage",
    188: "Walking Speed",
    194: "Headphone Audio Exposure",
    197: "Environmental Audio Exposure",
    249: "Apple Sleeping Wrist Temperature",
    274: "Running Speed",
}

# HKWorkoutActivityType values commonly observed in Apple Health databases.
WORKOUT_ACTIVITY_TYPES = {
    1: "American Football",
    2: "Archery",
    3: "Australian Football",
    4: "Badminton",
    5: "Baseball",
    6: "Basketball",
    7: "Bowling",
    8: "Boxing",
    9: "Climbing",
    10: "Cricket",
    11: "Cross Training",
    12: "Curling",
    13: "Cycling",
    14: "Dance",
    16: "Elliptical",
    17: "Equestrian Sports",
    18: "Fencing",
    19: "Fishing",
    20: "Functional Strength Training",
    21: "Golf",
    22: "Gymnastics",
    23: "Handball",
    24: "Hiking",
    25: "Hockey",
    26: "Hunting",
    27: "Lacrosse",
    28: "Martial Arts",
    29: "Mind and Body",
    30: "Mixed Metabolic Cardio Training",
    31: "Paddle Sports",
    32: "Play",
    33: "Preparation and Recovery",
    34: "Racquetball",
    35: "Rowing",
    36: "Rugby",
    37: "Running",
    38: "Sailing",
    39: "Skating Sports",
    40: "Snow Sports",
    41: "Soccer",
    42: "Softball",
    43: "Squash",
    44: "Stair Climbing",
    45: "Surfing Sports",
    46: "Swimming",
    47: "Table Tennis",
    48: "Tennis",
    49: "Track and Field",
    50: "Traditional Strength Training",
    51: "Volleyball",
    52: "Walking",
    53: "Water Fitness",
    54: "Water Polo",
    55: "Water Sports",
    56: "Wrestling",
    57: "Yoga",
    58: "Barre",
    59: "Core Training",
    60: "Cross Country Skiing",
    61: "Downhill Skiing",
    62: "Flexibility",
    63: "High Intensity Interval Training",
    64: "Jump Rope",
    65: "Kickboxing",
    66: "Pilates",
    67: "Snowboarding",
    68: "Stairs",
    69: "Step Training",
    70: "Wheelchair Walk Pace",
    71: "Wheelchair Run Pace",
    72: "Tai Chi",
    73: "Mixed Cardio",
    74: "Hand Cycling",
    75: "Disc Sports",
    76: "Fitness Gaming",
    77: "Cardio Dance",
    78: "Social Dance",
    79: "Pickleball",
    80: "Cooldown",
}

LOCATION_TYPES = {
    2: "Indoor",
    3: "Outdoor",
}

UNIT_ROWID_MAP = {
    1: "count/min",
    2: "count/s",
    3: "s",
    4: "cm",
    5: "km",
    6: "Cal",
}

GOAL_TYPES = {
    0: "Open",
    1: "Distance in meters",
    2: "Time in seconds",
    3: "Kilocalories",
}

ENERGY_DATA_TYPES = set([9, 10])

METADATA_KEY_ALIASES = {
    "average_mets": [
        "HKAverageMETs", "AverageMETs", "average mets", "mets",
    ],
    "heart_rate_min": [
        "_HKPrivateWorkoutMinHeartRate", "WorkoutMinHeartRate", "min heart rate",
    ],
    "heart_rate_max": [
        "_HKPrivateWorkoutMaxHeartRate", "WorkoutMaxHeartRate", "max heart rate",
    ],
    "heart_rate_avg": [
        "_HKPrivateWorkoutAverageHeartRate", "WorkoutAverageHeartRate", "average heart rate",
    ],
    "weather_temperature": [
        "HKWeatherTemperature", "WeatherTemperature", "weather temperature",
        "temperature",
    ],
    "weather_humidity": [
        "HKWeatherHumidity", "WeatherHumidity", "weather humidity", "humidity",
    ],
    "weather_latitude": [
        "_HKPrivateWorkoutWeatherLocationCoordinatesLatitude", "WorkoutWeatherLocationCoordinatesLatitude",
        "weather location coordinates latitude",
    ],
    "weather_longitude": [
        "_HKPrivateWorkoutWeatherLocationCoordinatesLongitude", "WorkoutWeatherLocationCoordinatesLongitude",
        "weather location coordinates longitude",
    ],
    "min_ground_elevation": [
        "_HKPrivateWorkoutMinGroundElevation", "WorkoutMinGroundElevation", "min ground elevation",
    ],
    "max_ground_elevation": [
        "_HKPrivateWorkoutMaxGroundElevation", "WorkoutMaxGroundElevation", "max ground elevation",
    ],
}

APPLE_DEVICE_MODELS = {
    "Watch1,1": "Apple Watch (1st generation, 38mm)",
    "Watch1,2": "Apple Watch (1st generation, 42mm)",
    "Watch2,3": "Apple Watch Series 2 (38mm)",
    "Watch2,4": "Apple Watch Series 2 (42mm)",
    "Watch2,6": "Apple Watch Series 1 (38mm)",
    "Watch2,7": "Apple Watch Series 1 (42mm)",
    "Watch3,1": "Apple Watch Series 3 (GPS + Cellular, 38mm)",
    "Watch3,2": "Apple Watch Series 3 (GPS + Cellular, 42mm)",
    "Watch3,3": "Apple Watch Series 3 (GPS, 38mm)",
    "Watch3,4": "Apple Watch Series 3 (GPS, 42mm)",
    "Watch4,1": "Apple Watch Series 4 (GPS, 40mm)",
    "Watch4,2": "Apple Watch Series 4 (GPS, 44mm)",
    "Watch4,3": "Apple Watch Series 4 (GPS + Cellular, 40mm)",
    "Watch4,4": "Apple Watch Series 4 (GPS + Cellular, 44mm)",
    "Watch5,1": "Apple Watch Series 5 (GPS, 40mm)",
    "Watch5,2": "Apple Watch Series 5 (GPS, 44mm)",
    "Watch5,3": "Apple Watch Series 5 (GPS + Cellular, 40mm)",
    "Watch5,4": "Apple Watch Series 5 (GPS + Cellular, 44mm)",
    "Watch5,9": "Apple Watch SE (GPS, 40mm)",
    "Watch5,10": "Apple Watch SE (GPS, 44mm)",
    "Watch5,11": "Apple Watch SE (GPS + Cellular, 40mm)",
    "Watch5,12": "Apple Watch SE (GPS + Cellular, 44mm)",
    "Watch6,1": "Apple Watch Series 6 (GPS, 40mm)",
    "Watch6,2": "Apple Watch Series 6 (GPS, 44mm)",
    "Watch6,3": "Apple Watch Series 6 (GPS + Cellular, 40mm)",
    "Watch6,4": "Apple Watch Series 6 (GPS + Cellular, 44mm)",
    "Watch6,6": "Apple Watch Series 7 (GPS, 41mm)",
    "Watch6,7": "Apple Watch Series 7 (GPS, 45mm)",
    "Watch6,8": "Apple Watch Series 7 (GPS + Cellular, 41mm)",
    "Watch6,9": "Apple Watch Series 7 (GPS + Cellular, 45mm)",
    "Watch6,10": "Apple Watch SE (2nd generation, GPS, 40mm)",
    "Watch6,11": "Apple Watch SE (2nd generation, GPS, 44mm)",
    "Watch6,12": "Apple Watch SE (2nd generation, GPS + Cellular, 40mm)",
    "Watch6,13": "Apple Watch SE (2nd generation, GPS + Cellular, 44mm)",
    "Watch6,14": "Apple Watch Series 8 (GPS, 41mm)",
    "Watch6,15": "Apple Watch Series 8 (GPS, 45mm)",
    "Watch6,16": "Apple Watch Series 8 (GPS + Cellular, 41mm)",
    "Watch6,17": "Apple Watch Series 8 (GPS + Cellular, 45mm)",
    "Watch6,18": "Apple Watch Ultra",
    "Watch7,1": "Apple Watch Series 9 (GPS, 41mm)",
    "Watch7,2": "Apple Watch Series 9 (GPS, 45mm)",
    "Watch7,3": "Apple Watch Series 9 (GPS + Cellular, 41mm)",
    "Watch7,4": "Apple Watch Series 9 (GPS + Cellular, 45mm)",
    "Watch7,5": "Apple Watch Ultra 2",
    "iPhone11,8": "iPhone XR",
    "iPhone11,2": "iPhone XS",
    "iPhone11,4": "iPhone XS Max",
    "iPhone11,6": "iPhone XS Max",
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
}


def safe_float(value):
    try:
        if value is None:
            return None
        f = float(value)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    except Exception:
        return None

# Apple Time conversion
def cf_time_to_iso(value):
    try:
        if value is None:
            return None
        return (APPLE_EPOCH + datetime.timedelta(seconds=float(value))).isoformat()
    except Exception:
        return None


def seconds_to_min(value):
    v = safe_float(value)
    if v is None:
        return None
    return v / 60.0


def seconds_to_hms(value):
    v = safe_float(value)
    if v is None:
        return None
    try:
        total = int(round(v))
        sign = "-" if total < 0 else ""
        total = abs(total)
        hours = total // 3600
        minutes = (total % 3600) // 60
        seconds = total % 60
        return "{}{:02d}:{:02d}:{:02d}".format(sign, hours, minutes, seconds)
    except Exception:
        return None


def m_to_km(value):
    v = safe_float(value)
    if v is None:
        return None
    return v / 1000.0


def m_to_miles(value):
    v = safe_float(value)
    if v is None:
        return None
    return v / 1609.344


def c_to_f(value):
    v = safe_float(value)
    if v is None:
        return None
    return (v * 9.0 / 5.0) + 32.0


def f_to_c(value):
    v = safe_float(value)
    if v is None:
        return None
    return (v - 32.0) * 5.0 / 9.0


def kelvin_to_c(value):
    v = safe_float(value)
    if v is None:
        return None
    return v - 273.15


def workout_total_distance_to_m(value):
    v = safe_float(value)
    if v is None:
        return None
    if abs(v) >= 1000:
        return v
    return v * 1000.0


def get_distance_from_statistics_m(stats):
    if not stats:
        return None
    for item in stats:
        try:
            if int(item.get("data_type")) == 8:
                v = safe_float(item.get("quantity"))
                if v is not None and v >= 0:
                    return v
        except Exception:
            pass
    return None


def choose_distance_m(total_distance_raw, stats):
    stat_m = get_distance_from_statistics_m(stats)
    if stat_m is not None:
        return stat_m, "workout_statistics.data_type_8"

    total_m = workout_total_distance_to_m(total_distance_raw)
    if total_m is not None:
        return total_m, "workouts.total_distance_normalized"

    return None, None


def kmh_from_distance_duration(distance_m, duration_s):
    d = safe_float(distance_m)
    t = safe_float(duration_s)
    if d is None or t is None or t <= 0:
        return None
    return (d / 1000.0) / (t / 3600.0)


def min_per_km(distance_m, duration_s):
    d = safe_float(distance_m)
    t = safe_float(duration_s)
    if d is None or t is None or d <= 0:
        return None
    return (t / 60.0) / (d / 1000.0)


def count_per_sec_to_bpm(value):
    v = safe_float(value)
    if v is None:
        return None
    return v * 60.0


def rounded(value, ndigits=6):
    v = safe_float(value)
    if v is None:
        return None
    return round(v, ndigits)


def blob_to_uuid(value):
    if value is None:
        return None
    try:
        b = bytes(value)
        if len(b) == 16:
            return str(uuid.UUID(bytes=b))
        return binascii.hexlify(b).decode("ascii")
    except Exception:
        try:
            return binascii.hexlify(value).decode("ascii")
        except Exception:
            return None


def blob_to_hex_preview(value, max_len=64):
    if value is None:
        return None
    try:
        h = binascii.hexlify(bytes(value)).decode("ascii")
        if len(h) > max_len:
            return h[:max_len] + "...[truncated]"
        return h
    except Exception:
        return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()



def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        return {
            "blob_size": len(b),
            "blob_hex_preview": blob_to_hex_preview(b),
        }
    return value

def compact_json(value, max_len):
    try:
        text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    except Exception:
        text = str(value)
    if text is None:
        return ""
    if len(text) > max_len:
        return text[:max_len] + "...[truncated]"
    return text


def metadata_lookup(metadata, aliases):
    if not metadata:
        return None
    lowered = []
    for key, value in metadata.items():
        try:
            lowered.append((str(key).lower(), value))
        except Exception:
            pass

    for alias in aliases:
        alias_l = str(alias).lower()
        for key_l, value in lowered:
            if alias_l == key_l or alias_l in key_l:
                return value
    return None


def extract_numeric_value(value):
    if value is None:
        return None
    v = safe_float(value)
    if v is not None:
        return v
    if isinstance(value, dict):
        for key in ["value", "quantity", "numerical_value", "number", "double", "float"]:
            if key in value:
                v = safe_float(value.get(key))
                if v is not None:
                    return v
        return None
    try:
        # Extract a number from strings such as "24.44 degC" or "76 F".
        m = re.search(r"[-+]?\d+(?:\.\d+)?", str(value))
        if m:
            return safe_float(m.group(0))
    except Exception:
        pass
    return None


def normalize_temperature_c(value):
    v = extract_numeric_value(value)
    if v is None:
        return None
    if v > 150:
        return kelvin_to_c(v)
    if v > 45:
        return f_to_c(v)
    return v


def normalize_humidity_percent(value):
    v = extract_numeric_value(value)
    if v is None:
        return None
    if 0 <= v <= 1:
        return v * 100.0
    return v


def goal_type_label(value):
    try:
        return GOAL_TYPES.get(int(value), "goal_type_{}".format(value))
    except Exception:
        return "" if value is None else "goal_type_{}".format(value)


def decode_device_model(product_type):
    if not product_type:
        return None
    return APPLE_DEVICE_MODELS.get(str(product_type), str(product_type))


class HealthSQLiteDecoder(object):
    def __init__(self, db_path, include_points=True, workout_limit=None, sample_limit=20, healthdb_path=None):
        self.db_path = db_path
        self.healthdb_path = healthdb_path
        self.include_points = include_points
        self.workout_limit = workout_limit
        self.sample_limit = sample_limit
        self.con = sqlite3.connect("file:{}?mode=ro".format(os.path.abspath(db_path)), uri=True)
        self.con.row_factory = sqlite3.Row
        self.cur = self.con.cursor()
        self.tables = set()
        self.unit_strings = {}
        self.healthdb_sources = {}
        self.healthdb_source_devices = {}

    def close(self):
        try:
            self.con.close()
        except Exception:
            pass

    def table_exists(self, table_name):
        return table_name in self.tables

    def load_schema(self):
        rows = self.cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        self.tables = set([r["name"] for r in rows])
        if self.table_exists("unit_strings"):
            try:
                for row in self.cur.execute("SELECT ROWID, unit_string FROM unit_strings"):
                    self.unit_strings[int(row["ROWID"])] = row["unit_string"]
            except Exception:
                self.unit_strings = dict(UNIT_ROWID_MAP)
        if not self.unit_strings:
            self.unit_strings = dict(UNIT_ROWID_MAP)
        self.load_healthdb_lookup()

    def load_healthdb_lookup(self):
        self.healthdb_sources = {}
        self.healthdb_source_devices = {}

        candidate = self.healthdb_path
        if not candidate:
            sibling = os.path.join(os.path.dirname(os.path.abspath(self.db_path)), "healthdb.sqlite")
            if os.path.exists(sibling):
                candidate = sibling

        if not candidate or not os.path.exists(candidate):
            return

        con2 = None
        try:
            con2 = sqlite3.connect("file:{}?mode=ro".format(os.path.abspath(candidate)), uri=True)
            con2.row_factory = sqlite3.Row
            cur2 = con2.cursor()

            try:
                for row in cur2.execute("SELECT ROWID, name FROM sources"):
                    self.healthdb_sources[int(row["ROWID"])] = {
                        "name": row["name"],
                    }
            except Exception:
                pass

            try:
                for row in cur2.execute("SELECT ROWID, name, manufacturer, model, hardware, software, firmware, localIdentifier FROM source_devices"):
                    self.healthdb_source_devices[int(row["ROWID"])] = {
                        "name": row["name"],
                        "manufacturer": row["manufacturer"],
                        "model": row["model"],
                        "hardware": row["hardware"],
                        "software": row["software"],
                        "firmware": row["firmware"],
                        "localIdentifier": row["localIdentifier"],
                    }
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try:
                if con2 is not None:
                    con2.close()
            except Exception:
                pass

    def scalar(self, sql, params=(), default=None):
        try:
            row = self.cur.execute(sql, params).fetchone()
            if row is None:
                return default
            return row[0]
        except Exception:
            return default

    def query(self, sql, params=()):
        try:
            return self.cur.execute(sql, params).fetchall()
        except Exception:
            return []

    def table_count(self, table_name):
        if not self.table_exists(table_name):
            return None
        return self.scalar('SELECT COUNT(*) FROM "{}"'.format(table_name), default=0)

    def schema_inventory(self):
        inventory = []
        rows = self.query("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name")
        for row in rows:
            name = row["name"]
            cols = []
            try:
                for c in self.cur.execute('PRAGMA table_info("{}")'.format(name)):
                    cols.append({
                        "name": c["name"],
                        "type": c["type"],
                        "not_null": c["notnull"],
                        "primary_key": c["pk"],
                    })
            except Exception:
                pass
            inventory.append({
                "table": name,
                "row_count": self.table_count(name),
                "columns": cols,
            })
        return inventory

    def table_counts(self):
        counts = {}
        for t in sorted(self.tables):
            counts[t] = self.table_count(t)
        return counts

    def data_type_label(self, data_type):
        try:
            dt = int(data_type)
            return DATA_TYPE_NAMES.get(dt, "data_type_{}".format(dt))
        except Exception:
            return "data_type_{}".format(data_type)

    def workout_activity_label(self, activity_type):
        try:
            at = int(activity_type)
            return WORKOUT_ACTIVITY_TYPES.get(at, "workout_activity_type_{}".format(at))
        except Exception:
            return "workout_activity_type_{}".format(activity_type)

    def location_type_label(self, location_type):
        if location_type is None:
            return None
        try:
            lt = int(location_type)
            return LOCATION_TYPES.get(lt, str(lt))
        except Exception:
            return str(location_type)

    def decode_unit(self, original_unit):
        if original_unit is None:
            return None
        try:
            unit_int = int(original_unit)
            return self.unit_strings.get(unit_int, str(original_unit))
        except Exception:
            return str(original_unit)

    def get_file_meta(self):
        return {
            "file_name": os.path.basename(self.db_path),
            "path": os.path.abspath(self.db_path),
            "size_bytes": os.path.getsize(self.db_path),
            "sha256": sha256_file(self.db_path),
        }

    def get_sqlite_meta(self):
        integrity = None
        try:
            integrity = self.scalar("PRAGMA quick_check", default=None)
        except Exception as e:
            integrity = "ERROR: {}".format(e)
        return {
            "integrity_check": integrity,
            "user_version": self.scalar("PRAGMA user_version", default=None),
            "schema_version": self.scalar("PRAGMA schema_version", default=None),
            "page_count": self.scalar("PRAGMA page_count", default=None),
            "page_size": self.scalar("PRAGMA page_size", default=None),
            "table_count": len(self.tables),
        }

    def get_summary(self):
        min_start = self.scalar("SELECT MIN(start_date) FROM samples" if self.table_exists("samples") else "SELECT NULL")
        max_end = self.scalar("SELECT MAX(end_date) FROM samples" if self.table_exists("samples") else "SELECT NULL")
        location_series_points = self.table_count("location_series_data") or 0
        race_route_points = self.table_count("RacePreviousRoute_location_series") or 0
        return {
            "database_kind": "Apple Health SQLite",
            "objects_count": self.table_count("objects"),
            "samples_count": self.table_count("samples"),
            "quantity_samples_count": self.table_count("quantity_samples"),
            "category_samples_count": self.table_count("category_samples"),
            "workouts_count": self.table_count("workouts"),
            "workout_activities_count": self.table_count("workout_activities"),
            "workout_events_count": self.table_count("workout_events"),
            "workout_statistics_count": self.table_count("workout_statistics"),
            "data_series_count": self.table_count("data_series"),
            "location_series_points_count": location_series_points,
            "race_previous_route_points_count": race_route_points,
            "total_route_points_count": location_series_points + race_route_points,
            "achievements_earned_count": self.table_count("ACHAchievementsPlugin_earned_instances"),
            "activity_caches_count": self.table_count("activity_caches"),
            "sleep_schedule_samples_count": self.table_count("sleep_schedule_samples"),
            "earliest_sample_time": cf_time_to_iso(min_start),
            "latest_sample_time": cf_time_to_iso(max_end),
        }

    def get_quantity_summary(self):
        if not (self.table_exists("samples") and self.table_exists("quantity_samples")):
            return []
        sql = """
        SELECT s.data_type,
               COUNT(*) AS sample_count,
               MIN(s.start_date) AS min_start,
               MAX(s.end_date) AS max_end,
               MIN(q.quantity) AS min_quantity,
               MAX(q.quantity) AS max_quantity,
               AVG(q.quantity) AS avg_quantity,
               GROUP_CONCAT(DISTINCT q.original_unit) AS original_units
        FROM samples s
        JOIN quantity_samples q ON q.data_id = s.data_id
        GROUP BY s.data_type
        ORDER BY sample_count DESC, s.data_type
        """
        out = []
        for row in self.query(sql):
            units = []
            if row["original_units"]:
                for u in str(row["original_units"]).split(","):
                    units.append({"raw": u, "decoded": self.decode_unit(u)})
            out.append({
                "data_type": row["data_type"],
                "data_type_label": self.data_type_label(row["data_type"]),
                "sample_count": row["sample_count"],
                "start_time_min": cf_time_to_iso(row["min_start"]),
                "end_time_max": cf_time_to_iso(row["max_end"]),
                "quantity_min": rounded(row["min_quantity"]),
                "quantity_max": rounded(row["max_quantity"]),
                "quantity_avg": rounded(row["avg_quantity"]),
                "original_units": units,
            })
        return out

    def get_category_summary(self):
        if not (self.table_exists("samples") and self.table_exists("category_samples")):
            return []
        sql = """
        SELECT s.data_type, c.value,
               COUNT(*) AS sample_count,
               MIN(s.start_date) AS min_start,
               MAX(s.end_date) AS max_end
        FROM samples s
        JOIN category_samples c ON c.data_id = s.data_id
        GROUP BY s.data_type, c.value
        ORDER BY sample_count DESC, s.data_type, c.value
        """
        out = []
        for row in self.query(sql):
            out.append({
                "data_type": row["data_type"],
                "data_type_label": self.data_type_label(row["data_type"]),
                "value": row["value"],
                "sample_count": row["sample_count"],
                "start_time_min": cf_time_to_iso(row["min_start"]),
                "end_time_max": cf_time_to_iso(row["max_end"]),
            })
        return out

    def get_activity_cache_summary(self):
        if not self.table_exists("activity_caches"):
            return {}
        cols = ["energy_burned", "move_minutes", "brisk_minutes", "active_hours", "steps", "walk_distance", "flights"]
        out = {
            "count": self.table_count("activity_caches"),
            "fields": {},
        }
        for col in cols:
            try:
                row = self.cur.execute(
                    'SELECT MIN({0}) AS min_v, MAX({0}) AS max_v, AVG({0}) AS avg_v FROM activity_caches'.format(col)
                ).fetchone()
                out["fields"][col] = {
                    "min": rounded(row["min_v"]),
                    "max": rounded(row["max_v"]),
                    "avg": rounded(row["avg_v"]),
                }
            except Exception:
                pass
        sample_rows = []
        try:
            sql = """
            SELECT ac.*, s.start_date, s.end_date
            FROM activity_caches ac
            LEFT JOIN samples s ON s.data_id = ac.data_id
            ORDER BY ac.cache_index DESC, ac.sequence DESC
            LIMIT ?
            """
            for row in self.cur.execute(sql, (self.sample_limit,)):
                d = dict(row)
                d["start_time"] = cf_time_to_iso(d.pop("start_date", None))
                d["end_time"] = cf_time_to_iso(d.pop("end_date", None))
                sample_rows.append(d)
        except Exception:
            pass
        out["sample_rows"] = sample_rows
        return out

    def get_metadata_for_object(self, object_id):
        if not (self.table_exists("metadata_values") and self.table_exists("metadata_keys")):
            return {}
        out = {}
        sql = """
        SELECT mk.key, mv.value_type, mv.string_value, mv.numerical_value,
               mv.date_value, mv.data_value
        FROM metadata_values mv
        LEFT JOIN metadata_keys mk ON mk.ROWID = mv.key_id
        WHERE mv.object_id = ?
        ORDER BY mk.key
        """
        for row in self.query(sql, (object_id,)):
            key = row["key"] or "metadata_key_unknown"
            value = None
            if row["string_value"] is not None:
                value = row["string_value"]
            elif row["numerical_value"] is not None:
                value = row["numerical_value"]
            elif row["date_value"] is not None:
                value = cf_time_to_iso(row["date_value"])
            elif row["data_value"] is not None:
                value = {
                    "blob_size": len(row["data_value"]),
                    "blob_hex_preview": blob_to_hex_preview(row["data_value"]),
                }
            out[key] = value
        return out

    def get_workout_routes_map(self):
        route_map = {}
        if not (self.table_exists("associations") and self.table_exists("data_series")):
            return route_map
        sql = """
        SELECT a.parent_id AS workout_data_id,
               ds.data_id AS route_data_id,
               ds.count AS expected_point_count,
               ds.hfd_key AS series_identifier,
               ds.series_location,
               ds.frozen,
               rs.start_date AS route_start_date,
               rs.end_date AS route_end_date
        FROM associations a
        JOIN data_series ds ON ds.data_id = a.child_id
        LEFT JOIN samples rs ON rs.data_id = ds.data_id
        ORDER BY a.parent_id, ds.hfd_key
        """
        for row in self.query(sql):
            wid = row["workout_data_id"]
            route_map.setdefault(wid, []).append(dict(row))
        return route_map

    def get_route_points(self, series_identifier, limit=None):
        if not self.table_exists("location_series_data"):
            return []
        sql = """
        SELECT timestamp, latitude, longitude, altitude, speed, course,
               horizontal_accuracy, vertical_accuracy, speed_accuracy,
               course_accuracy, signal_environment
        FROM location_series_data
        WHERE series_identifier = ?
        ORDER BY timestamp
        """
        params = [series_identifier]
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        points = []
        for row in self.query(sql, tuple(params)):
            points.append({
                "timestamp_raw": row["timestamp"],
                "time": cf_time_to_iso(row["timestamp"]),
                "lat": row["latitude"],
                "lon": row["longitude"],
                "altitude_m": row["altitude"],
                "speed_mps": row["speed"],
                "course": row["course"],
                "horizontal_accuracy_m": row["horizontal_accuracy"],
                "vertical_accuracy_m": row["vertical_accuracy"],
                "speed_accuracy": row["speed_accuracy"],
                "course_accuracy": row["course_accuracy"],
                "signal_environment": row["signal_environment"],
            })
        return points

    def summarize_points(self, points):
        if not points:
            return {
                "gps_points_count": 0,
                "track_points_sample": [],
            }
        lats = [p.get("lat") for p in points if p.get("lat") is not None]
        lons = [p.get("lon") for p in points if p.get("lon") is not None]
        alts = [p.get("altitude_m") for p in points if p.get("altitude_m") is not None]
        speeds = [p.get("speed_mps") for p in points if p.get("speed_mps") is not None]
        return {
            "gps_points_count": len(points),
            "start_lat": points[0].get("lat"),
            "start_lon": points[0].get("lon"),
            "start_gps_time": points[0].get("time"),
            "end_lat": points[-1].get("lat"),
            "end_lon": points[-1].get("lon"),
            "end_gps_time": points[-1].get("time"),
            "min_lat": min(lats) if lats else None,
            "max_lat": max(lats) if lats else None,
            "min_lon": min(lons) if lons else None,
            "max_lon": max(lons) if lons else None,
            "min_altitude_m": min(alts) if alts else None,
            "max_altitude_m": max(alts) if alts else None,
            "avg_altitude_m": (sum(alts) / float(len(alts))) if alts else None,
            "avg_speed_mps": (sum(speeds) / float(len(speeds))) if speeds else None,
            "avg_speed_kmh": ((sum(speeds) / float(len(speeds))) * 3.6) if speeds else None,
            "track_points_sample": points[:10],
        }

    def get_workout_statistics(self, workout_activity_id):
        if not self.table_exists("workout_statistics"):
            return []
        stats = []
        sql = """
        SELECT data_type, quantity, min, max
        FROM workout_statistics
        WHERE workout_activity_id = ?
        ORDER BY data_type
        """
        for row in self.query(sql, (workout_activity_id,)):
            data_type = row["data_type"]
            item = {
                "data_type": data_type,
                "data_type_label": self.data_type_label(data_type),
                "quantity": row["quantity"],
                "min": row["min"],
                "max": row["max"],
            }
            if data_type == 5:
                item["quantity_bpm"] = rounded(count_per_sec_to_bpm(row["quantity"]), 3)
                item["min_bpm"] = rounded(count_per_sec_to_bpm(row["min"]), 3)
                item["max_bpm"] = rounded(count_per_sec_to_bpm(row["max"]), 3)
            elif data_type == 8:
                item["distance_m"] = rounded(row["quantity"], 3)
                item["distance_km"] = rounded(m_to_km(row["quantity"]), 6)
            elif data_type in (9, 10):
                item["energy_quantity"] = row["quantity"]
            stats.append(item)
        return stats

    def get_workout_events(self, workout_id):
        if not self.table_exists("workout_events"):
            return []
        events = []
        sql = """
        SELECT date, type, duration, session_uuid, error
        FROM workout_events
        WHERE owner_id = ?
        ORDER BY date
        """
        for row in self.query(sql, (workout_id,)):
            events.append({
                "time": cf_time_to_iso(row["date"]),
                "date_raw": row["date"],
                "type": row["type"],
                "duration_sec": row["duration"],
                "session_uuid": blob_to_uuid(row["session_uuid"]),
                "error_blob_preview": blob_to_hex_preview(row["error"]),
            })
        return events

    def get_workouts(self):
        if not (self.table_exists("workouts") and self.table_exists("samples")):
            return []
        route_map = self.get_workout_routes_map()
        sql = """
        SELECT w.data_id, w.total_distance, w.goal_type, w.goal, w.condenser_version,
               w.condenser_date,
               s.start_date, s.end_date, s.data_type,
               o.uuid, o.creation_date, o.provenance,
               dp.origin_product_type, dp.origin_build, dp.local_product_type,
               dp.local_build, dp.source_id, dp.device_id, dp.source_version, dp.tz_name,
               wa.ROWID AS workout_activity_rowid, wa.uuid AS activity_uuid,
               wa.is_primary_activity, wa.activity_type, wa.location_type,
               wa.swimming_location_type, wa.start_date AS activity_start_date,
               wa.end_date AS activity_end_date, wa.duration AS activity_duration
        FROM workouts w
        JOIN samples s ON s.data_id = w.data_id
        LEFT JOIN objects o ON o.data_id = w.data_id
        LEFT JOIN data_provenances dp ON dp.ROWID = o.provenance
        LEFT JOIN workout_activities wa ON wa.owner_id = w.data_id
        ORDER BY s.start_date
        """
        if self.workout_limit is not None:
            sql += " LIMIT {}".format(int(self.workout_limit))
        workouts = []
        for row in self.query(sql):
            stats = self.get_workout_statistics(row["workout_activity_rowid"])
            distance_m, distance_source = choose_distance_m(row["total_distance"], stats)
            duration_s = row["activity_duration"] or (safe_float(row["end_date"]) - safe_float(row["start_date"]) if row["end_date"] is not None and row["start_date"] is not None else None)
            metadata = self.get_metadata_for_object(row["data_id"])
            source_lookup = self.healthdb_sources.get(row["source_id"], {}) if row["source_id"] is not None else {}
            device_lookup = self.healthdb_source_devices.get(row["device_id"], {}) if row["device_id"] is not None else {}

            workout = {
                "data_id": row["data_id"],
                "uuid": blob_to_uuid(row["uuid"]),
                "start_time": cf_time_to_iso(row["start_date"]),
                "end_time": cf_time_to_iso(row["end_date"]),
                "created_time": cf_time_to_iso(row["creation_date"]),
                "workout_data_type": row["data_type"],
                "workout_data_type_label": self.data_type_label(row["data_type"]),
                "activity_uuid": blob_to_uuid(row["activity_uuid"]),
                "activity_type": row["activity_type"],
                "activity_type_label": self.workout_activity_label(row["activity_type"]),
                "location_type": row["location_type"],
                "location_type_label": self.location_type_label(row["location_type"]),
                "is_primary_activity": row["is_primary_activity"],
                "duration_sec": duration_s,
                "duration_min": rounded(seconds_to_min(duration_s), 3),
                "total_distance_raw": row["total_distance"],
                "total_distance_source": distance_source,
                "total_distance_m": rounded(distance_m, 3),
                "total_distance_km": rounded(m_to_km(distance_m), 6),
                "average_speed_kmh": rounded(kmh_from_distance_duration(distance_m, duration_s), 3),
                "average_pace_min_per_km": rounded(min_per_km(distance_m, duration_s), 3),
                "goal_type": row["goal_type"],
                "goal": row["goal"],
                "condenser_version": row["condenser_version"],
                "condenser_date": cf_time_to_iso(row["condenser_date"]),
                "source": {
                    "provenance_rowid": row["provenance"],
                    "source_id": row["source_id"],
                    "source_name": source_lookup.get("name"),
                    "device_id": row["device_id"],
                    "device_name": device_lookup.get("name"),
                    "device_hardware": device_lookup.get("hardware"),
                    "device_manufacturer": device_lookup.get("manufacturer"),
                    "device_model_raw": device_lookup.get("model"),
                    "device_software": device_lookup.get("software"),
                    "source_version": row["source_version"],
                    "origin_product_type": row["origin_product_type"],
                    "origin_build": row["origin_build"],
                    "local_product_type": row["local_product_type"],
                    "local_build": row["local_build"],
                    "timezone": row["tz_name"],
                },
                "statistics": stats,
                "metadata": metadata,
                "events": self.get_workout_events(row["data_id"]),
                "routes": [],
            }

            for route in route_map.get(row["data_id"], []):
                points = self.get_route_points(route["series_identifier"])
                gps_summary = self.summarize_points(points)
                route_obj = {
                    "route_data_id": route["route_data_id"],
                    "series_identifier": route["series_identifier"],
                    "expected_point_count": route["expected_point_count"],
                    "series_location": route["series_location"],
                    "route_start_time": cf_time_to_iso(route["route_start_date"]),
                    "route_end_time": cf_time_to_iso(route["route_end_date"]),
                    "gps": gps_summary,
                }
                if self.include_points:
                    route_obj["track_points"] = points
                workout["routes"].append(route_obj)

            workout["statistics_summary"] = summarize_workout_statistics_for_compact(stats)
            workout["workout_details"] = create_workout_details(workout)

            workouts.append(workout)
        return workouts

    def get_race_previous_routes(self):
        if not (self.table_exists("RacePreviousRoute_location_series") and self.table_exists("RacePreviousRoute_workout")):
            return []
        routes = []
        sql = """
        SELECT rp.ROWID, rp.route_key, rp.workout_uuid, rp.date_to_delete,
               o.data_id AS workout_data_id,
               s.start_date AS workout_start_date,
               s.end_date AS workout_end_date
        FROM RacePreviousRoute_workout rp
        LEFT JOIN objects o ON o.uuid = rp.workout_uuid
        LEFT JOIN samples s ON s.data_id = o.data_id
        ORDER BY rp.ROWID
        """
        for row in self.query(sql):
            pts = []
            psql = """
            SELECT timestamp, latitude, longitude, altitude, distance, signal_type
            FROM RacePreviousRoute_location_series
            WHERE series_id = ?
            ORDER BY timestamp
            """
            for p in self.query(psql, (row["route_key"],)):
                pts.append({
                    "timestamp_offset_sec": p["timestamp"],
                    "lat": p["latitude"],
                    "lon": p["longitude"],
                    "altitude_m": p["altitude"],
                    "distance_m": p["distance"],
                    "signal_type": p["signal_type"],
                })
            gps_summary = self.summarize_points([
                {
                    "time": None,
                    "lat": p["lat"],
                    "lon": p["lon"],
                    "altitude_m": p["altitude_m"],
                    "speed_mps": None,
                }
                for p in pts
            ])
            route_obj = {
                "rowid": row["ROWID"],
                "route_key": row["route_key"],
                "workout_uuid": blob_to_uuid(row["workout_uuid"]),
                "workout_data_id": row["workout_data_id"],
                "workout_start_time": cf_time_to_iso(row["workout_start_date"]),
                "workout_end_time": cf_time_to_iso(row["workout_end_date"]),
                "date_to_delete": cf_time_to_iso(row["date_to_delete"]),
                "gps": gps_summary,
            }
            if self.include_points:
                route_obj["track_points"] = pts
            routes.append(route_obj)
        return routes

    def get_sources_summary(self):
        if not self.table_exists("data_provenances"):
            return []
        sql = """
        SELECT source_id, device_id, origin_product_type, local_product_type,
               source_version, tz_name, COUNT(*) AS provenance_rows
        FROM data_provenances
        GROUP BY source_id, device_id, origin_product_type, local_product_type, source_version, tz_name
        ORDER BY provenance_rows DESC, source_id, device_id
        """
        out = []
        for row in self.query(sql):
            out.append(dict(row))
        return out

    def get_recent_quantity_samples(self):
        if not (self.table_exists("samples") and self.table_exists("quantity_samples")):
            return []
        sql = """
        SELECT s.data_id, s.data_type, s.start_date, s.end_date,
               q.quantity, q.original_quantity, q.original_unit,
               o.uuid, o.creation_date,
               dp.source_id, dp.device_id, dp.source_version, dp.origin_product_type, dp.tz_name
        FROM samples s
        JOIN quantity_samples q ON q.data_id = s.data_id
        LEFT JOIN objects o ON o.data_id = s.data_id
        LEFT JOIN data_provenances dp ON dp.ROWID = o.provenance
        ORDER BY s.start_date DESC
        LIMIT ?
        """
        out = []
        for row in self.query(sql, (self.sample_limit,)):
            out.append({
                "data_id": row["data_id"],
                "uuid": blob_to_uuid(row["uuid"]),
                "data_type": row["data_type"],
                "data_type_label": self.data_type_label(row["data_type"]),
                "start_time": cf_time_to_iso(row["start_date"]),
                "end_time": cf_time_to_iso(row["end_date"]),
                "quantity": row["quantity"],
                "original_quantity": row["original_quantity"],
                "original_unit_raw": row["original_unit"],
                "original_unit": self.decode_unit(row["original_unit"]),
                "created_time": cf_time_to_iso(row["creation_date"]),
                "source": {
                    "source_id": row["source_id"],
                    "device_id": row["device_id"],
                    "source_version": row["source_version"],
                    "origin_product_type": row["origin_product_type"],
                    "timezone": row["tz_name"],
                },
            })
        return out

    def get_recent_category_samples(self):
        if not (self.table_exists("samples") and self.table_exists("category_samples")):
            return []
        sql = """
        SELECT s.data_id, s.data_type, s.start_date, s.end_date,
               c.value, o.uuid, o.creation_date,
               dp.source_id, dp.device_id, dp.source_version, dp.origin_product_type, dp.tz_name
        FROM samples s
        JOIN category_samples c ON c.data_id = s.data_id
        LEFT JOIN objects o ON o.data_id = s.data_id
        LEFT JOIN data_provenances dp ON dp.ROWID = o.provenance
        ORDER BY s.start_date DESC
        LIMIT ?
        """
        out = []
        for row in self.query(sql, (self.sample_limit,)):
            out.append({
                "data_id": row["data_id"],
                "uuid": blob_to_uuid(row["uuid"]),
                "data_type": row["data_type"],
                "data_type_label": self.data_type_label(row["data_type"]),
                "start_time": cf_time_to_iso(row["start_date"]),
                "end_time": cf_time_to_iso(row["end_date"]),
                "value": row["value"],
                "created_time": cf_time_to_iso(row["creation_date"]),
                "source": {
                    "source_id": row["source_id"],
                    "device_id": row["device_id"],
                    "source_version": row["source_version"],
                    "origin_product_type": row["origin_product_type"],
                    "timezone": row["tz_name"],
                },
            })
        return out

    def get_achievement_summary(self):
        if not self.table_exists("ACHAchievementsPlugin_earned_instances"):
            return []
        out = []
        sql = """
        SELECT template_unique_name, created_date, earned_date,
               value_in_canonical_unit, value_canonical_unit, external_identifier
        FROM ACHAchievementsPlugin_earned_instances
        ORDER BY created_date DESC
        LIMIT ?
        """
        for row in self.query(sql, (self.sample_limit,)):
            out.append({
                "template_unique_name": row["template_unique_name"],
                "created_time": cf_time_to_iso(row["created_date"]),
                "earned_date": row["earned_date"],
                "value_in_canonical_unit": row["value_in_canonical_unit"],
                "value_canonical_unit": row["value_canonical_unit"],
                "external_identifier": row["external_identifier"],
            })
        return out

    def get_global_gps_summary(self, workouts, race_routes):
        route_count = 0
        total_points = 0
        all_samples = []
        starts = []
        ends = []
        lats = []
        lons = []
        for w in workouts:
            for route in w.get("routes", []):
                route_count += 1
                gps = route.get("gps", {})
                total_points += gps.get("gps_points_count") or 0
                sample = gps.get("track_points_sample") or []
                all_samples.extend(sample[:3])
                if gps.get("start_gps_time"):
                    starts.append(gps.get("start_gps_time"))
                if gps.get("end_gps_time"):
                    ends.append(gps.get("end_gps_time"))
                for key in ["start_lat", "end_lat", "min_lat", "max_lat"]:
                    if gps.get(key) is not None:
                        lats.append(gps.get(key))
                for key in ["start_lon", "end_lon", "min_lon", "max_lon"]:
                    if gps.get(key) is not None:
                        lons.append(gps.get(key))
        for r in race_routes:
            route_count += 1
            gps = r.get("gps", {})
            total_points += gps.get("gps_points_count") or 0
            all_samples.extend((gps.get("track_points_sample") or [])[:3])
            for key in ["start_lat", "end_lat", "min_lat", "max_lat"]:
                if gps.get(key) is not None:
                    lats.append(gps.get(key))
            for key in ["start_lon", "end_lon", "min_lon", "max_lon"]:
                if gps.get(key) is not None:
                    lons.append(gps.get(key))
        return {
            "workout_route_count": route_count,
            "gps_points_count": total_points,
            "start_gps_time_min": min(starts) if starts else None,
            "end_gps_time_max": max(ends) if ends else None,
            "min_lat": min(lats) if lats else None,
            "max_lat": max(lats) if lats else None,
            "min_lon": min(lons) if lons else None,
            "max_lon": max(lons) if lons else None,
            "track_points_sample": all_samples[:20],
        }

    def decode(self):
        self.load_schema()
        quantity_summary = self.get_quantity_summary()
        category_summary = self.get_category_summary()
        workouts = self.get_workouts()
        race_routes = self.get_race_previous_routes()
        gps = self.get_global_gps_summary(workouts, race_routes)

        activity_type_counts = {}
        for w in workouts:
            label = w.get("activity_type_label") or "Unknown"
            activity_type_counts[label] = activity_type_counts.get(label, 0) + 1

        parsed = {
            "file": self.get_file_meta(),
            "sqlite": self.get_sqlite_meta(),
            "summary": self.get_summary(),
            "gps": gps,
            "quantity_summary": quantity_summary,
            "category_summary": category_summary,
            "workout_activity_type_counts": activity_type_counts,
            "workouts": workouts,
            "race_previous_routes": race_routes,
            "activity_cache_summary": self.get_activity_cache_summary(),
            "sources": self.get_sources_summary(),
            "recent_quantity_samples": self.get_recent_quantity_samples(),
            "recent_category_samples": self.get_recent_category_samples(),
            "earned_achievements_sample": self.get_achievement_summary(),
            "table_counts": self.table_counts(),
            "schema_inventory": self.schema_inventory(),
        }
        return parsed


def summarize_workout_gps_for_compact(workout, sample_limit=5):
    """Build a per-workout GPS summary without full track points."""
    routes = workout.get("routes", []) or []
    route_count = 0
    total_points = 0
    sample_points = []
    starts = []
    ends = []
    lats = []
    lons = []
    alts = []
    first_start_lat = None
    first_start_lon = None
    first_start_time = None
    last_end_lat = None
    last_end_lon = None
    last_end_time = None

    for route in routes:
        gps = route.get("gps", {}) or {}
        route_count += 1
        total_points += gps.get("gps_points_count") or 0

        if first_start_lat is None and gps.get("start_lat") is not None:
            first_start_lat = gps.get("start_lat")
            first_start_lon = gps.get("start_lon")
            first_start_time = gps.get("start_gps_time")

        if gps.get("end_lat") is not None:
            last_end_lat = gps.get("end_lat")
            last_end_lon = gps.get("end_lon")
            last_end_time = gps.get("end_gps_time")

        if gps.get("start_gps_time"):
            starts.append(gps.get("start_gps_time"))
        if gps.get("end_gps_time"):
            ends.append(gps.get("end_gps_time"))

        for key in ["start_lat", "end_lat", "min_lat", "max_lat"]:
            if gps.get(key) is not None:
                lats.append(gps.get(key))
        for key in ["start_lon", "end_lon", "min_lon", "max_lon"]:
            if gps.get(key) is not None:
                lons.append(gps.get(key))
        for key in ["min_altitude_m", "max_altitude_m", "avg_altitude_m"]:
            if gps.get(key) is not None:
                alts.append(gps.get(key))

        for point in (gps.get("track_points_sample") or []):
            if len(sample_points) < sample_limit:
                sample_points.append(point)

    return {
        "route_count": route_count,
        "gps_points_count": total_points,
        "start_gps_time": first_start_time or (min(starts) if starts else None),
        "end_gps_time": last_end_time or (max(ends) if ends else None),
        "start_lat": first_start_lat,
        "start_lon": first_start_lon,
        "end_lat": last_end_lat,
        "end_lon": last_end_lon,
        "min_lat": min(lats) if lats else None,
        "max_lat": max(lats) if lats else None,
        "min_lon": min(lons) if lons else None,
        "max_lon": max(lons) if lons else None,
        "min_altitude_m": min(alts) if alts else None,
        "max_altitude_m": max(alts) if alts else None,
        "track_points_sample": sample_points,
    }


def summarize_workout_statistics_for_compact(stats):
    """Extract common workout metrics for Autopsy/iLEAPP-style activity rows."""
    out = {
        "heart_rate_avg_bpm": None,
        "heart_rate_min_bpm": None,
        "heart_rate_max_bpm": None,
        "distance_m": None,
        "distance_km": None,
        "total_active_energy_kcal": None,
        "total_resting_energy_kcal": None,
        "average_mets": None,
        "energy_quantity": None,
        "energy_data_type": None,
        "energy_by_data_type": {},
    }

    for item in stats or []:
        try:
            data_type = int(item.get("data_type"))
        except Exception:
            data_type = None

        label = (item.get("data_type_label") or "").lower()
        quantity = safe_float(item.get("energy_quantity") if item.get("energy_quantity") is not None else item.get("quantity"))

        if data_type == 5:
            out["heart_rate_avg_bpm"] = item.get("quantity_bpm")
            out["heart_rate_min_bpm"] = item.get("min_bpm")
            out["heart_rate_max_bpm"] = item.get("max_bpm")
        elif data_type == 8:
            out["distance_m"] = item.get("distance_m")
            out["distance_km"] = item.get("distance_km")
        elif data_type in ENERGY_DATA_TYPES or "energy" in label or "cal" in label:
            if quantity is not None:
                out["energy_by_data_type"][str(data_type)] = quantity
                if data_type == 10:
                    out["total_active_energy_kcal"] = rounded(quantity, 3)
                elif data_type == 9:
                    out["total_resting_energy_kcal"] = rounded(quantity, 3)
                if out.get("energy_quantity") is None:
                    out["energy_quantity"] = quantity
                    out["energy_data_type"] = data_type
        elif "met" in label:
            out["average_mets"] = rounded(quantity, 3)

    return out


def create_workout_details(workout):
    """Build an iLEAPP-like flat details object for one workout/activity."""
    gps = summarize_workout_gps_for_compact(workout, sample_limit=5)
    stats = workout.get("statistics_summary") or summarize_workout_statistics_for_compact(workout.get("statistics", []))
    metadata = workout.get("metadata", {}) or {}
    source = workout.get("source", {}) or {}

    temp_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["weather_temperature"])
    temp_f = extract_numeric_value(temp_raw)
    temp_c = f_to_c(temp_f) if temp_f is not None else None

    humidity_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["weather_humidity"])
    humidity_percent = normalize_humidity_percent(humidity_raw)

    average_mets_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["average_mets"])
    average_mets = extract_numeric_value(average_mets_raw)
    if average_mets is None:
        average_mets = stats.get("average_mets")

    min_hr_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["heart_rate_min"])
    max_hr_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["heart_rate_max"])
    avg_hr_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["heart_rate_avg"])
    min_hr_value = extract_numeric_value(min_hr_raw)
    max_hr_value = extract_numeric_value(max_hr_raw)
    avg_hr_value = extract_numeric_value(avg_hr_raw)
    min_hr = count_per_sec_to_bpm(min_hr_value) if min_hr_value is not None else stats.get("heart_rate_min_bpm")
    max_hr = count_per_sec_to_bpm(max_hr_value) if max_hr_value is not None else stats.get("heart_rate_max_bpm")
    avg_hr = count_per_sec_to_bpm(avg_hr_value) if avg_hr_value is not None else stats.get("heart_rate_avg_bpm")

    lat_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["weather_latitude"])
    lon_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["weather_longitude"])
    min_elev_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["min_ground_elevation"])
    max_elev_raw = metadata_lookup(metadata, METADATA_KEY_ALIASES["max_ground_elevation"])
    latitude = extract_numeric_value(lat_raw)
    longitude = extract_numeric_value(lon_raw)
    min_elev = extract_numeric_value(min_elev_raw)
    max_elev = extract_numeric_value(max_elev_raw)
    if latitude is None:
        latitude = gps.get("start_lat")
    if longitude is None:
        longitude = gps.get("start_lon")
    if min_elev is None:
        min_elev = gps.get("min_altitude_m")
    if max_elev is None:
        max_elev = gps.get("max_altitude_m")

    distance_m = workout.get("total_distance_m")
    device_id = source.get("device_hardware") or source.get("origin_product_type") or source.get("local_product_type")
    device_model = decode_device_model(device_id)
    source_name = source.get("source_name") or source.get("source_id")

    return {
        "start_timestamp": workout.get("start_time"),
        "end_timestamp": workout.get("end_time"),
        "activity_type": workout.get("activity_type_label"),
        "activity_type_raw": workout.get("activity_type"),
        "location_type": workout.get("location_type_label"),
        "location_type_raw": workout.get("location_type"),
        "total_time_duration": seconds_to_hms(workout.get("duration_sec")),
        "duration": seconds_to_hms(workout.get("duration_sec")),
        "duration_sec": workout.get("duration_sec"),
        "duration_min": workout.get("duration_min"),
        "distance_km": rounded(m_to_km(distance_m), 2),
        "distance_miles": rounded(m_to_miles(distance_m), 2),
        "distance_m": rounded(distance_m, 3),
        "goal_type": goal_type_label(workout.get("goal_type")),
        "goal_type_raw": workout.get("goal_type"),
        "goal": workout.get("goal"),
        "total_active_energy_kcal": stats.get("total_active_energy_kcal"),
        "total_resting_energy_kcal": stats.get("total_resting_energy_kcal"),
        "average_mets": rounded(average_mets, 3),
        "min_heart_rate_bpm": rounded(min_hr, 0),
        "max_heart_rate_bpm": rounded(max_hr, 0),
        "average_heart_rate_bpm": rounded(avg_hr, 0),
        "temperature_c": rounded(temp_c, 2),
        "temperature_f": rounded(temp_f, 2),
        "humidity_percent": rounded(humidity_percent, 2),
        "latitude": latitude,
        "longitude": longitude,
        "min_ground_elevation_m": rounded(min_elev, 2),
        "max_ground_elevation_m": rounded(max_elev, 2),
        "device_id": device_id,
        "device_rowid": source.get("device_id"),
        "device_model": device_model,
        "source": source_name,
        "software_version": source.get("source_version"),
        "timezone": source.get("timezone"),
        "timestamp_added_to_health": workout.get("created_time"),
        "metadata_weather_temperature_raw": temp_raw,
        "metadata_weather_humidity_raw": humidity_raw,
        "metadata_average_mets_raw": average_mets_raw,
        "metadata_min_heart_rate_raw": min_hr_raw,
        "metadata_max_heart_rate_raw": max_hr_raw,
        "metadata_average_heart_rate_raw": avg_hr_raw,
        "metadata_latitude_raw": lat_raw,
        "metadata_longitude_raw": lon_raw,
        "metadata_min_ground_elevation_raw": min_elev_raw,
        "metadata_max_ground_elevation_raw": max_elev_raw,
    }


def safe_filename_part(value, fallback="unknown"):
    """Return a filesystem-safe filename component."""
    text = "" if value is None else str(value)
    text = text.strip()
    if not text:
        text = fallback
    text = text.replace("+00:00", "Z")
    text = text.replace(":", "-")
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._-")
    if not text:
        text = fallback
    return text[:80]


def make_activity_json_filename(workout, index):
    """Create a stable per-activity JSON filename similar to FIT/TCX activity JSON output."""
    data_id = safe_filename_part(workout.get("data_id"), "data_id_unknown")
    activity = safe_filename_part(workout.get("activity_type_label"), "activity")
    start = safe_filename_part(workout.get("start_time"), "no_start_time")
    return "{0:04d}_{1}_{2}_{3}.json".format(int(index), data_id, start, activity)


def write_activity_json_files(parsed, activity_output_dir, parent_json_path=None, pretty=False):
    """
    Write one JSON file per Apple Health workout/activity.

    The database-level JSON still contains the entire parsed database. These
    per-activity JSON files are easier to inspect and mirror the FIT/TCX design:
    one activity file contains one activity record plus its full GPS track_points.
    """
    if not activity_output_dir:
        return []

    abs_dir = os.path.abspath(activity_output_dir)
    if not os.path.exists(abs_dir):
        os.makedirs(abs_dir)

    manifest = []
    workouts = parsed.get("workouts", []) or []
    source_file = parsed.get("file", {}) or {}

    for idx, workout in enumerate(workouts, start=1):
        filename = make_activity_json_filename(workout, idx)
        path = os.path.join(abs_dir, filename)
        compact = make_compact_workout(workout)

        activity_doc = {
            "activity_index": idx,
            "activity_json_path": path,
            "parent_database_json_path": parent_json_path,
            "sqlite_file": source_file,
            "sqlite": parsed.get("sqlite", {}),
            "summary": {
                "data_id": workout.get("data_id"),
                "uuid": workout.get("uuid"),
                "activity_uuid": workout.get("activity_uuid"),
                "activity_type": workout.get("activity_type_label"),
                "location_type": workout.get("location_type_label"),
                "start_time": workout.get("start_time"),
                "end_time": workout.get("end_time"),
                "created_time": workout.get("created_time"),
                "duration_sec": workout.get("duration_sec"),
                "duration_min": workout.get("duration_min"),
                "distance_km": workout.get("total_distance_km"),
                "gps_points_count": (compact.get("gps") or {}).get("gps_points_count"),
                "route_count": (compact.get("gps") or {}).get("route_count"),
            },
            "workout_details": compact.get("workout_details", {}),
            "statistics_summary": compact.get("statistics_summary", {}),
            "gps": compact.get("gps", {}),
            "workout": workout,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(activity_doc, f, indent=2 if pretty else None, sort_keys=False, ensure_ascii=False)

        workout["activity_json_path"] = path
        if isinstance(workout.get("workout_details"), dict):
            workout["workout_details"]["activity_json_path"] = path

        manifest.append({
            "activity_index": idx,
            "data_id": workout.get("data_id"),
            "uuid": workout.get("uuid"),
            "activity_uuid": workout.get("activity_uuid"),
            "activity_type": workout.get("activity_type_label"),
            "start_time": workout.get("start_time"),
            "end_time": workout.get("end_time"),
            "gps_points_count": (compact.get("gps") or {}).get("gps_points_count"),
            "activity_json_path": path,
        })

    parsed["activity_json_output_dir"] = abs_dir
    parsed["activity_json_files"] = manifest
    try:
        parsed.setdefault("summary", {})["activity_json_files_count"] = len(manifest)
    except Exception:
        pass
    return manifest

def make_compact_workout(workout):
    """Return one lightweight workout/activity row for Autopsy blackboard use."""
    gps = summarize_workout_gps_for_compact(workout, sample_limit=5)
    stats_summary = workout.get("statistics_summary") or summarize_workout_statistics_for_compact(workout.get("statistics", []))
    workout_details = workout.get("workout_details") or create_workout_details(workout)

    route_summaries = []
    for route in workout.get("routes", []) or []:
        route_gps = route.get("gps", {}) or {}
        route_summaries.append({
            "route_data_id": route.get("route_data_id"),
            "series_identifier": route.get("series_identifier"),
            "expected_point_count": route.get("expected_point_count"),
            "route_start_time": route.get("route_start_time"),
            "route_end_time": route.get("route_end_time"),
            "gps_points_count": route_gps.get("gps_points_count"),
            "start_lat": route_gps.get("start_lat"),
            "start_lon": route_gps.get("start_lon"),
            "end_lat": route_gps.get("end_lat"),
            "end_lon": route_gps.get("end_lon"),
        })

    return {
        "data_id": workout.get("data_id"),
        "uuid": workout.get("uuid"),
        "activity_uuid": workout.get("activity_uuid"),
        "activity_type": workout.get("activity_type"),
        "activity_type_label": workout.get("activity_type_label"),
        "location_type": workout.get("location_type"),
        "location_type_label": workout.get("location_type_label"),
        "is_primary_activity": workout.get("is_primary_activity"),
        "start_time": workout.get("start_time"),
        "end_time": workout.get("end_time"),
        "created_time": workout.get("created_time"),
        "duration_sec": workout.get("duration_sec"),
        "duration_min": workout.get("duration_min"),
        "duration_hms": workout_details.get("duration"),
        "total_distance_raw": workout.get("total_distance_raw"),
        "total_distance_source": workout.get("total_distance_source"),
        "total_distance_m": workout.get("total_distance_m"),
        "total_distance_km": workout.get("total_distance_km"),
        "total_distance_miles": workout_details.get("distance_miles"),
        "average_speed_kmh": workout.get("average_speed_kmh"),
        "average_pace_min_per_km": workout.get("average_pace_min_per_km"),
        "goal_type": workout.get("goal_type"),
        "goal_type_label": workout_details.get("goal_type"),
        "goal": workout.get("goal"),
        "workout_details": workout_details,
        "source": workout.get("source", {}),
        "statistics_summary": stats_summary,
        "route_count": gps.get("route_count"),
        "gps": gps,
        "routes": route_summaries,
        "activity_json_path": workout.get("activity_json_path"),
    }


def make_compact(parsed):
    summary = parsed.get("summary", {})
    gps = parsed.get("gps", {})
    workouts = parsed.get("workouts", []) or []
    compact_workouts = [make_compact_workout(w) for w in workouts]

    return {
        "file": parsed.get("file", {}),
        "sqlite": parsed.get("sqlite", {}),
        "summary": summary,
        "gps": gps,
        "quantity_summary": parsed.get("quantity_summary", [])[:30],
        "category_summary": parsed.get("category_summary", [])[:30],
        "workout_activity_type_counts": parsed.get("workout_activity_type_counts", {}),
        "workouts": compact_workouts,
        "workouts_sample": compact_workouts[:5],
        "activity_json_output_dir": parsed.get("activity_json_output_dir"),
        "activity_json_files": parsed.get("activity_json_files", []),
        "recent_quantity_samples": parsed.get("recent_quantity_samples", [])[:10],
        "recent_category_samples": parsed.get("recent_category_samples", [])[:10],
        "table_counts": parsed.get("table_counts", {}),
    }


def print_json_stdout(obj, pretty=False):
    text = json.dumps(
        obj,
        indent=2 if pretty else None,
        sort_keys=False,
        ensure_ascii=True,
    )
    try:
        sys.stdout.write(text + "\n")
    except UnicodeEncodeError:
        sys.stdout.buffer.write((text + "\n").encode("ascii", "backslashreplace"))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decode Apple Health healthdb SQLite into JSON.")
    parser.add_argument("db_path", help="Path to healthdb_secure.sqlite / healthdb SQLite file")
    parser.add_argument("--output", help="Write full JSON to this path")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print output JSON")
    parser.add_argument("--compact", action="store_true", help="Print compact JSON to stdout")
    parser.add_argument("--no-points", action="store_true", help="Do not include full route points in full JSON")
    parser.add_argument("--workout-limit", type=int, default=None, help="Optional maximum number of workouts to include")
    parser.add_argument("--sample-limit", type=int, default=20, help="Number of recent/sample rows to include")
    parser.add_argument("--healthdb", default=None, help="Optional companion healthdb.sqlite path for iLEAPP-style source/device labels")
    parser.add_argument("--activity-output-dir", default=None, help="Optional directory where one JSON file per workout/activity will be written")
    args = parser.parse_args(argv)

    decoder = None
    try:
        decoder = HealthSQLiteDecoder(
            args.db_path,
            include_points=(not args.no_points),
            workout_limit=args.workout_limit,
            sample_limit=args.sample_limit,
            healthdb_path=args.healthdb,
        )
        parsed = json_safe(decoder.decode())

        if args.activity_output_dir:
            write_activity_json_files(
                parsed,
                args.activity_output_dir,
                parent_json_path=os.path.abspath(args.output) if args.output else None,
                pretty=args.pretty,
            )

        if args.output:
            parent = os.path.dirname(os.path.abspath(args.output))
            if parent and not os.path.exists(parent):
                os.makedirs(parent)
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2 if args.pretty else None, sort_keys=False, ensure_ascii=False)

        out_obj = make_compact(parsed) if args.compact else parsed
        print_json_stdout(out_obj, pretty=(args.pretty and not args.compact))
        return 0

    except Exception as e:
        err = {
            "error": str(e),
            "file": {
                "file_name": os.path.basename(args.db_path) if args.db_path else None,
                "path": os.path.abspath(args.db_path) if args.db_path else None,
            },
        }
        try:
            import traceback
            err["traceback"] = traceback.format_exc()
        except Exception:
            pass
        if args.output:
            try:
                parent = os.path.dirname(os.path.abspath(args.output))
                if parent and not os.path.exists(parent):
                    os.makedirs(parent)
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(err, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
        print_json_stdout(err, pretty=False)
        return 1
    finally:
        if decoder is not None:
            decoder.close()


if __name__ == "__main__":
    sys.exit(main())
