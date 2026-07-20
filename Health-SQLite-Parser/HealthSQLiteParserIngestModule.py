import os
import json
import subprocess
import traceback
import inspect
import re

from java.io import File
from java.util import ArrayList
from java.util.logging import Level
from java.lang import System, String

from org.sleuthkit.autopsy.ingest import (
    IngestModule, IngestMessage, IngestServices,
    DataSourceIngestModule, IngestModuleFactoryAdapter, ModuleDataEvent
)
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.datamodel import BlackboardAttribute


class HealthSQLiteIngestFactory(IngestModuleFactoryAdapter):
    moduleName = "Apple Health SQLite Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses Apple Health SQLite files, saves database JSON plus one JSON file per workout/activity, and creates database summary plus activity artifacts."

    def getModuleVersionNumber(self):
        return "1.3"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return HealthSQLiteIngestModule()


class HealthSQLiteIngestModule(DataSourceIngestModule):

    def __init__(self):
        self.logger = IngestServices.getInstance().getLogger(HealthSQLiteIngestFactory.moduleName)

    def log(self, level, msg):
        self.logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.context = context
        self.services = IngestServices.getInstance()
        self.moduleNameStr = String(HealthSQLiteIngestFactory.moduleName)

        self.log(Level.INFO, "[Startup] Apple Health SQLite Parser initialized.")
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                HealthSQLiteIngestFactory.moduleName,
                "Module initialized successfully."
            )
        )

    def safe_str(self, value):
        if value is None:
            return ""
        try:
            return str(value)
        except Exception:
            try:
                return unicode(value)
            except Exception:
                return ""

    def compact_json(self, value, max_len):
        try:
            text = json.dumps(value, sort_keys=True)
        except Exception:
            text = self.safe_str(value)
        if text is None:
            return ""
        if len(text) > max_len:
            return text[:max_len] + "...[truncated]"
        return text

    def sanitize_filename(self, name):
        try:
            return re.sub(r"[^A-Za-z0-9._-]+", "_", self.safe_str(name))
        except Exception:
            return "health_sqlite"

    def make_json_filename(self, db_name):
        name = self.safe_str(db_name).strip()
        lower_name = name.lower()

        for suffix in [".sqlite", ".sqlite3", ".db", ".database"]:
            if lower_name.endswith(suffix):
                name = name[:-len(suffix)]
                break

        name = self.sanitize_filename(name)
        if not name:
            name = "health_sqlite"

        return "{}.json".format(name)

    def get_source_path(self, f):
        try:
            return "{}{}".format(f.getParentPath(), f.getName())
        except Exception:
            return self.safe_str(f.getName())

    def get_parent_path(self, f):
        try:
            return self.safe_str(f.getParentPath())
        except Exception:
            return ""

    def copy_sqlite_sidecars(self, fileManager, dataSource, source_file, local_db):
        copied = []
        parent_path = self.get_parent_path(source_file)
        base_name = self.safe_str(source_file.getName())

        for suffix in ["-wal", "-shm", ".journal", "-journal"]:
            sidecar_name = base_name + suffix
            try:
                candidates = fileManager.findFiles(dataSource, sidecar_name)
                for candidate in candidates:
                    if self.get_parent_path(candidate) != parent_path:
                        continue
                    local_sidecar = local_db + suffix
                    ContentUtils.writeToFile(candidate, File(local_sidecar))
                    copied.append(local_sidecar)
                    self.log(Level.INFO, "[Copy] Saved SQLite sidecar: {}".format(local_sidecar))
                    break
            except Exception as e:
                self.log(Level.INFO, "[Copy] Sidecar {} not copied: {}".format(sidecar_name, e))

        return copied

    def copy_companion_healthdb(self, fileManager, dataSource, source_file, case_temp):
        try:
            if self.safe_str(source_file.getName()).lower() != "healthdb_secure.sqlite":
                return None

            parent_path = self.get_parent_path(source_file)
            candidates = fileManager.findFiles(dataSource, "healthdb.sqlite")
            for candidate in candidates:
                try:
                    if self.get_parent_path(candidate) != parent_path:
                        continue
                    local_healthdb = os.path.join(case_temp, "{}_healthdb.sqlite".format(source_file.getId()))
                    ContentUtils.writeToFile(candidate, File(local_healthdb))
                    self.copy_sqlite_sidecars(fileManager, dataSource, candidate, local_healthdb)
                    self.log(Level.INFO, "[Copy] Saved companion healthdb.sqlite for iLEAPP source/device labels: {}".format(local_healthdb))
                    return local_healthdb
                except Exception as e:
                    self.log(Level.INFO, "[Copy] Failed to copy companion healthdb.sqlite candidate: {}".format(e))
            return None
        except Exception as e:
            self.log(Level.INFO, "[Copy] Companion healthdb.sqlite not available: {}".format(e))
            return None

    def find_python_executable(self):
        env_path = os.getenv("HEALTH_SQLITE_PARSER_PYTHON")
        if env_path and os.path.exists(env_path):
            self.log(Level.INFO, "[Python] Using path from HEALTH_SQLITE_PARSER_PYTHON: {}".format(env_path))
            return env_path

        # Reuse the FIT/TCX parser variable if you already configured it.
        env_path = os.getenv("FIT_PARSER_PYTHON")
        if env_path and os.path.exists(env_path):
            self.log(Level.INFO, "[Python] Using path from FIT_PARSER_PYTHON: {}".format(env_path))
            return env_path

        env_path = os.getenv("TCX_PARSER_PYTHON")
        if env_path and os.path.exists(env_path):
            self.log(Level.INFO, "[Python] Using path from TCX_PARSER_PYTHON: {}".format(env_path))
            return env_path

        try:
            output = subprocess.check_output(["py", "-0p"], stderr=subprocess.STDOUT)
            try:
                output = output.decode("utf-8")
            except Exception:
                pass
            for line in output.splitlines():
                line = line.strip()
                if ".exe" in line:
                    exe_path = line.split()[-1].strip()
                    if os.path.exists(exe_path):
                        self.log(Level.INFO, "[Python] Auto-detected via py launcher: {}".format(exe_path))
                        os.environ["HEALTH_SQLITE_PARSER_PYTHON"] = exe_path
                        return exe_path
        except Exception as e:
            self.log(Level.WARNING, "[Python] 'py -0p' detection failed: {}".format(e))

        for name in ["python3", "python"]:
            for d in os.getenv("PATH", "").split(os.pathsep):
                candidate = os.path.join(d, name)
                if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                    try:
                        out = subprocess.check_output([candidate, "--version"], stderr=subprocess.STDOUT)
                        try:
                            out = out.decode("utf-8")
                        except Exception:
                            pass
                        if "Python 3" in out:
                            self.log(Level.INFO, "[Python] Found in PATH: {}".format(candidate))
                            return candidate
                    except Exception:
                        pass

        os_name = System.getProperty("os.name").lower()
        if "win" in os_name:
            poss = [
                r"C:\Python312\python.exe", r"C:\Python311\python.exe", r"C:\Python310\python.exe",
                r"C:\Program Files\Python312\python.exe", r"C:\Program Files\Python311\python.exe",
                r"C:\ProgramData\Anaconda3\python.exe", r"C:\Users\Public\anaconda3\python.exe"
            ]
        elif "mac" in os_name:
            poss = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        else:
            poss = ["/usr/bin/python3", "/usr/local/bin/python3", "/bin/python3"]

        for p in poss:
            if os.path.exists(p):
                self.log(Level.INFO, "[Python] Found in known path: {}".format(p))
                return p

        self.log(Level.SEVERE, "[Python] No valid Python 3 interpreter found.")
        return None

    def get_json_output_dir(self, case_obj, case_temp):
        case_dir = ""

        try:
            case_dir = self.safe_str(case_obj.getCaseDirectory())
        except Exception as e:
            self.log(Level.WARNING, "[JSON] Failed to get case directory: {}".format(e))

        if not case_dir:
            try:
                case_dir = os.path.dirname(self.safe_str(case_temp))
            except Exception:
                case_dir = self.safe_str(case_temp)

        json_output_dir = os.path.join(case_dir, "Reports", "Apple_Health_SQLite_JSON")

        try:
            if not os.path.exists(json_output_dir):
                os.makedirs(json_output_dir)
            self.log(Level.INFO, "[JSON] Output directory: {}".format(json_output_dir))
        except Exception as e:
            self.log(Level.SEVERE, "[JSON] Failed to create output directory: {}".format(e))

        return json_output_dir


    def get_activity_json_output_dir(self, case_obj, case_temp):
        case_dir = ""
        try:
            case_dir = self.safe_str(case_obj.getCaseDirectory())
        except Exception as e:
            self.log(Level.WARNING, "[JSON] Failed to get case directory for activity JSON: {}".format(e))

        if not case_dir:
            try:
                case_dir = os.path.dirname(self.safe_str(case_temp))
            except Exception:
                case_dir = self.safe_str(case_temp)

        activity_json_dir = os.path.join(case_dir, "Reports", "Apple_Health_Workout_Activity_JSON")
        try:
            if not os.path.exists(activity_json_dir):
                os.makedirs(activity_json_dir)
            self.log(Level.INFO, "[JSON] Activity JSON output directory: {}".format(activity_json_dir))
        except Exception as e:
            self.log(Level.SEVERE, "[JSON] Failed to create activity JSON output directory: {}".format(e))
        return activity_json_dir

    def write_error_json(self, json_path, data):
        try:
            parent_dir = os.path.dirname(json_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir)

            with open(json_path, "wb") as dbg:
                try:
                    dbg.write(json.dumps(data, indent=2).encode("utf-8"))
                except Exception:
                    dbg.write(json.dumps(data, indent=2))
            return True
        except Exception as e:
            self.log(Level.SEVERE, "[JSON] Failed to write error JSON {}: {}".format(json_path, e))
            return False

    def add_json_report(self, case_obj, json_path, db_name):
        try:
            if os.path.exists(json_path):
                case_obj.addReport(
                    json_path,
                    HealthSQLiteIngestFactory.moduleName,
                    "Parsed Apple Health SQLite JSON - {}".format(db_name)
                )
                self.log(Level.INFO, "[Report] Added JSON report: {}".format(json_path))
        except Exception as e:
            self.log(Level.WARNING, "[Report] Failed to add JSON report: {}".format(e))

    def decode_process_output(self, data):
        if data is None:
            return ""

        for enc in ["utf-8", "utf-8-sig", "cp1252", "latin-1"]:
            try:
                return data.decode(enc)
            except Exception:
                pass

        try:
            return data.decode("utf-8", "replace")
        except Exception:
            try:
                return str(data)
            except Exception:
                return ""

    def extract_json_object(self, text):
        if text is None:
            return ""
        cleaned = text.strip()
        if cleaned.startswith("{") or cleaned.startswith("["):
            return cleaned

        first_obj = cleaned.find("{")
        first_arr = cleaned.find("[")
        starts = [x for x in [first_obj, first_arr] if x >= 0]
        if starts:
            return cleaned[min(starts):].strip()
        return cleaned

    def run_decoder(self, python_exec, decode_path, local_db, json_path, healthdb_path=None, activity_json_dir=None):
        # Decoder writes full JSON to json_path and returns compact JSON on stdout.
        # Full workout route points remain in the JSON report, not in the blackboard.
        cmd = [python_exec, decode_path, "--output", json_path, "--pretty", "--compact"]
        if healthdb_path and os.path.exists(healthdb_path):
            cmd.extend(["--healthdb", healthdb_path])
        if activity_json_dir:
            cmd.extend(["--activity-output-dir", activity_json_dir])
        cmd.append(local_db)
        self.log(Level.INFO, "[Decode] Running command: {}".format(" ".join(cmd)))

        env = os.environ.copy()
        # Force Python stdout/stderr to UTF-8. The decoder also uses ASCII-only
        # JSON on stdout, but this keeps tracebacks and warning messages safer.
        env["PYTHONIOENCODING"] = "utf-8"

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        out, err = proc.communicate()

        out_text = self.decode_process_output(out)
        err_text = self.decode_process_output(err)

        if err_text:
            self.log(Level.INFO, "[Decode STDERR] {}".format(err_text[:2000]))

        if not out_text or not out_text.strip():
            raise Exception("Decoder returned no stdout. STDERR: {}".format(err_text[:1000]))

        try:
            return json.loads(self.extract_json_object(out_text))
        except Exception:
            self.log(Level.SEVERE, "[Decode STDOUT preview] {}".format(out_text[:2000]))
            raise

    def find_health_sqlite(self, fileManager, dataSource):
        db_files = []
        seen_ids = set()

        patterns = [
            "%healthdb%", "%Health%", "%health%",
            "%.sqlite", "%.SQLITE", "%.sqlite%", "%.SQLITE%",
            "%.sqlite3", "%.SQLITE3", "%.db", "%.DB", "%.db%", "%.DB%"
        ]

        skip_suffixes = ["-wal", "-shm", ".journal", "-journal"]

        for pattern in patterns:
            try:
                found = fileManager.findFiles(dataSource, pattern)
                for ff in found:
                    name = self.safe_str(ff.getName()).lower()
                    source_path = self.get_source_path(ff).lower()

                    skip = False
                    for suffix in skip_suffixes:
                        if name.endswith(suffix):
                            skip = True
                            break
                    if skip:
                        continue

                    is_sqlite_name = (".sqlite" in name or name.endswith(".db") or ".db" in name)
                    looks_health = ("healthdb" in name or "health" in name or "/health/" in source_path)

                    if not (is_sqlite_name and looks_health):
                        continue

                    fid = ff.getId()
                    if fid not in seen_ids:
                        db_files.append(ff)
                        seen_ids.add(fid)
            except Exception as e:
                self.log(Level.WARNING, "[FindFiles] Pattern {} failed: {}".format(pattern, e))

        secure_by_parent = set()
        for ff in db_files:
            if self.safe_str(ff.getName()).lower() == "healthdb_secure.sqlite":
                secure_by_parent.add(self.get_parent_path(ff))

        prioritized = []
        seen_ids2 = set()

        def add_candidate(ff):
            fid = ff.getId()
            if fid not in seen_ids2:
                prioritized.append(ff)
                seen_ids2.add(fid)

        for ff in db_files:
            if self.safe_str(ff.getName()).lower() == "healthdb_secure.sqlite":
                add_candidate(ff)

        for ff in db_files:
            name = self.safe_str(ff.getName()).lower()
            parent = self.get_parent_path(ff)
            if name == "healthdb.sqlite" and parent in secure_by_parent:
                self.log(Level.INFO, "[FindFiles] Skipping healthdb.sqlite because healthdb_secure.sqlite exists in the same folder: {}".format(parent))
                continue
            add_candidate(ff)

        return prioritized

    def add_artifact_type(self, skCase, type_name, display_name):
        try:
            return skCase.addArtifactType(type_name, display_name)
        except Exception:
            return skCase.getArtifactTypeID(type_name)

    def add_string_attr(self, skCase, artifact, attr_name, display_name, value):
        try:
            skCase.addArtifactAttributeType(
                attr_name,
                BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                display_name
            )
        except Exception:
            pass

        artifact.addAttribute(
            BlackboardAttribute(
                skCase.getAttributeType(attr_name),
                HealthSQLiteIngestFactory.moduleName,
                self.safe_str(value)
            )
        )

    def create_workout_activity_artifacts(self, skCase, f, parsed, json_path):
        if not parsed:
            return 0

        workouts = parsed.get("workouts", [])
        if not workouts:
            return 0

        art_type_id = self.add_artifact_type(
            skCase,
            "TSK_HEALTH_WORKOUT_ACTIVITY",
            "Apple Health Workout Activity"
        )

        art_list = ArrayList()
        created = 0

        for idx, workout in enumerate(workouts):
            try:
                gps = workout.get("gps", {}) if workout else {}
                stats = workout.get("statistics_summary", {}) if workout else {}
                details = workout.get("ileapp_details", {}) if workout else {}

                art = f.newArtifact(art_type_id)

                attrs = [
                    ("TSK_HEALTH_ACTIVITY_INDEX", "Activity Index", idx + 1),
                    ("TSK_HEALTH_ACTIVITY_DATA_ID", "Workout Data ID", workout.get("data_id")),
                    ("TSK_HEALTH_ACTIVITY_UUID", "Workout UUID", workout.get("uuid")),
                    ("TSK_HEALTH_ACTIVITY_ACTIVITY_UUID", "Workout Activity UUID", workout.get("activity_uuid")),
                    ("TSK_HEALTH_ACTIVITY_TYPE", "Activity Type", workout.get("activity_type_label")),
                    ("TSK_HEALTH_ACTIVITY_TYPE_RAW", "Activity Type Raw", workout.get("activity_type")),
                    ("TSK_HEALTH_ACTIVITY_LOCATION_TYPE", "Location Type", workout.get("location_type_label")),
                    ("TSK_HEALTH_ACTIVITY_LOCATION_TYPE_RAW", "Location Type Raw", workout.get("location_type")),
                    ("TSK_HEALTH_ACTIVITY_PRIMARY", "Is Primary Activity", workout.get("is_primary_activity")),
                    ("TSK_HEALTH_ACTIVITY_START", "Activity Start Time", workout.get("start_time")),
                    ("TSK_HEALTH_ACTIVITY_END", "Activity End Time", workout.get("end_time")),
                    ("TSK_HEALTH_ACTIVITY_CREATED", "Activity Created Time", workout.get("created_time")),

                    ("TSK_HEALTH_ACT_START_TS", "Start Timestamp", details.get("start_timestamp") or workout.get("start_time")),
                    ("TSK_HEALTH_ACT_END_TS", "End Timestamp", details.get("end_timestamp") or workout.get("end_time")),
                    ("TSK_HEALTH_ACT_TOTAL_TIME", "Total Time Duration", details.get("total_time_duration")),
                    ("TSK_HEALTH_ACT_DURATION", "Duration", details.get("duration")),
                    ("TSK_HEALTH_ACT_DISTANCE_KM", "Distance (in KM)", details.get("distance_km") if details.get("distance_km") is not None else workout.get("total_distance_km")),
                    ("TSK_HEALTH_ACT_DISTANCE_MI", "Distance (in Miles)", details.get("distance_miles")),
                    ("TSK_HEALTH_ACT_GOAL_TYPE_LABEL", "Goal Type", details.get("goal_type")),
                    ("TSK_HEALTH_ACT_GOAL", "Goal", details.get("goal")),
                    ("TSK_HEALTH_ACT_ACTIVE_ENERGY", "Total Active Energy (kcal)", details.get("total_active_energy_kcal")),
                    ("TSK_HEALTH_ACT_RESTING_ENERGY", "Total Resting Energy (kcal)", details.get("total_resting_energy_kcal")),
                    ("TSK_HEALTH_ACT_AVG_METS", "Average METs", details.get("average_mets")),
                    ("TSK_HEALTH_ACT_HR_MIN", "Min. Heart Rate (BPM)", details.get("min_heart_rate_bpm")),
                    ("TSK_HEALTH_ACT_HR_MAX", "Max. Heart Rate (BPM)", details.get("max_heart_rate_bpm")),
                    ("TSK_HEALTH_ACT_HR_AVG", "Average Heart Rate (BPM)", details.get("average_heart_rate_bpm")),
                    ("TSK_HEALTH_ACT_TEMP_C", "Temperature (°C)", details.get("temperature_c")),
                    ("TSK_HEALTH_ACT_TEMP_F", "Temperature (°F)", details.get("temperature_f")),
                    ("TSK_HEALTH_ACT_HUMIDITY", "Humidity (%)", details.get("humidity_percent")),
                    ("TSK_HEALTH_ACT_LATITUDE", "Latitude", details.get("latitude")),
                    ("TSK_HEALTH_ACT_LONGITUDE", "Longitude", details.get("longitude")),
                    ("TSK_HEALTH_ACT_MIN_ELEV", "Min. ground elevation (in Meters)", details.get("min_ground_elevation_m")),
                    ("TSK_HEALTH_ACT_MAX_ELEV", "Max. ground elevation (in Meters)", details.get("max_ground_elevation_m")),
                    ("TSK_HEALTH_ACT_DEVICE_ID", "Device ID", details.get("device_id")),
                    ("TSK_HEALTH_ACT_DEVICE_MODEL", "Device Model", details.get("device_model")),
                    ("TSK_HEALTH_ACT_SOURCE_NAME", "Source", details.get("source")),
                    ("TSK_HEALTH_ACT_SOFTWARE", "Software Version", details.get("software_version")),
                    ("TSK_HEALTH_ACT_TIMEZONE", "Timezone", details.get("timezone")),
                    ("TSK_HEALTH_ACT_ADDED", "Timestamp added to Health", details.get("timestamp_added_to_health")),

                    ("TSK_HEALTH_ACTIVITY_DURATION_SEC", "Duration (sec)", workout.get("duration_sec")),
                    ("TSK_HEALTH_ACTIVITY_DURATION_MIN", "Duration (min)", workout.get("duration_min")),
                    ("TSK_HEALTH_ACTIVITY_DISTANCE_M", "Distance (m)", workout.get("total_distance_m")),
                    ("TSK_HEALTH_ACTIVITY_DISTANCE_KM", "Distance (km)", workout.get("total_distance_km")),
                    ("TSK_HEALTH_ACTIVITY_DISTANCE_SOURCE", "Distance Source", workout.get("total_distance_source")),
                    ("TSK_HEALTH_ACTIVITY_SPEED_KMH", "Average Speed (km/h)", workout.get("average_speed_kmh")),
                    ("TSK_HEALTH_ACTIVITY_PACE", "Average Pace (min/km)", workout.get("average_pace_min_per_km")),
                    ("TSK_HEALTH_ACTIVITY_GOAL_TYPE", "Goal Type Raw", workout.get("goal_type")),
                    ("TSK_HEALTH_ACTIVITY_GOAL", "Goal", workout.get("goal")),

                    ("TSK_HEALTH_ACTIVITY_HR_AVG", "Heart Rate Avg (bpm)", stats.get("heart_rate_avg_bpm")),
                    ("TSK_HEALTH_ACTIVITY_HR_MIN", "Heart Rate Min (bpm)", stats.get("heart_rate_min_bpm")),
                    ("TSK_HEALTH_ACTIVITY_HR_MAX", "Heart Rate Max (bpm)", stats.get("heart_rate_max_bpm")),
                    ("TSK_HEALTH_ACTIVITY_ENERGY", "Energy Quantity", stats.get("energy_quantity")),
                    ("TSK_HEALTH_ACTIVITY_ENERGY_TYPE", "Energy Data Type", stats.get("energy_data_type")),

                    ("TSK_HEALTH_ACTIVITY_ROUTE_COUNT", "Route Count", gps.get("route_count")),
                    ("TSK_HEALTH_ACTIVITY_GPS_POINTS", "GPS / Route Points Count", gps.get("gps_points_count")),
                    ("TSK_HEALTH_ACTIVITY_START_GPS_TIME", "First GPS Time", gps.get("start_gps_time")),
                    ("TSK_HEALTH_ACTIVITY_END_GPS_TIME", "Last GPS Time", gps.get("end_gps_time")),
                    ("TSK_HEALTH_ACTIVITY_START_LAT", "Start Latitude", gps.get("start_lat")),
                    ("TSK_HEALTH_ACTIVITY_START_LON", "Start Longitude", gps.get("start_lon")),
                    ("TSK_HEALTH_ACTIVITY_END_LAT", "End Latitude", gps.get("end_lat")),
                    ("TSK_HEALTH_ACTIVITY_END_LON", "End Longitude", gps.get("end_lon")),
                    ("TSK_HEALTH_ACTIVITY_MIN_LAT", "Minimum Latitude", gps.get("min_lat")),
                    ("TSK_HEALTH_ACTIVITY_MAX_LAT", "Maximum Latitude", gps.get("max_lat")),
                    ("TSK_HEALTH_ACTIVITY_MIN_LON", "Minimum Longitude", gps.get("min_lon")),
                    ("TSK_HEALTH_ACTIVITY_MAX_LON", "Maximum Longitude", gps.get("max_lon")),
                    ("TSK_HEALTH_ACTIVITY_GPS_SAMPLE", "GPS Track Sample JSON", self.compact_json(gps.get("track_points_sample"), 3000)),

                    ("TSK_HEALTH_ACTIVITY_SOURCE", "Activity Source JSON", self.compact_json(workout.get("source", {}), 2000)),
                    ("TSK_HEALTH_ACTIVITY_ILEAPP", "iLEAPP-like Details JSON", self.compact_json(details, 3000)),
                    ("TSK_HEALTH_ACTIVITY_STATS", "Activity Statistics Summary JSON", self.compact_json(stats, 2000)),
                    ("TSK_HEALTH_ACTIVITY_ROUTES", "Route Summary JSON", self.compact_json(workout.get("routes", []), 3000)),
                    ("TSK_HEALTH_ACTIVITY_JSON_PATH", "Activity JSON Path", workout.get("activity_json_path") or json_path),
                    ("TSK_HEALTH_ACTIVITY_PARENT_JSON_PATH", "Database JSON Path", json_path),
                ]

                for attr_name, label, value in attrs:
                    self.add_string_attr(skCase, art, attr_name, label, value)

                art_list.add(art)
                created += 1

            except Exception:
                self.log(Level.WARNING, "[ActivityArtifact] Failed to create activity artifact index {}: {}".format(idx, traceback.format_exc()))

        try:
            bb_type = skCase.getArtifactType("TSK_HEALTH_WORKOUT_ACTIVITY")
            if bb_type is not None and art_list.size() > 0:
                evt = ModuleDataEvent(self.moduleNameStr, bb_type, art_list)
                IngestServices.getInstance().fireModuleDataEvent(evt)
        except Exception:
            self.log(Level.WARNING, "[Event] Failed to fire activity ModuleDataEvent: {}".format(traceback.format_exc()))

        return created

    def create_artifact(self, skCase, f, parsed, json_path, parse_status, parse_error):
        db_name = f.getName()
        source_path = self.get_source_path(f)

        file_meta = parsed.get("file", {}) if parsed else {}
        sqlite_meta = parsed.get("sqlite", {}) if parsed else {}
        summary = parsed.get("summary", {}) if parsed else {}
        gps = parsed.get("gps", {}) if parsed else {}
        quantity_summary = parsed.get("quantity_summary", []) if parsed else []
        category_summary = parsed.get("category_summary", []) if parsed else []
        workout_counts = parsed.get("workout_activity_type_counts", {}) if parsed else {}
        workouts_sample = parsed.get("workouts_sample", []) if parsed else []
        recent_quantity = parsed.get("recent_quantity_samples", []) if parsed else []
        recent_category = parsed.get("recent_category_samples", []) if parsed else []
        table_counts = parsed.get("table_counts", {}) if parsed else {}
        activity_json_files = parsed.get("activity_json_files", []) if parsed else []
        activity_json_dir = parsed.get("activity_json_output_dir", "") if parsed else ""

        art_type_id = self.add_artifact_type(skCase, "TSK_HEALTH_SQLITE", "Apple Health SQLite Summary")
        art = f.newArtifact(art_type_id)

        attrs = [
            ("TSK_HEALTH_PARSE_STATUS", "Parse Status", parse_status),
            ("TSK_HEALTH_PARSE_ERROR", "Parse Error", parse_error),
            ("TSK_HEALTH_FILE_NAME", "SQLite File Name", db_name),
            ("TSK_HEALTH_SOURCE_PATH", "SQLite Source Path", source_path),
            ("TSK_HEALTH_SHA256", "SQLite SHA-256", file_meta.get("sha256")),
            ("TSK_HEALTH_FILE_SIZE", "SQLite File Size (bytes)", file_meta.get("size_bytes")),
            ("TSK_HEALTH_JSON_PATH", "Decoded Database JSON Path", json_path),
            ("TSK_HEALTH_ACTIVITY_JSON_DIR", "Activity JSON Directory", activity_json_dir),
            ("TSK_HEALTH_ACTIVITY_JSON_COUNT", "Activity JSON Files Count", len(activity_json_files)),
            ("TSK_HEALTH_ACTIVITY_JSON_FILES", "Activity JSON Files Manifest", self.compact_json(activity_json_files, 3000)),

            ("TSK_HEALTH_INTEGRITY", "SQLite Integrity Check", sqlite_meta.get("integrity_check")),
            ("TSK_HEALTH_USER_VERSION", "SQLite User Version", sqlite_meta.get("user_version")),
            ("TSK_HEALTH_SCHEMA_VERSION", "SQLite Schema Version", sqlite_meta.get("schema_version")),
            ("TSK_HEALTH_TABLE_COUNT", "SQLite Table Count", sqlite_meta.get("table_count")),

            ("TSK_HEALTH_OBJECTS", "Objects Count", summary.get("objects_count")),
            ("TSK_HEALTH_SAMPLES", "Samples Count", summary.get("samples_count")),
            ("TSK_HEALTH_QUANTITY_SAMPLES", "Quantity Samples Count", summary.get("quantity_samples_count")),
            ("TSK_HEALTH_CATEGORY_SAMPLES", "Category Samples Count", summary.get("category_samples_count")),
            ("TSK_HEALTH_WORKOUTS", "Workouts Count", summary.get("workouts_count")),
            ("TSK_HEALTH_WORKOUT_ACTIVITIES", "Workout Activities Count", summary.get("workout_activities_count")),
            ("TSK_HEALTH_WORKOUT_EVENTS", "Workout Events Count", summary.get("workout_events_count")),
            ("TSK_HEALTH_WORKOUT_STATS", "Workout Statistics Count", summary.get("workout_statistics_count")),
            ("TSK_HEALTH_ACTIVITY_CACHES", "Activity Caches Count", summary.get("activity_caches_count")),
            ("TSK_HEALTH_ACHIEVEMENTS", "Earned Achievements Count", summary.get("achievements_earned_count")),
            ("TSK_HEALTH_SLEEP_SCHEDULES", "Sleep Schedule Samples Count", summary.get("sleep_schedule_samples_count")),
            ("TSK_HEALTH_EARLIEST", "Earliest Sample Time", summary.get("earliest_sample_time")),
            ("TSK_HEALTH_LATEST", "Latest Sample Time", summary.get("latest_sample_time")),

            ("TSK_HEALTH_ROUTE_COUNT", "Workout Route Count", gps.get("workout_route_count")),
            ("TSK_HEALTH_GPS_POINTS", "GPS / Route Points Count", gps.get("gps_points_count")),
            ("TSK_HEALTH_START_GPS_TIME", "First GPS Time", gps.get("start_gps_time_min")),
            ("TSK_HEALTH_END_GPS_TIME", "Last GPS Time", gps.get("end_gps_time_max")),
            ("TSK_HEALTH_MIN_LAT", "Minimum Latitude", gps.get("min_lat")),
            ("TSK_HEALTH_MAX_LAT", "Maximum Latitude", gps.get("max_lat")),
            ("TSK_HEALTH_MIN_LON", "Minimum Longitude", gps.get("min_lon")),
            ("TSK_HEALTH_MAX_LON", "Maximum Longitude", gps.get("max_lon")),
            ("TSK_HEALTH_GPS_SAMPLE", "GPS Track Sample JSON", self.compact_json(gps.get("track_points_sample"), 3000)),

            ("TSK_HEALTH_WORKOUT_TYPES", "Workout Activity Type Counts JSON", self.compact_json(workout_counts, 2000)),
            ("TSK_HEALTH_WORKOUT_SAMPLE", "Workout Sample JSON", self.compact_json(workouts_sample, 3000)),
            ("TSK_HEALTH_QUANTITY_SUMMARY", "Quantity Summary JSON", self.compact_json(quantity_summary, 3000)),
            ("TSK_HEALTH_CATEGORY_SUMMARY", "Category Summary JSON", self.compact_json(category_summary, 3000)),
            ("TSK_HEALTH_RECENT_QUANTITY", "Recent Quantity Samples JSON", self.compact_json(recent_quantity, 3000)),
            ("TSK_HEALTH_RECENT_CATEGORY", "Recent Category Samples JSON", self.compact_json(recent_category, 3000)),
            ("TSK_HEALTH_TABLE_COUNTS", "SQLite Table Counts JSON", self.compact_json(table_counts, 3000))
        ]

        for attr_name, label, value in attrs:
            self.add_string_attr(skCase, art, attr_name, label, value)

        try:
            bb_type = skCase.getArtifactType("TSK_HEALTH_SQLITE")
            if bb_type is not None:
                art_list = ArrayList()
                art_list.add(art)
                evt = ModuleDataEvent(self.moduleNameStr, bb_type, art_list)
                IngestServices.getInstance().fireModuleDataEvent(evt)
        except Exception:
            self.log(Level.WARNING, "[Event] Failed to fire ModuleDataEvent: {}".format(traceback.format_exc()))

        return art

    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()

        case_obj = Case.getCurrentCase()
        skCase = case_obj.getSleuthkitCase()
        fileManager = case_obj.getServices().getFileManager()

        case_temp = case_obj.getTempDirectory()
        json_output_dir = self.get_json_output_dir(case_obj, case_temp)
        activity_json_output_dir = self.get_activity_json_output_dir(case_obj, case_temp)

        db_files = self.find_health_sqlite(fileManager, dataSource)

        num_files = len(db_files)
        self.log(Level.INFO, "[Process] Found {} Apple Health SQLite candidate file(s).".format(num_files))
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                HealthSQLiteIngestFactory.moduleName,
                "Found {} Apple Health SQLite candidate file(s).".format(num_files)
            )
        )

        if num_files == 0:
            return IngestModule.ProcessResult.OK

        progressBar.switchToDeterminate(num_files)
        python_exec = self.find_python_executable()

        if not python_exec:
            self.services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.WARNING,
                    HealthSQLiteIngestFactory.moduleName,
                    "No valid Python 3 interpreter found. Install Python 3+ or set HEALTH_SQLITE_PARSER_PYTHON."
                )
            )
            return IngestModule.ProcessResult.OK

        decode_path = os.path.join(os.path.dirname(__file__), "HealthSQLiteDecode.py")
        if not os.path.exists(decode_path):
            self.services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    HealthSQLiteIngestFactory.moduleName,
                    "HealthSQLiteDecode.py was not found in the module directory."
                )
            )
            return IngestModule.ProcessResult.OK

        parsed_count = 0
        failed_count = 0
        activity_artifact_count = 0

        for i, f in enumerate(db_files):
            if self.context.isJobCancelled():
                self.log(Level.WARNING, "[Process] Ingest cancelled by user.")
                return IngestModule.ProcessResult.OK

            db_name = f.getName()
            safe_db_name = self.sanitize_filename(db_name)
            json_file_name = self.make_json_filename(db_name)

            progressBar.progress(db_name, i + 1)

            local_db = os.path.join(
                case_temp,
                "{}_{}".format(f.getId(), safe_db_name)
            )

            json_path = os.path.join(
                json_output_dir,
                json_file_name
            )

            self.log(Level.INFO, "[Process] Handling Apple Health SQLite file: {}".format(self.get_source_path(f)))

            try:
                ContentUtils.writeToFile(f, File(local_db))
                self.log(Level.INFO, "[Copy] Saved SQLite copy to temp: {}".format(local_db))
                self.copy_sqlite_sidecars(fileManager, dataSource, f, local_db)
                companion_healthdb = self.copy_companion_healthdb(fileManager, dataSource, f, case_temp)
            except Exception as e:
                failed_count += 1
                self.log(Level.SEVERE, "[CopyError] {}: {}".format(db_name, e))
                try:
                    self.create_artifact(skCase, f, {}, "", "FAILED_COPY", self.safe_str(e))
                except Exception:
                    self.log(Level.SEVERE, "[ArtifactErrorAfterCopyFail] {}: {}".format(db_name, traceback.format_exc()))
                continue

            try:
                parsed = self.run_decoder(python_exec, decode_path, local_db, json_path, companion_healthdb, activity_json_output_dir)

                if parsed.get("error"):
                    raise Exception(parsed.get("error"))

                self.add_json_report(case_obj, json_path, db_name)
                self.create_artifact(skCase, f, parsed, json_path, "Success", "")
                created_activities = self.create_workout_activity_artifacts(skCase, f, parsed, json_path)
                activity_artifact_count += created_activities
                parsed_count += 1

                self.log(Level.INFO, "[Artifact] Created Apple Health SQLite summary artifact and {} activity artifact(s) for {}".format(created_activities, db_name))
                self.services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.DATA,
                        HealthSQLiteIngestFactory.moduleName,
                        "Parsed Apple Health SQLite file: {}".format(db_name)
                    )
                )

            except Exception:
                failed_count += 1
                err = traceback.format_exc()
                self.log(Level.SEVERE, "[DecodeOrArtifactError] {}: {}".format(db_name, err))

                try:
                    if not os.path.exists(json_path):
                        error_json = {
                            "file_name": self.safe_str(db_name),
                            "source_path": self.get_source_path(f),
                            "parse_status": "FAILED",
                            "error": err
                        }
                        self.write_error_json(json_path, error_json)
                    self.add_json_report(case_obj, json_path, db_name)
                except Exception:
                    self.log(Level.WARNING, "[JSON] Failed to save error JSON: {}".format(traceback.format_exc()))

                try:
                    self.create_artifact(skCase, f, {}, json_path, "FAILED", err[:3000])
                except Exception:
                    self.log(Level.SEVERE, "[ArtifactErrorAfterDecodeFail] {}: {}".format(db_name, traceback.format_exc()))

        self.log(Level.INFO, "[Done] Apple Health SQLite Parser completed. Parsed DBs: {} Activity artifacts: {} Failed: {}".format(parsed_count, activity_artifact_count, failed_count))
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                HealthSQLiteIngestFactory.moduleName,
                "Apple Health SQLite parsing completed. Parsed DBs: {}. Activity artifacts: {}. Failed: {}. Artifacts available under 'Apple Health SQLite Summary' and 'Apple Health Workout Activity'.".format(parsed_count, activity_artifact_count, failed_count)
            )
        )

        return IngestModule.ProcessResult.OK


def createModule():
    return HealthSQLiteIngestFactory()
