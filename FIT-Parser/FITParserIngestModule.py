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


class FitActivityIngestFactory(IngestModuleFactoryAdapter):
    moduleName = "FIT Activity Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses FIT files and extracts detailed activity, GPS, sensor, device, and forensic metadata."

    def getModuleVersionNumber(self):
        return "5.1"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return FitActivityIngestModule()


class FitActivityIngestModule(DataSourceIngestModule):

    def __init__(self):
        self.logger = IngestServices.getInstance().getLogger(FitActivityIngestFactory.moduleName)

    def log(self, level, msg):
        self.logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.context = context
        self.services = IngestServices.getInstance()
        self.moduleNameStr = String(FitActivityIngestFactory.moduleName)
        self.log(Level.INFO, "[Startup] FIT Activity Parser initialized.")
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                FitActivityIngestFactory.moduleName,
                "Module initialized successfully."
            )
        )

    def find_python_executable(self):
        env_path = os.getenv("FIT_PARSER_PYTHON")
        if env_path and os.path.exists(env_path):
            self.log(Level.INFO, "[Python] Using path from FIT_PARSER_PYTHON: {}".format(env_path))
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
                        os.environ["FIT_PARSER_PYTHON"] = exe_path
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

        bundled = os.path.join(os.path.dirname(__file__), "python_embedded", "python.exe")
        if os.path.exists(bundled):
            self.log(Level.INFO, "[Python] Using bundled embedded Python: {}".format(bundled))
            return bundled

        self.log(Level.SEVERE, "[Python] No valid Python 3 interpreter found.")
        return None

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
            return re.sub(r"[^A-Za-z0-9._-]+", "_", name)
        except Exception:
            return "fit_file"

    def make_json_filename(self, fit_name):
        name = self.safe_str(fit_name).strip()
        lower_name = name.lower()

        if lower_name.endswith(".fit.gz"):
            name = name[:-7]
        elif lower_name.endswith(".fit"):
            name = name[:-4]
        elif lower_name.endswith(".gz"):
            name = name[:-3]

        name = self.sanitize_filename(name)

        if not name:
            name = "fit_file"

        return "{}.json".format(name)

    def get_source_path(self, f):
        try:
            return "{}{}".format(f.getParentPath(), f.getName())
        except Exception:
            return self.safe_str(f.getName())

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
                FitActivityIngestFactory.moduleName,
                self.safe_str(value)
            )
        )

    def run_decoder(self, python_exec, fit_decode_path, local_fit):
        cmd = [python_exec, fit_decode_path, "--compact", local_fit]
        self.log(Level.INFO, "[Decode] Running command: {}".format(" ".join(cmd)))

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()

        try:
            out_text = out.decode("utf-8")
        except Exception:
            out_text = out

        try:
            err_text = err.decode("utf-8")
        except Exception:
            err_text = err

        if err_text:
            self.log(Level.INFO, "[Decode STDERR] {}".format(err_text[:2000]))

        if not out_text or not out_text.strip():
            raise Exception("Decoder returned no stdout. STDERR: {}".format(err_text[:1000]))

        return json.loads(out_text)

    def find_fit(self, fileManager, dataSource):
        fit_files = []
        seen_ids = set()

        patterns = [
            "%.fit", "%.FIT",
            "%.fit%", "%.FIT%",
            "%.fit.gz", "%.FIT.GZ",
            "%.gz", "%.GZ"
        ]

        for pattern in patterns:
            try:
                found = fileManager.findFiles(dataSource, pattern)
                for ff in found:
                    name = self.safe_str(ff.getName()).lower()
                    # Keep .fit, .fit.gz, and renamed copies containing ".fit".
                    # For generic .gz, only keep it when the name still indicates FIT.
                    if ".fit" not in name:
                        continue
                    fid = ff.getId()
                    if fid not in seen_ids:
                        fit_files.append(ff)
                        seen_ids.add(fid)
            except Exception as e:
                self.log(Level.WARNING, "[FindFiles] Pattern {} failed: {}".format(pattern, e))

        return fit_files

    def get_json_output_dir(self, case_obj, case_temp):
        case_dir = ""

        try:
            case_dir = self.safe_str(case_obj.getCaseDirectory())
        except Exception as e:
            self.log(Level.WARNING, "[JSON] Failed to get case directory: {}".format(e))

        # Fallback, just in case getCaseDirectory() is not available
        if not case_dir:
            try:
                case_dir = os.path.dirname(self.safe_str(case_temp))
            except Exception:
                case_dir = self.safe_str(case_temp)

        json_output_dir = os.path.join(case_dir, "Reports", "FIT_Activity_JSON")

        try:
            if not os.path.exists(json_output_dir):
                os.makedirs(json_output_dir)
            self.log(Level.INFO, "[JSON] Output directory: {}".format(json_output_dir))
        except Exception as e:
            self.log(Level.SEVERE, "[JSON] Failed to create output directory: {}".format(e))

        return json_output_dir


    def write_json_file(self, json_path, data):
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
            self.log(Level.SEVERE, "[JSON] Failed to write JSON file {}: {}".format(json_path, e))
            return False


    def add_json_report(self, case_obj, json_path, fit_name):
        try:
            case_obj.addReport(
                json_path,
                FitActivityIngestFactory.moduleName,
                "Parsed FIT JSON - {}".format(fit_name)
            )
            self.log(Level.INFO, "[Report] Added JSON report: {}".format(json_path))
        except Exception as e:
            self.log(Level.WARNING, "[Report] Failed to add JSON report: {}".format(e))
            
    def create_artifact(self, skCase, f, parsed, debug_path, parse_status, parse_error):
        fit_name = f.getName()
        source_path = self.get_source_path(f)

        summary = parsed.get("summary", {}) if parsed else {}
        analytics = parsed.get("analytics", {}) if parsed else {}
        gps = parsed.get("gps", {}) if parsed else {}
        fit_header = parsed.get("fit_header", {}) if parsed else {}
        file_meta = parsed.get("file", {}) if parsed else {}
        message_counts = parsed.get("message_counts", {}) if parsed else {}
        available_message_types = parsed.get("available_message_types", []) if parsed else []
        field_inventory = parsed.get("field_inventory", {}) if parsed else {}

        art_type_id = self.add_artifact_type(skCase, "TSK_FIT_ACTIVITY", "FIT Activity Summary")
        art = f.newArtifact(art_type_id)

        attrs = [
            ("TSK_FIT_PARSE_STATUS", "Parse Status", parse_status),
            ("TSK_FIT_PARSE_ERROR", "Parse Error", parse_error),
            ("TSK_FIT_FILE_NAME", "FIT File Name", fit_name),
            ("TSK_FIT_SOURCE_PATH", "FIT Source Path", source_path),
            ("TSK_FIT_SHA256", "FIT SHA-256", file_meta.get("sha256")),
            ("TSK_FIT_FILE_SIZE", "FIT File Size (bytes)", file_meta.get("size_bytes")),
            ("TSK_FIT_SOURCE_GZIP", "Source is GZIP", file_meta.get("source_is_gzip")),
            ("TSK_FIT_DECODED_SIZE", "Decoded FIT Size (bytes)", file_meta.get("decoded_size_bytes")),
            ("TSK_FIT_JSON_PATH", "Decoded JSON Path", debug_path),

            ("TSK_FIT_SIGNATURE", "FIT Signature Valid", fit_header.get("is_fit_signature")),
            ("TSK_FIT_PROTOCOL", "FIT Protocol Version", "{}.{}".format(fit_header.get("protocol_version_major", ""), fit_header.get("protocol_version_minor", ""))),
            ("TSK_FIT_PROFILE", "FIT Profile Version", "{}.{}".format(fit_header.get("profile_version_major", ""), fit_header.get("profile_version_minor", ""))),
            ("TSK_FIT_DATA_SIZE", "FIT Data Size (bytes)", fit_header.get("data_size_bytes")),
            ("TSK_FIT_SIZE_MATCH", "FIT Size Matches Header", fit_header.get("size_matches_header")),

            ("TSK_FIT_TYPE", "FIT File Type", summary.get("fit_file_type")),
            ("TSK_FIT_SPORT", "Sport", summary.get("sport", "Unknown")),
            ("TSK_FIT_SUBSPORT", "Sub Sport", summary.get("sub_sport")),
            ("TSK_FIT_START", "Start Time", summary.get("start_time")),
            ("TSK_FIT_CREATED", "Created Time", summary.get("created_time")),
            ("TSK_FIT_DISTANCE_KM", "Total Distance (km)", summary.get("total_distance_km")),
            ("TSK_FIT_DISTANCE_M", "Total Distance (m)", summary.get("total_distance_m")),
            ("TSK_FIT_DURATION_MIN", "Duration (min)", summary.get("total_timer_time_min")),
            ("TSK_FIT_DURATION_SEC", "Duration (sec)", summary.get("total_timer_time_sec")),
            ("TSK_FIT_CALORIES", "Total Calories", summary.get("total_calories")),

            ("TSK_FIT_AVG_HR", "Average HR (bpm)", summary.get("average_heart_rate") or analytics.get("heart_rate_bpm_avg")),
            ("TSK_FIT_MAX_HR", "Max HR (bpm)", summary.get("max_heart_rate") or analytics.get("heart_rate_bpm_max")),
            ("TSK_FIT_MIN_HR", "Min HR (bpm)", summary.get("min_heart_rate") or analytics.get("heart_rate_bpm_min")),
            ("TSK_FIT_AVG_SPEED", "Average Speed (km/h)", summary.get("average_speed_kmh") or analytics.get("average_speed_kmh_from_records")),
            ("TSK_FIT_MAX_SPEED", "Max Speed (km/h)", summary.get("max_speed_kmh") or analytics.get("max_speed_kmh_from_records")),
            ("TSK_FIT_AVG_PACE", "Average Pace (min/km)", summary.get("average_pace_min_per_km")),
            ("TSK_FIT_BEST_PACE", "Best Pace (min/km)", analytics.get("best_pace_min_per_km_from_records")),
            ("TSK_FIT_AVG_CADENCE", "Average Cadence", summary.get("average_cadence_rpm_spm") or analytics.get("cadence_rpm_spm_avg")),
            ("TSK_FIT_MAX_CADENCE", "Max Cadence", summary.get("max_cadence_rpm_spm") or analytics.get("cadence_rpm_spm_max")),
            ("TSK_FIT_AVG_POWER", "Average Power (W)", summary.get("average_power_w") or analytics.get("power_w_avg")),
            ("TSK_FIT_MAX_POWER", "Max Power (W)", summary.get("max_power_w") or analytics.get("power_w_max")),
            ("TSK_FIT_NORMALIZED_POWER", "Normalized Power (W)", summary.get("normalized_power_w")),
            ("TSK_FIT_ASCENT", "Elevation Gain (m)", summary.get("total_ascent_m")),
            ("TSK_FIT_DESCENT", "Elevation Loss (m)", summary.get("total_descent_m")),
            ("TSK_FIT_AVG_ALTITUDE", "Average Altitude (m)", summary.get("avg_altitude_m") or analytics.get("enhanced_altitude_m_avg") or analytics.get("altitude_m_avg")),
            ("TSK_FIT_MAX_ALTITUDE", "Max Altitude (m)", summary.get("max_altitude_m") or analytics.get("enhanced_altitude_m_max") or analytics.get("altitude_m_max")),
            ("TSK_FIT_MIN_ALTITUDE", "Min Altitude (m)", summary.get("min_altitude_m") or analytics.get("enhanced_altitude_m_min") or analytics.get("altitude_m_min")),
            ("TSK_FIT_AVG_TEMP", "Average Temperature (C)", summary.get("avg_temperature_c") or analytics.get("temperature_c_avg")),
            ("TSK_FIT_MAX_TEMP", "Max Temperature (C)", summary.get("max_temperature_c") or analytics.get("temperature_c_max")),
            ("TSK_FIT_MIN_TEMP", "Min Temperature (C)", summary.get("min_temperature_c") or analytics.get("temperature_c_min")),

            ("TSK_FIT_GPS_POINTS", "GPS Points Count", gps.get("gps_points_count")),
            ("TSK_FIT_START_LAT", "Start Latitude", gps.get("start_lat")),
            ("TSK_FIT_START_LON", "Start Longitude", gps.get("start_lon")),
            ("TSK_FIT_START_GPS_TIME", "Start GPS Time", gps.get("start_gps_time")),
            ("TSK_FIT_END_LAT", "End Latitude", gps.get("end_lat")),
            ("TSK_FIT_END_LON", "End Longitude", gps.get("end_lon")),
            ("TSK_FIT_END_GPS_TIME", "End GPS Time", gps.get("end_gps_time")),
            ("TSK_FIT_MIN_LAT", "Minimum Latitude", gps.get("min_lat")),
            ("TSK_FIT_MAX_LAT", "Maximum Latitude", gps.get("max_lat")),
            ("TSK_FIT_MIN_LON", "Minimum Longitude", gps.get("min_lon")),
            ("TSK_FIT_MAX_LON", "Maximum Longitude", gps.get("max_lon")),
            ("TSK_FIT_GPS_SAMPLE", "GPS Track Sample JSON", self.compact_json(gps.get("track_points_sample"), 3000)),

            ("TSK_FIT_CREATOR_DEVICE", "Creator Device", summary.get("creator_device")),
            ("TSK_FIT_MANUFACTURER", "Manufacturer", summary.get("manufacturer")),
            ("TSK_FIT_PRODUCT", "Product", summary.get("product")),
            ("TSK_FIT_GARMIN_PRODUCT", "Garmin Product", summary.get("garmin_product")),
            ("TSK_FIT_SERIAL", "Serial Number", summary.get("serial_number")),
            ("TSK_FIT_SOFTWARE", "Software Version", summary.get("software_version")),
            ("TSK_FIT_HARDWARE", "Hardware Version", summary.get("hardware_version")),

            ("TSK_FIT_RECORD_COUNT", "Record Message Count", analytics.get("record_count")),
            ("TSK_FIT_LAP_COUNT", "Lap Count", analytics.get("lap_count")),
            ("TSK_FIT_LENGTH_COUNT", "Length Count", analytics.get("length_count")),
            ("TSK_FIT_HRV_COUNT", "HRV Count", analytics.get("hrv_count")),
            ("TSK_FIT_EVENT_COUNT", "Event Count", analytics.get("event_count")),
            ("TSK_FIT_MESSAGE_TYPES", "Available FIT Message Types", ", ".join([self.safe_str(x) for x in available_message_types])),
            ("TSK_FIT_MESSAGE_COUNTS", "FIT Message Counts JSON", self.compact_json(message_counts, 2000)),
            ("TSK_FIT_FIELD_INVENTORY", "FIT Field Inventory JSON", self.compact_json(field_inventory, 3000))
        ]

        for attr_name, label, value in attrs:
            self.add_string_attr(skCase, art, attr_name, label, value)

        try:
            bb_type = skCase.getArtifactType("TSK_FIT_ACTIVITY")
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

        # Temporary folder is still used only for the copied FIT file
        case_temp = case_obj.getTempDirectory()

        # Permanent folder for parsed JSON output
        json_output_dir = self.get_json_output_dir(case_obj, case_temp)

        fit_files = self.find_fit(fileManager, dataSource)

        num_files = len(fit_files)
        self.log(Level.INFO, "[Process] Found {} FIT candidate file(s).".format(num_files))
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                FitActivityIngestFactory.moduleName,
                "Found {} FIT candidate file(s).".format(num_files)
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
                    FitActivityIngestFactory.moduleName,
                    "No valid Python interpreter found. Install Python 3+ or set FIT_PARSER_PYTHON."
                )
            )
            return IngestModule.ProcessResult.OK

        fit_decode_path = os.path.join(os.path.dirname(__file__), "FitDecode.py")
        if not os.path.exists(fit_decode_path):
            self.services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    FitActivityIngestFactory.moduleName,
                    "FitDecode.py was not found in the module directory."
                )
            )
            return IngestModule.ProcessResult.OK

        parsed_count = 0
        failed_count = 0

        # Loop through each FIT file and process it
        for i, f in enumerate(fit_files):
            if self.context.isJobCancelled():
                self.log(Level.WARNING, "[Process] Ingest cancelled by user.")
                return IngestModule.ProcessResult.OK

            fit_name = f.getName()
            safe_fit_name = self.sanitize_filename(fit_name)
            json_file_name = self.make_json_filename(fit_name)

            progressBar.progress(fit_name, i + 1)

            # Keep the copied FIT file in temp
            local_fit = os.path.join(
                case_temp,
                "{}_{}".format(f.getId(), safe_fit_name)
            )

            # Save parsed JSON permanently with clean original filename
            # Example: 18199059665.fit -> 18199059665.json
            debug_path = os.path.join(
                json_output_dir,
                json_file_name
            )

            self.log(Level.INFO, "[Process] Handling FIT file: {}".format(self.get_source_path(f)))

            try:
                ContentUtils.writeToFile(f, File(local_fit))
                self.log(Level.INFO, "[Copy] Saved FIT copy to temp: {}".format(local_fit))
            except Exception as e:
                failed_count += 1
                self.log(Level.SEVERE, "[CopyError] {}: {}".format(fit_name, e))
                try:
                    self.create_artifact(skCase, f, {}, "", "FAILED_COPY", self.safe_str(e))
                except Exception:
                    self.log(Level.SEVERE, "[ArtifactErrorAfterCopyFail] {}: {}".format(fit_name, traceback.format_exc()))
                continue

            try:
                parsed = self.run_decoder(python_exec, fit_decode_path, local_fit)
                if parsed.get("error"):
                    raise Exception(parsed.get("error"))

                # Write parsed JSON to permanent Reports/FIT_Activity_JSON folder
                self.write_json_file(debug_path, parsed)

                # Register JSON as an Autopsy report so it can be opened from the case UI
                self.add_json_report(case_obj, debug_path, fit_name)

                # Store permanent JSON path in artifact attribute TSK_FIT_JSON_PATH
                self.create_artifact(skCase, f, parsed, debug_path, "Success", "")
                parsed_count += 1

                self.log(Level.INFO, "[Artifact] Created detailed FIT artifact for {}".format(fit_name))
                self.services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.DATA,
                        FitActivityIngestFactory.moduleName,
                        "Parsed FIT file: {}".format(fit_name)
                    )
                )

            except Exception:
                failed_count += 1
                err = traceback.format_exc()
                self.log(Level.SEVERE, "[DecodeOrArtifactError] {}: {}".format(fit_name, err))

                # Save error JSON too, but do not overwrite parsed JSON if it already exists
                try:
                    if not os.path.exists(debug_path):
                        error_json = {
                            "file_name": self.safe_str(fit_name),
                            "source_path": self.get_source_path(f),
                            "parse_status": "FAILED",
                            "error": err
                        }
                        self.write_json_file(debug_path, error_json)
                        self.add_json_report(case_obj, debug_path, fit_name)
                except Exception:
                    self.log(Level.WARNING, "[JSON] Failed to save error JSON: {}".format(traceback.format_exc()))

                try:
                    self.create_artifact(skCase, f, {}, debug_path, "FAILED", err[:3000])
                except Exception:
                    self.log(Level.SEVERE, "[ArtifactErrorAfterDecodeFail] {}: {}".format(fit_name, traceback.format_exc()))

        self.log(Level.INFO, "[Done] FIT Parser completed. Parsed: {} Failed: {}".format(parsed_count, failed_count))
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                FitActivityIngestFactory.moduleName,
                "FIT parsing completed. Parsed: {}. Failed: {}. Artifacts available under 'FIT Activity Summary'.".format(parsed_count, failed_count)
            )
        )

        return IngestModule.ProcessResult.OK

def createModule():
    return FitActivityIngestFactory()
