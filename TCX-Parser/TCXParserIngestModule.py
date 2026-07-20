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


class TCXActivityIngestFactory(IngestModuleFactoryAdapter):
    moduleName = "TCX Activity Parser"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Parses TCX files, saves detailed JSON with GPS track points, and creates summary artifacts."

    def getModuleVersionNumber(self):
        return "3.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return TCXActivityIngestModule()


class TCXActivityIngestModule(DataSourceIngestModule):

    def __init__(self):
        self.logger = IngestServices.getInstance().getLogger(TCXActivityIngestFactory.moduleName)

    def log(self, level, msg):
        self.logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.context = context
        self.services = IngestServices.getInstance()
        self.moduleNameStr = String(TCXActivityIngestFactory.moduleName)

        self.log(Level.INFO, "[Startup] TCX Activity Parser initialized.")
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                TCXActivityIngestFactory.moduleName,
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
            return "tcx_file"

    def make_json_filename(self, tcx_name):
        """
        Convert:
          12799834215.tcx    -> 12799834215.json
          12799834215.TCX    -> 12799834215.json
          12799834215.tcx.gz -> 12799834215.json
        """
        name = self.safe_str(tcx_name).strip()
        lower_name = name.lower()

        if lower_name.endswith(".tcx.gz"):
            name = name[:-7]
        elif lower_name.endswith(".tcx"):
            name = name[:-4]
        elif lower_name.endswith(".gz"):
            name = name[:-3]

        name = self.sanitize_filename(name)
        if not name:
            name = "tcx_file"

        return "{}.json".format(name)

    def get_source_path(self, f):
        try:
            return "{}{}".format(f.getParentPath(), f.getName())
        except Exception:
            return self.safe_str(f.getName())

    def find_python_executable(self):
        env_path = os.getenv("TCX_PARSER_PYTHON")
        if env_path and os.path.exists(env_path):
            self.log(Level.INFO, "[Python] Using path from TCX_PARSER_PYTHON: {}".format(env_path))
            return env_path

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
                        os.environ["TCX_PARSER_PYTHON"] = exe_path
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

        json_output_dir = os.path.join(case_dir, "Reports", "TCX_Activity_JSON")

        try:
            if not os.path.exists(json_output_dir):
                os.makedirs(json_output_dir)
            self.log(Level.INFO, "[JSON] Output directory: {}".format(json_output_dir))
        except Exception as e:
            self.log(Level.SEVERE, "[JSON] Failed to create output directory: {}".format(e))

        return json_output_dir

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

    def add_json_report(self, case_obj, json_path, tcx_name):
        try:
            if os.path.exists(json_path):
                case_obj.addReport(
                    json_path,
                    TCXActivityIngestFactory.moduleName,
                    "Parsed TCX JSON - {}".format(tcx_name)
                )
                self.log(Level.INFO, "[Report] Added JSON report: {}".format(json_path))
        except Exception as e:
            self.log(Level.WARNING, "[Report] Failed to add JSON report: {}".format(e))

    def run_decoder(self, python_exec, tcx_decode_path, local_tcx, json_path):
        # Decoder writes full JSON with GPS points to json_path.
        # Stdout is compact so large GPS point lists are not loaded into the blackboard.
        cmd = [python_exec, tcx_decode_path, "--output", json_path, "--pretty", "--compact", local_tcx]
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

    def find_tcx(self, fileManager, dataSource):
        tcx_files = []
        seen_ids = set()

        patterns = [
            "%.tcx", "%.TCX",
            "%.tcx%", "%.TCX%",
            "%.tcx.gz", "%.TCX.GZ",
            "%.gz", "%.GZ"
        ]

        for pattern in patterns:
            try:
                found = fileManager.findFiles(dataSource, pattern)
                for ff in found:
                    name = self.safe_str(ff.getName()).lower()
                    if ".tcx" not in name:
                        continue
                    fid = ff.getId()
                    if fid not in seen_ids:
                        tcx_files.append(ff)
                        seen_ids.add(fid)
            except Exception as e:
                self.log(Level.WARNING, "[FindFiles] Pattern {} failed: {}".format(pattern, e))

        return tcx_files

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
                TCXActivityIngestFactory.moduleName,
                self.safe_str(value)
            )
        )

    def create_artifact(self, skCase, f, parsed, json_path, parse_status, parse_error):
        tcx_name = f.getName()
        source_path = self.get_source_path(f)

        summary = parsed.get("summary", {}) if parsed else {}
        analytics = parsed.get("analytics", {}) if parsed else {}
        gps = parsed.get("gps", {}) if parsed else {}
        file_meta = parsed.get("file", {}) if parsed else {}
        creator = parsed.get("creator", {}) if parsed else {}

        art_type_id = self.add_artifact_type(skCase, "TSK_TCX_ACTIVITY", "TCX Activity Summary")
        art = f.newArtifact(art_type_id)

        attrs = [
            ("TSK_TCX_PARSE_STATUS", "Parse Status", parse_status),
            ("TSK_TCX_PARSE_ERROR", "Parse Error", parse_error),
            ("TSK_TCX_FILE_NAME", "TCX File Name", tcx_name),
            ("TSK_TCX_SOURCE_PATH", "TCX Source Path", source_path),
            ("TSK_TCX_SHA256", "TCX SHA-256", file_meta.get("sha256")),
            ("TSK_TCX_FILE_SIZE", "TCX File Size (bytes)", file_meta.get("size_bytes")),
            ("TSK_TCX_SOURCE_GZIP", "Source is GZIP", file_meta.get("source_is_gzip")),
            ("TSK_TCX_DECODED_SIZE", "Decoded TCX Size (bytes)", file_meta.get("decoded_size_bytes")),
            ("TSK_TCX_JSON_PATH", "Decoded JSON Path", json_path),

            ("TSK_TCX_SPORT", "Sport", summary.get("sport", "Unknown")),
            ("TSK_TCX_ACTIVITY_ID", "Activity ID", summary.get("activity_id")),
            ("TSK_TCX_START", "Start Time", summary.get("start_time")),
            ("TSK_TCX_CREATOR", "Creator", summary.get("creator") or creator.get("name")),
            ("TSK_TCX_DEVICE", "Device", summary.get("device") or creator.get("device")),
            ("TSK_TCX_CREATOR_UNIT_ID", "Creator Unit ID", creator.get("unit_id")),
            ("TSK_TCX_CREATOR_PRODUCT_ID", "Creator Product ID", creator.get("product_id")),

            ("TSK_TCX_DISTANCE_KM", "Total Distance (km)", summary.get("total_distance_km")),
            ("TSK_TCX_DISTANCE_M", "Total Distance (m)", summary.get("total_distance_m")),
            ("TSK_TCX_DURATION_MIN", "Duration (min)", summary.get("total_timer_time_min")),
            ("TSK_TCX_DURATION_SEC", "Duration (sec)", summary.get("total_timer_time_sec")),
            ("TSK_TCX_CALORIES", "Calories", summary.get("total_calories")),
            ("TSK_TCX_AVG_HR", "Average HR (bpm)", summary.get("average_heart_rate") or analytics.get("heart_rate_bpm_avg")),
            ("TSK_TCX_MAX_HR", "Max HR (bpm)", summary.get("max_heart_rate") or analytics.get("heart_rate_bpm_max")),
            ("TSK_TCX_AVG_PACE", "Average Pace (min/km)", summary.get("average_pace_min_per_km")),
            ("TSK_TCX_AVG_SPEED", "Average Speed (km/h)", summary.get("average_speed_kmh")),
            ("TSK_TCX_MAX_SPEED", "Max Speed (km/h)", summary.get("max_speed_kmh")),
            ("TSK_TCX_AVG_CADENCE", "Average Cadence (spm)", summary.get("average_cadence_spm") or analytics.get("cadence_avg")),

            ("TSK_TCX_LAP_COUNT", "Lap Count", analytics.get("lap_count") or summary.get("lap_count")),
            ("TSK_TCX_TRACKPOINT_COUNT", "Trackpoint Count", analytics.get("trackpoint_count")),
            ("TSK_TCX_GPS_POINTS", "GPS Points Count", gps.get("gps_points_count") or analytics.get("gps_points_count")),

            # Only summary GPS metadata is stored in blackboard.
            # Full GPS track points are saved only in the JSON file.
            ("TSK_TCX_START_LAT", "Start Latitude", gps.get("start_lat")),
            ("TSK_TCX_START_LON", "Start Longitude", gps.get("start_lon")),
            ("TSK_TCX_START_GPS_TIME", "Start GPS Time", gps.get("start_gps_time")),
            ("TSK_TCX_END_LAT", "End Latitude", gps.get("end_lat")),
            ("TSK_TCX_END_LON", "End Longitude", gps.get("end_lon")),
            ("TSK_TCX_END_GPS_TIME", "End GPS Time", gps.get("end_gps_time")),
            ("TSK_TCX_MIN_LAT", "Minimum Latitude", gps.get("min_lat")),
            ("TSK_TCX_MAX_LAT", "Maximum Latitude", gps.get("max_lat")),
            ("TSK_TCX_MIN_LON", "Minimum Longitude", gps.get("min_lon")),
            ("TSK_TCX_MAX_LON", "Maximum Longitude", gps.get("max_lon")),
            ("TSK_TCX_GPS_SAMPLE", "GPS Track Sample JSON", self.compact_json(gps.get("track_points_sample"), 3000)),

            ("TSK_TCX_AVG_ALTITUDE", "Average Altitude (m)", analytics.get("altitude_m_avg")),
            ("TSK_TCX_MAX_ALTITUDE", "Max Altitude (m)", analytics.get("altitude_m_max")),
            ("TSK_TCX_MIN_ALTITUDE", "Min Altitude (m)", analytics.get("altitude_m_min")),
            ("TSK_TCX_ASCENT_EST", "Estimated Elevation Gain (m)", analytics.get("altitude_gain_estimate_m")),
            ("TSK_TCX_DESCENT_EST", "Estimated Elevation Loss (m)", analytics.get("altitude_loss_estimate_m"))
        ]

        for attr_name, label, value in attrs:
            self.add_string_attr(skCase, art, attr_name, label, value)

        try:
            bb_type = skCase.getArtifactType("TSK_TCX_ACTIVITY")
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

        tcx_files = self.find_tcx(fileManager, dataSource)

        num_files = len(tcx_files)
        self.log(Level.INFO, "[Process] Found {} TCX candidate file(s).".format(num_files))
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                TCXActivityIngestFactory.moduleName,
                "Found {} TCX candidate file(s).".format(num_files)
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
                    TCXActivityIngestFactory.moduleName,
                    "No valid Python 3 interpreter found. Install Python 3+ or set TCX_PARSER_PYTHON."
                )
            )
            return IngestModule.ProcessResult.OK

        tcx_decode_path = os.path.join(os.path.dirname(__file__), "TCXDecode.py")
        if not os.path.exists(tcx_decode_path):
            self.services.postMessage(
                IngestMessage.createMessage(
                    IngestMessage.MessageType.ERROR,
                    TCXActivityIngestFactory.moduleName,
                    "TCXDecode.py was not found in the module directory."
                )
            )
            return IngestModule.ProcessResult.OK

        parsed_count = 0
        failed_count = 0

        for i, f in enumerate(tcx_files):
            if self.context.isJobCancelled():
                self.log(Level.WARNING, "[Process] Ingest cancelled by user.")
                return IngestModule.ProcessResult.OK

            tcx_name = f.getName()
            safe_tcx_name = self.sanitize_filename(tcx_name)
            json_file_name = self.make_json_filename(tcx_name)

            progressBar.progress(tcx_name, i + 1)

            local_tcx = os.path.join(
                case_temp,
                "{}_{}".format(f.getId(), safe_tcx_name)
            )

            json_path = os.path.join(
                json_output_dir,
                json_file_name
            )

            self.log(Level.INFO, "[Process] Handling TCX file: {}".format(self.get_source_path(f)))

            try:
                ContentUtils.writeToFile(f, File(local_tcx))
                self.log(Level.INFO, "[Copy] Saved TCX copy to temp: {}".format(local_tcx))
            except Exception as e:
                failed_count += 1
                self.log(Level.SEVERE, "[CopyError] {}: {}".format(tcx_name, e))
                try:
                    self.create_artifact(skCase, f, {}, "", "FAILED_COPY", self.safe_str(e))
                except Exception:
                    self.log(Level.SEVERE, "[ArtifactErrorAfterCopyFail] {}: {}".format(tcx_name, traceback.format_exc()))
                continue

            try:
                parsed = self.run_decoder(python_exec, tcx_decode_path, local_tcx, json_path)

                if parsed.get("error"):
                    raise Exception(parsed.get("error"))

                # Register the full JSON output as an Autopsy report.
                self.add_json_report(case_obj, json_path, tcx_name)

                # Create blackboard artifact with summary only.
                # Full GPS track points remain in the JSON file and are not added to blackboard.
                self.create_artifact(skCase, f, parsed, json_path, "Success", "")
                parsed_count += 1

                self.log(Level.INFO, "[Artifact] Created TCX summary artifact for {}".format(tcx_name))
                self.services.postMessage(
                    IngestMessage.createMessage(
                        IngestMessage.MessageType.DATA,
                        TCXActivityIngestFactory.moduleName,
                        "Parsed TCX file: {}".format(tcx_name)
                    )
                )

            except Exception:
                failed_count += 1
                err = traceback.format_exc()
                self.log(Level.SEVERE, "[DecodeOrArtifactError] {}: {}".format(tcx_name, err))

                try:
                    if not os.path.exists(json_path):
                        error_json = {
                            "file_name": self.safe_str(tcx_name),
                            "source_path": self.get_source_path(f),
                            "parse_status": "FAILED",
                            "error": err
                        }
                        self.write_error_json(json_path, error_json)
                    self.add_json_report(case_obj, json_path, tcx_name)
                except Exception:
                    self.log(Level.WARNING, "[JSON] Failed to save error JSON: {}".format(traceback.format_exc()))

                try:
                    self.create_artifact(skCase, f, {}, json_path, "FAILED", err[:3000])
                except Exception:
                    self.log(Level.SEVERE, "[ArtifactErrorAfterDecodeFail] {}: {}".format(tcx_name, traceback.format_exc()))

        self.log(Level.INFO, "[Done] TCX Parser completed. Parsed: {} Failed: {}".format(parsed_count, failed_count))
        self.services.postMessage(
            IngestMessage.createMessage(
                IngestMessage.MessageType.INFO,
                TCXActivityIngestFactory.moduleName,
                "TCX parsing completed. Parsed: {}. Failed: {}. Artifacts available under 'TCX Activity Summary'.".format(parsed_count, failed_count)
            )
        )

        return IngestModule.ProcessResult.OK


def createModule():
    return TCXActivityIngestFactory()
