"""Identify and extract blobs and files from loaded binary using Unblob API
"""

import json
import uuid
from pathlib import Path
from shutil import rmtree
from os import path, makedirs
from tempfile import gettempdir

from unblob.models import Task, ProcessResult
from unblob.processing import Processor, ExtractionConfig
from unblob.report import StatReport, FileMagicReport, ChunkReport, HashReport
from unblob.logging import configure_logger
from binaryninja.project import Project
from binaryninja import log_info, log_alert, log_error, BackgroundTaskThread, BinaryView


def _get_root_dir_path() -> Path:
    dirpath = Path(path.join(gettempdir(), "blob_extractor"))
    makedirs(dirpath, exist_ok=True)
    return dirpath


def _get_tmp_path(mkdir: bool = False) -> Path:
    filepath = Path(path.join(_get_root_dir_path(), str(uuid.uuid4())))
    if mkdir:
        makedirs(filepath, exist_ok=True)
    return filepath


def _process_tasks(proc: Processor, task: Task, aggregated_result: ProcessResult, scan_only=bool) -> None:
    process_result = proc.process_task(task)
    aggregated_result.register(process_result)
    if scan_only:
        return

    for new_task in process_result.subtasks:
        _process_tasks(proc, new_task, aggregated_result, scan_only)


def _process_file(config: ExtractionConfig, input_path: Path, scan_only: bool = False) -> ProcessResult:
    if not input_path.is_file():
        raise FileNotFoundError("input_path is not a file", input_path)

    proc = Processor(config)
    task = Task(
        blob_id="",
        path=input_path,
        depth=0,
    )

    aggregated_result = ProcessResult()
    _process_tasks(proc, task, aggregated_result, scan_only)
    return aggregated_result


def _extract_from_file(filepath: str, outdir: str, scan_only: bool = False) -> list[tuple]:
    log_info(f"extracting binaries from '{filepath}'...")
    files = []
    log_path = _get_root_dir_path() / "unblob.log"
    configure_logger(0, Path(outdir), log_path)
    config = ExtractionConfig(
        extract_root=Path(outdir),
        randomness_depth=1,
        verbose=0,
    )

    processed = _process_file(config, Path(filepath), scan_only)
    for result in processed.results:
        sr = result.filter_reports(StatReport)
        if not sr or not sr[0].is_file or sr[0].is_link:
            continue

        fmr = result.filter_reports(FileMagicReport)
        if fmr:
            fmr = fmr[0]

        crs = result.filter_reports(ChunkReport)
        hr = result.filter_reports(HashReport)
        if hr:
            hr = hr[0]

        files.append((sr[0], fmr, crs, hr))

    return files


def _file_in_project(sha1: str, project: Project) -> bool:
    for file in project.files:
        try:
            description = json.loads(file.description)
        except json.decoder.JSONDecodeError:
            continue

        file_sha1 = description.get("sha1")
        if file_sha1 is None:
            continue

        if file_sha1 == sha1:
            return True

    return False


def import_files_into_project(files: list[tuple], project: Project) -> tuple:
    """Import files into Binary Ninja project"""

    log_info("importing extracted binaries into Binary Ninja project...")
    skipped = 0
    imported = 0
    with project.bulk_operation():
        for sr, fmr, _, hr in files:
            if _file_in_project(hr.sha1, project):
                skipped += 1
                continue

            description = {
                "sha1": hr.sha1,
                "magic": fmr.magic,
            }

            project.create_file_from_path(
                str(sr.path), None, path.basename(sr.path), description=json.dumps(description)
            )
            imported += 1

    return (skipped, imported)


def _export_file_contents(bv: BinaryView) -> tuple:
    """Export the contents of the binary view to a temporary file and return the path"""

    if path.isfile(bv.file.original_filename):
        return (False, bv.file.original_filename)

    tmp = _get_tmp_path()
    if not bv.save(tmp):
        return (False, None)

    return (True, tmp)


class ExtractFilesTask(BackgroundTaskThread):
    """Extract files (recursively) from the loaded binary"""

    def __init__(self, bv: BinaryView, results_callback: callable):
        super().__init__("Extracting files...", True)
        self.bv = bv.get_view_of_type("Raw")
        self.results_callback = results_callback
        self.is_tmpfile, self.filepath = _export_file_contents(self.bv)

    def run(self):
        """Run the task"""

        if not self.filepath:
            log_alert("Failed to get original file for binary view")
            self.results_callback([], None)
            return

        try:
            extract_dir = _get_tmp_path(mkdir=True)
            files = _extract_from_file(self.filepath, extract_dir)
            if len(files) < 2:  # First file is the file we're scanning
                self.results_callback([], None)
                return

            self.results_callback(files[1:], extract_dir)
        finally:
            if self.is_tmpfile:
                Path.unlink(self.filepath)


class FindBlobsTask(BackgroundTaskThread):
    """Scan for known file signatures and interesting blobs in file"""

    def __init__(self, bv: BinaryView, results_callback: callable):
        super().__init__("", True)
        self.bv = bv
        self.raw = self.bv.get_view_of_type("Raw")
        self.is_tmpfile, self.filepath = _export_file_contents(self.bv)
        self.results_callback = results_callback
        self.progress = ""

    def run(self):
        """Run the task"""

        self.progress = "Scanning for data signatures..."
        if not self.filepath:
            log_error("Failed to get original file for binary view")
            self.results_callback([])
            return

        try:
            extract_dir = _get_tmp_path(mkdir=True)
            files = _extract_from_file(self.filepath, extract_dir, scan_only=True)
            if not files or not files[0][2]:  # Make sure there is a file and chunk report
                log_info("No interesting chunks found")
                self.results_callback([])
                return

            try:
                rmtree(extract_dir)
            except FileNotFoundError:
                pass

            results = files[0][2]
            self.results_callback(results)
        finally:
            if self.is_tmpfile:
                Path.unlink(self.filepath)
