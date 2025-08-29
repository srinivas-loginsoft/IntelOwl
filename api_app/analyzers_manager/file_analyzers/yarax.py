import logging
import os
import pathlib
from zipfile import ZipFile

import requests
import yara_x
from django.conf import settings

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


RULES_URL = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
BASE_RULES_LOCATION = f"{settings.MEDIA_ROOT}/yarax"


class YaraX(FileAnalyzer):
    rule_set: str = "core"

    def get_rule_location(self):
        logger.info(f"Searching for rules at {BASE_RULES_LOCATION}/{self.rule_set}")
        try:
            rule_set_dir = pathlib.Path(BASE_RULES_LOCATION) / self.rule_set
            rule = rule_set_dir.rglob("*.yar")
            return next(rule).__str__()

        except StopIteration as e:
            logger.error(f"{self.rule_set} not found, function exited with error {e}")
            raise AnalyzerRunException(f"{self.rule_set} rules not present")

    @classmethod
    def _unzip(cls, rule_set_type: str, filename: str):

        rule_file_path = pathlib.Path(BASE_RULES_LOCATION) / rule_set_type / filename
        logger.info(f"Extracting rules at {rule_file_path.parent}")
        with ZipFile(rule_file_path, mode="r") as archive:
            archive.extractall(
                rule_file_path.parent
            )  # this will overwrite any existing directory
        logger.info("Rules have been succesfully extracted")

    @classmethod
    def _download_rules(
        cls, rule_set_download_url: str, filename: str, rule_set_type: str
    ):
        rule_set_directory = f"{BASE_RULES_LOCATION}/{rule_set_type}"
        rule_file_path = f"{rule_set_directory}/{filename}"

        if not os.path.exists(rule_set_directory):
            os.makedirs(rule_set_directory)

        logger.info(f"Started downloading rules from {rule_set_download_url}")
        response = requests.get(rule_set_download_url, stream=True)
        with open(rule_file_path, mode="wb+") as file:
            for chunk in response.iter_content(chunk_size=10 * 1024):
                file.write(chunk)

        logger.info(f"Rules have been successfully downloaded at {rule_file_path}")

    @classmethod
    def update(cls, rule_set) -> bool:
        logger.info(f"Updating {rule_set} rule set")
        rule_set_download_url = ""
        filename = ""
        try:
            response = requests.get(RULES_URL)
            assets = response.json()["assets"]
            for asset in assets:
                if rule_set in asset["browser_download_url"]:
                    rule_set_download_url = asset["browser_download_url"]
                    filename = asset["name"]
                    break

            cls._download_rules(
                rule_set_download_url=rule_set_download_url,
                filename=filename,
                rule_set_type=rule_set,
            )
            cls._unzip(rule_set_type=rule_set, filename=filename)

            logger.info(f"Successfully updated {rule_set} rules")
            return True

        except Exception as e:
            logger.error(f"Failed to update yara-forge rules. Error: {e}")

        return False

    def run(self):

        if self.rule_set not in ("core", "extended", "full"):
            raise AnalyzerRunException(
                "Please select the correct ruleset pack from available options."
                " Available options are core, extended, full"
            )

        rule_dir = f"{BASE_RULES_LOCATION}/{self.rule_set}"
        if not os.path.isdir(rule_dir) and not self.update(rule_set=self.rule_set):
            logger.info(f"Failed to update {self.rule_set} rule set")
            raise AnalyzerRunException(f"Couldn't update {self.rule_set} rules")

        rules_file_path = self.get_rule_location()
        logger.info(f"Found rules at {rules_file_path}")

        with open(rules_file_path, mode="r") as f:
            rules_source = f.read()

        try:
            logger.info(f"Compiling rules present at {self.rule_set}")
            compiler = yara_x.Compiler()
            compiler.add_source(rules_source, origin=rules_file_path)
            rules = compiler.build()
            logger.info("Successfully compiled and built rules")

            logger.info(f"Starting scanning {self.filename} with {self.rule_set} rules")
            scanner = yara_x.Scanner(rules)

            result = []
            scan_results = scanner.scan_file(self.filepath)
            for rule in scan_results.matching_rules:
                logger.info(f"Rule Identifier: {rule.identifier}")
                rule_metadata = {}
                for detail in rule.metadata:
                    rule_metadata[detail[0]] = detail[1]
                rule_details = {
                    "rule_identifier": rule.identifier,
                    "rule_metadata": rule_metadata,
                    "pattern_details": [],
                }
                for pattern in rule.patterns:
                    pattern_details = {
                        "pattern_identifier": pattern.identifier,
                        "match_details": [],
                    }

                    for match in pattern.matches:
                        match_details = {
                            "match_offset": match.offset,
                            "match_length": match.length,
                            "match_xor_key": match.xor_key,
                        }
                        pattern_details["match_details"].append(match_details)

                    rule_details["pattern_details"].append(pattern_details)

                result.append(rule_details)

            logger.info(f"Successfully scanned {self.filename} with hash {self.md5}")

            return "No Match" if not result else result

        except yara_x.CompileError as e:
            logger.error(
                f"Failed to compile {self.rule_set} rules present at {rules_file_path} with error {e}"
            )
            raise AnalyzerRunException(f"Failed to compile {self.rule_set} rules")

        except yara_x.ScanError as e:
            logger.error(f"Failed to scan file {self.filename} with error {e}")
            raise AnalyzerRunException(f"Failed to scan {self.filename}")

        except yara_x.TimeoutError as e:
            logger.error(f"Failed with timeout with error {e}")
            raise AnalyzerRunException("Failed with timeout")
