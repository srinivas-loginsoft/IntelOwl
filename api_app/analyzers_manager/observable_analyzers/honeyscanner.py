import logging
import socket

import honeyscanner.main

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.choices import Classification
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class HoneyScanner(ObservableAnalyzer):
    honeypot_username: str = ""
    _honeypot_password: str = ""

    @staticmethod
    def resolve_hostname_to_ip(hostname):
        """
        Resolves a given hostname to its corresponding IP address.
        """
        try:
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except socket.gaierror:
            return f"Error: Could not resolve hostname '{hostname}'"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        if self.observable_classification == Classification.DOMAIN:
            ip_address = self.resolve_hostname_to_ip(self.observable_name)
        else:
            ip_address = self.observable_name

        logger.info(f"Running HoneyScanner for {ip_address=}")

        result = honeyscanner.main.run_honeyscanner(
            ip_address,
            username=self.honeypot_username,
            password=self._honeypot_password,
        )

        logger.info(f"Successfully executed honeyscanner for ip_address {ip_address}")

        return result

    @classmethod
    def _monkeypatch(cls):

        honeyscanner_result = {
            "results": {
                "cves": 124,
                "active": {
                    "attacks": [
                        {
                            "message": "Honeypot is still alive after banner fuzzing - Honeypot is still alive after terminal fuzzing - \
                          112312 test cases executed in 349.80s (local network, quick test + legacy boofuzz)",
                            "attack_name": "Fuzzing",
                            "additional_metrics": {"test_cases_executed": 112312},
                            "vulnerability_found": False,
                            "execution_time_seconds": 349,
                        },
                        {
                            "message": "Tar bomb attack executed (30/30 successful), but honeypot is still alive",
                            "attack_name": "TarBomb",
                            "additional_metrics": {"bombs_used": 30},
                            "vulnerability_found": False,
                            "execution_time_seconds": 90,
                        },
                        {
                            "message": "Vulnerability found: DoS attack made the honeypot reject connections",
                            "attack_name": "DoS",
                            "additional_metrics": {"threads_used": 40},
                            "vulnerability_found": True,
                            "execution_time_seconds": 16,
                        },
                    ],
                    "summary": {
                        "success_rate": 33.33,
                        "total_attacks": 3,
                        "successful_attacks": 1,
                    },
                    "target_ip": "172.18.0.9",
                    "report_title": "Honeypot Active Attack Report",
                },
                "passive": {
                    "summary": {
                        "attack_types": [
                            "ContainerSecurityScanner",
                            "StaticAnalyzer",
                            "VulnerableLibrariesAnalyzer",
                        ],
                        "recommendations_count": 3,
                        "total_attacks_performed": 3,
                    },
                    "target_ip": "172.18.0.9",
                    "report_title": "Honeypot Passive Attack Report",
                    "attack_results": {
                        "StaticAnalyzer": {
                            "attack_type": "Static Code Analysis",
                            "description": "Static analysis of honeypot codebase and configuration",
                            "report_content": {
                                "version": "v2.6.1",
                                "high_severity_count": 13,
                                "high_severity_issues": [
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/ftpget.py",
                                        "issue_text": "A FTP-related module is being imported.  FTP is considered insecure. \
                                      Use SSH/SFTP/SCP or some other encrypted protocol.",
                                        "line_number": 5,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/ftpget.py",
                                        "issue_text": "FTP-related functions are being called. FTP is considered insecure. \
                                      Use SSH/SFTP/SCP or some other encrypted protocol.",
                                        "line_number": 167,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/ping.py",
                                        "issue_text": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
                                        "line_number": 83,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/ssh.py",
                                        "issue_text": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
                                        "line_number": 96,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/yum.py",
                                        "issue_text": "Use of weak SHA1 hash for security. Consider usedforsecurity=False",
                                        "line_number": 73,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/yum.py",
                                        "issue_text": "Use of weak SHA1 hash for security. Consider usedforsecurity=False",
                                        "line_number": 74,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/cuckoo.py",
                                        "issue_text": "Call to requests with verify=False disabling SSL certificate checks, \
                                              security issue.",
                                        "line_number": 107,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/cuckoo.py",
                                        "issue_text": "Call to requests with verify=False disabling SSL certificate checks, \
                                              security issue.",
                                        "line_number": 134,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/cuckoo.py",
                                        "issue_text": "Call to requests with verify=False disabling SSL certificate checks, \
                                              security issue.",
                                        "line_number": 157,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/dshield.py",
                                        "issue_text": "Use of weak SHA1 hash for security. Consider usedforsecurity=False",
                                        "line_number": 132,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/dshield.py",
                                        "issue_text": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
                                        "line_number": 147,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/ssh/transport.py",
                                        "issue_text": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
                                        "line_number": 198,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/ssh_proxy/server_transport.py",
                                        "issue_text": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
                                        "line_number": 308,
                                    },
                                ],
                                "medium_severity_count": 31,
                                "medium_severity_issues": [
                                    {
                                        "filename": "cowrie-2.6.1/src/backend_pool/nat.py",
                                        "issue_text": "Possible binding to all interfaces.",
                                        "line_number": 106,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/backend_pool/nat.py",
                                        "issue_text": "Possible binding to all interfaces.",
                                        "line_number": 109,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/nc.py",
                                        "issue_text": "Possible binding to all interfaces.",
                                        "line_number": 108,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/netstat.py",
                                        "issue_text": "Possible binding to all interfaces.",
                                        "line_number": 74,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/commands/netstat.py",
                                        "issue_text": "Possible binding to all interfaces.",
                                        "line_number": 76,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/core/auth.py",
                                        "issue_text": "Possible binding to all interfaces.",
                                        "line_number": 71,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/core/utils.py",
                                        "issue_text": "Possible binding to all interfaces.",
                                        "line_number": 116,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/abuseipdb.py",
                                        "issue_text": "Pickle and modules that wrap it can be unsafe, \
                                            when used to deserialize untrusted data, possible security issue.",
                                        "line_number": 81,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/cuckoo.py",
                                        "issue_text": "Requests call without timeout",
                                        "line_number": 130,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/cuckoo.py",
                                        "issue_text": "Requests call without timeout",
                                        "line_number": 153,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/malshare.py",
                                        "issue_text": "Requests call without timeout",
                                        "line_number": 90,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/mysql.py",
                                        "issue_text": "Possible SQL injection vector through string-based query construction.",
                                        "line_number": 114,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/output/mysql.py",
                                        "issue_text": "Possible SQL injection vector through string-based query construction.",
                                        "line_number": 125,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/scripts/fsctl.py",
                                        "issue_text": "Pickle and modules that wrap it can be unsafe, \
                                              when used to deserialize untrusted data, possible security issue.",
                                        "line_number": 122,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/shell/fs.py",
                                        "issue_text": "Pickle and modules that wrap it can be unsafe, \
                                              when used to deserialize untrusted data, possible security issue.",
                                        "line_number": 111,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/shell/fs.py",
                                        "issue_text": "Pickle and modules that wrap it can be unsafe, \
                                              when used to deserialize untrusted data, possible security issue.",
                                        "line_number": 114,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/ssh/keys.py",
                                        "issue_text": "DSA key sizes below 2048 bits are considered breakable. ",
                                        "line_number": 61,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/fake_transport.py",
                                        "issue_text": "Use of exec detected.",
                                        "line_number": 82,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_awk.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_base64.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_base_commands.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 264,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_base_commands.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 282,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_base_commands.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 303,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_cat.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_chmod.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_echo.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_ftpget.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 14,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_ls.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_tee.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_tftp.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                    {
                                        "filename": "cowrie-2.6.1/src/cowrie/test/test_uniq.py",
                                        "issue_text": "Probable insecure usage of temp file/directory.",
                                        "line_number": 13,
                                    },
                                ],
                                "actionable_recommendation": "Bandit found vulnerabilities that can be exploited. \
                              Please refer to the StaticHoney's output for more details.",
                            },
                        },
                        "ContainerSecurityScanner": {
                            "attack_type": "Container Security Scan",
                            "description": "Security analysis of container configuration and vulnerabilities",
                            "report_content": {
                                "targets": [
                                    {
                                        "target": "cowrie/cowrie (debian 12.11)",
                                        "secrets": {
                                            "counts": {
                                                "HIGH": 0,
                                                "MEDIUM": 0,
                                                "CRITICAL": 0,
                                            }
                                        },
                                        "vulnerabilities": {
                                            "counts": {
                                                "HIGH": 6,
                                                "MEDIUM": 15,
                                                "CRITICAL": 3,
                                            }
                                        },
                                    },
                                    {
                                        "target": "Python",
                                        "secrets": {
                                            "counts": {
                                                "HIGH": 0,
                                                "MEDIUM": 0,
                                                "CRITICAL": 0,
                                            }
                                        },
                                        "vulnerabilities": {
                                            "counts": {
                                                "HIGH": 0,
                                                "MEDIUM": 0,
                                                "CRITICAL": 0,
                                            }
                                        },
                                    },
                                ],
                                "actionable_recommendation": "Trivy found vulnerabilities in the source code repository. \
                              Check the TrivyScanner section for more info and inform the developer(s) of the security issue.",
                            },
                        },
                        "VulnerableLibrariesAnalyzer": {
                            "attack_type": "Vulnerable Libraries Analysis",
                            "description": "Analysis of vulnerable libraries and dependencies",
                            "report_content": {
                                "libraries": {
                                    "urllib3": {
                                        "library_name": "urllib3",
                                        "vulnerabilities": [
                                            {
                                                "cve": "CVE-2025-50181",
                                                "cvss_score": 5.3,
                                                "vulnerability_id": "pyup.io-77744",
                                                "affected_versions": "<2.5.0",
                                                "severity_category": "medium",
                                            },
                                            {
                                                "cve": "CVE-2025-50182",
                                                "cvss_score": 5.3,
                                                "vulnerability_id": "pyup.io-77745",
                                                "affected_versions": "<2.5.0",
                                                "severity_category": "medium",
                                            },
                                        ],
                                        "vulnerability_count": 2,
                                    },
                                    "requests": {
                                        "library_name": "requests",
                                        "vulnerabilities": [
                                            {
                                                "cve": "CVE-2024-47081",
                                                "cvss_score": 5.3,
                                                "vulnerability_id": "pyup.io-77680",
                                                "affected_versions": "<2.32.4",
                                                "severity_category": "medium",
                                            }
                                        ],
                                        "vulnerability_count": 1,
                                    },
                                    "cryptography": {
                                        "library_name": "cryptography",
                                        "vulnerabilities": [
                                            {
                                                "cve": "CVE-2024-12797",
                                                "cvss_score": 6.3,
                                                "vulnerability_id": "pyup.io-76170",
                                                "affected_versions": ">=42.0.0,<44.0.1",
                                                "severity_category": "medium",
                                            }
                                        ],
                                        "vulnerability_count": 1,
                                    },
                                },
                                "actions_text": "All of these modules need to be updated:\ncryptography, requests, urllib3",
                                "action_required": "All of these modules need to be updated: cryptography, requests, urllib3",
                                "modules_to_update": [
                                    "cryptography",
                                    "requests",
                                    "urllib3",
                                ],
                                "severity_breakdown": {
                                    "low": 0,
                                    "high": 0,
                                    "medium": 4,
                                    "critical": 0,
                                    "no_score": 0,
                                },
                                "total_vulnerabilities": 4,
                                "total_vulnerable_libraries": 3,
                            },
                        },
                    },
                    "attacks_performed": [
                        "VulnerableLibrariesAnalyzer",
                        "StaticAnalyzer",
                        "ContainerSecurityScanner",
                    ],
                },
            },
            "metadata": {
                "filename": "report_2025-08-31_07-17-49.txt",
                "honeypot": {
                    "ip": "172.18.0.9",
                    "name": "cowrie",
                    "ports": [2222],
                    "version": "v2.6.1",
                },
                "report_date": "2025-08-31 07:17:49",
            },
            "recommendations": [
                "All of these modules need to be updated: cryptography, requests, urllib3",
                "Bandit found vulnerabilities that can be exploited. Please refer to the StaticHoney's output for more details.",
                "Trivy found vulnerabilities in the source code repository. \
              Check the TrivyScanner section for more info and inform the developer(s) of the security issue.",
            ],
        }

        patches = [
            if_mock_connections(
                patch(
                    "honeyscanner.main.run_honeyscanner",
                    return_value=honeyscanner_result,
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
