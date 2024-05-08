#!/usr/bin/python3

import argparse
import csv
import logging
import requests
import tempfile

from pathlib import Path

URL_BASE = "https://d4twhgtvn0ff5.cloudfront.net"

ALL_FILTERS = {
    "secure_pageloads_all": lambda x: True,  # noqa: ARG005
    "secure_pageloads_USA": lambda x: x["country"] == "US",
    "secure_pageloads_Germany": lambda x: x["country"] == "DE",
    "secure_pageloads_Japan": lambda x: x["country"] == "JP",
    "secure_pageloads_India": lambda x: x["country"] == "IN",
    "secure_pageloads_France": lambda x: x["country"] == "FR",
    "secure_pageloads_Egypt": lambda x: x["country"] == "EG",
    "secure_pageloads_MacOS": lambda x: x["os"] == "Darwin",
}

CERT_TIMELINE_HEADER = {
    "daily_certs_issued": 1,
    "total_certs_active": 2,
    "total_fqdns_active": 3,
    "total_registered_domains_active": 4,
}

PARSER = argparse.ArgumentParser(
    description="""
    Synthesize HTTPS adoption data
"""
)

PARSER.add_argument(
    "--log-level",
    default=logging.WARNING,
    type=lambda x: getattr(logging, x.upper()),
    help="Configure the logging level.",
)

PARSER.add_argument(
    "--cache-dir",
    default=Path(tempfile.gettempdir()),
    type=Path,
    help="The directory to cache files in",
)

PARSER.add_argument("--output", "-o", type=argparse.FileType("w"), default="-")


def get_file(dest_dir, url):
    filename = url.split("/")[-1]
    local_path = Path(dest_dir) / filename
    if not local_path.is_file() or not local_path.stat().st_size:
        logging.info("Downloading %s to %s", url, local_path)
        with requests.get(url, stream=True, timeout=60) as rsp:
            rsp.raise_for_status()
            with Path.open(local_path, "wb") as f:
                for chunk in rsp.iter_content(chunk_size=8192):
                    f.write(chunk)
    return local_path


class CurrentFirefoxStatsDay:
    def __init__(self):
        self._data = []

    def log(self, *, data):
        for x in ["os", "country", "normalized_pageloads", "ratio", "reporting_ratio"]:
            assert x in data
        self._data.append(data)

    def _data_filtered(self, filter_func):
        return filter(filter_func, self._data)

    def _total_normalized_pageloads(self, filter_func):
        return sum(
            float(d["normalized_pageloads"]) for d in self._data_filtered(filter_func)
        )

    def secure_pageload_ratio(self, filter_func):
        total_norm = self._total_normalized_pageloads(filter_func)
        total_secure_pageload_ratio = 0.0
        for d in self._data_filtered(filter_func):
            dimension_normalized_pageloads = (
                float(d["normalized_pageloads"]) / total_norm
            )
            total_secure_pageload_ratio += (
                float(d["ratio"]) * dimension_normalized_pageloads
            )
        return total_secure_pageload_ratio


class CurrentFirefoxStats:
    def __init__(self):
        self._date_to_data = {}

    def for_day(self, date_str):
        if date_str not in self._date_to_data:
            self._date_to_data[date_str] = CurrentFirefoxStatsDay()
        return self._date_to_data[date_str]

    def all_days(self):
        for day in sorted(self._date_to_data.keys()):
            yield day, self._date_to_data[day]


class IssuanceStatsDay:
    def __init__(self):
        self._data = {}

    def log(self, *, data):
        self._data = data

    def data(self):
        return self._data


class IssuanceStats:
    def __init__(self):
        self._date_to_data = {}

    def for_day(self, date_str):
        if date_str not in self._date_to_data:
            self._date_to_data[date_str] = IssuanceStatsDay()
        return self._date_to_data[date_str]


def main():
    """Start here."""
    args = PARSER.parse_args()
    logging.basicConfig(level=args.log_level)

    https_current_adoption = URL_BASE + "/current-https-adoption.csv"
    cur_path = get_file(args.cache_dir, https_current_adoption)

    cert_timeline = URL_BASE + "/cert-timeline.tsv"
    timeline_path = get_file(args.cache_dir, cert_timeline)

    firefox_stats = CurrentFirefoxStats()
    issuance_stats = IssuanceStats()

    with cur_path.open() as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            firefox_stats.for_day(row["submission_date"]).log(data=row)

    with timeline_path.open() as csvfile:
        reader = csv.reader(csvfile, dialect="excel-tab")
        for row in reader:
            if row:
                issuance_stats.for_day(row[0]).log(data=row)
            else:
                logging.debug("Skipping empty row from %s", timeline_path)

    # Prepare the output CSV writer with all headers
    field_names = ["date"] + [*ALL_FILTERS] + [*CERT_TIMELINE_HEADER]
    csv_writer = csv.DictWriter(args.output, fieldnames=field_names)
    csv_writer.writeheader()

    # Process all days
    for day, day_stats in firefox_stats.all_days():
        row = {"date": day}
        for name, func in ALL_FILTERS.items():
            row[name] = day_stats.secure_pageload_ratio(func)

        i_data = issuance_stats.for_day(day).data()
        if i_data:
            for name, row_id in CERT_TIMELINE_HEADER.items():
                row[name] = i_data[row_id]
        else:
            logging.debug("No Let's Encrypt issuance stats for date %s", day)
        csv_writer.writerow(row)
        logging.info(" ".join([f"{key}: {value}" for key, value in row.items()]))


if __name__ == "__main__":
    main()
