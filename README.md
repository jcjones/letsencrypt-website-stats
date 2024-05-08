# Summarize Let's Encrypt statistics

This pulls statistics from the Let's Encrypt stats page sources and summarizes them as a CSV file.

Uses the algorithm from https://docs.telemetry.mozilla.org/datasets/other/ssl/reference.html

`ALL_FILTERS` in the `main.py` defines filters by country, OS, or whatever you want.

Country codes are from the ISO 639 two-character country code list.
