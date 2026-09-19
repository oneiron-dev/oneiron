# Measurement status

The current Excel goldens have typed setup validation. The LibreOffice receipt uses those corrected inputs.
The formualizer report is the unchanged 0.9.3 first run. It still serializes date/time results as display strings rather than native Excel numeric cache values. The comparison is therefore provisional and MUST NOT enable the in-process default. The production seam now converts those values to serial numbers; rerun the unchanged evaluation for the final baseline before adopting a default.

The original native workbook SHA-256 and the privacy-normalized fixture SHA-256 are both recorded in `../excel/goldens.json`. Native receipts retain the exact Office version. Malformed LET is an explicit Excel formula rejection, not a fabricated cache.
