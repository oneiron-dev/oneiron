# Native Word revision semantics

The inputs are authored by `oneiron-docedit` examples, not imported Office data.
Receipts pin each input SHA-256, the AppleScript SHA-256 and Word 16.112.4.
The no-save revision oracle keeps inputs unchanged and restores the document count.

- Text insertion/deletion: accepting changes yields the authored final view;
  rejecting changes yields the original text. Both have three paragraphs.
- Paragraph-mark deletion: accepting joins only the first two paragraphs;
  rejecting restores all three paragraph boundaries.

`test_office_measurements.py` validates these stored observations without launching
Office. These four receipts do not stand in for the broader DOCX corpus comparison.
