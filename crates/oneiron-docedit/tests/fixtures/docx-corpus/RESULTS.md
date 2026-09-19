# W7-C14 Word oracle: docx comparison 3

Finished 2026-09-19 16:03 JST on the MacBook. Word 16.112.4 is the truth. LibreOffice 25.8.2.2 is the comparison engine.

- Corpus: 40 DOCX inputs (docx4j, poi, stemma). The native no-op archive round trip is byte exact on 40/40.
- The native editor proposed an edit on 15/40. The other 25 were refused (23 refused, 2 gate_rejected). They are unscored and listed in receipt.json.
- Word accepted every pending revision in all 15 native proposals: 15/15 pass. Word never asked for a repair.
- LibreOffice re-saved the same 15 edited files, then Word read them again: 14/15 match Word on resolved text, paragraph count and pending revision count.
- The one miss is docx4j/root/tracked-changes-equations.docx. The native output holds 13 pending revisions. After LibreOffice, Word sees 1 revision and a different resolved text. LibreOffice drops tracked changes inside equations. The native path keeps them.

Files on the MacBook (olety@100.124.216.116):
- /Users/olety/w7-oracle/W7-C14/docx-comparison-3/receipt.json: every case, both Word receipts, resolved texts and hashes.
- /Users/olety/w7-oracle/W7-C14/docx-comparison-3/case-NNN/: input.docx, the LibreOffice output, word-native/ and word-libreoffice/ receipts and driver logs.

Fetch from Arch:
    scp -r olety@100.124.216.116:/Users/olety/w7-oracle/W7-C14/docx-comparison-3 <dest>

Driver change in this run: the Word oracles stage each input inside Word's sandbox container (no Grant File Access prompt) and Word stays open between calls (a quit and relaunch raced LaunchServices and failed with -600). The runner quits Word once at the end. Receipt script_sha256 values changed with the scripts.
