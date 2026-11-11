---
name: oneiron.sheets
description: Google Sheets connector that reads and writes spreadsheets through the credential broker
version: 0.1.0
kind: connector
adapter: built-in:sheets
grants: ["sheets.read", "sheets.write"]
wakes: []
setup: {"skill":"setup","accounts":[{"id":"google","label":"A Google account or Google Workspace account","sign_up":"https://accounts.google.com/signup","note":"A Workspace admin may need to allow third-party apps to use Google Sheets."}],"connections":[{"id":"sheets","label":"Google Sheets","account":"google","auth":"oauth","connector":"google.sheets","secrets":[{"name":"sheets.oauth","label":"Google Sheets grant","effector":"connector:google.sheets","hint":"Made when you sign in with Google and allow Sheets access. Store what the sign-in returns, never your Google password."}],"permissions":[{"id":"read","scope":"https://www.googleapis.com/auth/spreadsheets.readonly","grant":"sheets.read","what":"Read the spreadsheets your Google account can open: their sheets and cell values","risk":"Every spreadsheet the account can open, shared ones included, becomes readable by your agent.","level":"high"},{"id":"write","scope":"https://www.googleapis.com/auth/spreadsheets","grant":"sheets.write","what":"Write cell values and change sheets: add, rename, format or delete them","risk":"A wrong write overwrites cells or deletes a sheet in a spreadsheet other people may use. Google keeps the version history.","level":"high","optional":true}],"verify":"sheets.token"}]}
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
