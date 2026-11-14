---
name: oneiron.microsoft365
description: Microsoft 365 connector pack that reads and edits the user's Excel workbooks in place through the credential broker
version: 0.1.0
kind: connector
adapter: built-in:microsoft365
grants: ["excel.write"]
wakes: []
setup: {"skill":"setup","accounts":[{"id":"microsoft","label":"A Microsoft 365 work or school account","sign_up":"https://www.microsoft.com/microsoft-365","note":"An organisation admin may need to consent before third-party apps can use the account's files."}],"connections":[{"id":"microsoft365","label":"Microsoft 365 files","account":"microsoft","auth":"oauth","connector":"microsoft365","secrets":[{"name":"microsoft365.oauth","label":"Microsoft grant","effector":"connector:microsoft365","hint":"Made when you sign in with Microsoft and allow the access you turned on here. Store what the sign-in returns, never your Microsoft password."}],"permissions":[{"id":"excel.write","scope":"https://graph.microsoft.com/Files.ReadWrite","grant":"excel.write","what":"Read and write the Excel workbooks in your OneDrive: their worksheets, cell values, formulas and number formats","risk":"Every file in the account's OneDrive becomes readable by your agent, and a wrong write overwrites cells in a workbook other people may use. OneDrive keeps the version history.","level":"high","optional":true}],"verify":"microsoft365.me"}]}
---

Built-in adapter metadata. Installation does not issue grants or start a wake subscriber.
