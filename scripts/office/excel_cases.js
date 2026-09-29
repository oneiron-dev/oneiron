// Excel oracle. The caller owns the shared Office lock and a 120-second osascript alarm.
ObjC.import("Foundation");
function run(argv) {
    var input = JSON.parse(ObjC.unwrap($.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, null)));
    var app = Application("Microsoft Excel");
    var report = {version:app.version(),initialWorkbooks:(app.workbooks() || []).length,cases:[]};
    var alerts = app.displayAlerts();
    try {
        app.displayAlerts = false;
        input.cases.forEach(function(c) {
            var wb = null, name = null;
            var row = {id:c.id,status:"error",stage:"new",file:c.file};
            try {
                wb = app.make({new:"workbook"});
                name = wb.name();
                wb.date1904 = false;
                var sheet = wb.worksheets[0];
                sheet.name = "Sheet1";
                row.stage = "setup";
                Object.keys(c.setup_cells || {}).forEach(function(address) {
                    var value = c.setup_cells[address];
                    if (value === null) return;
                    if (typeof value === "string" && value.charAt(0) === "=") sheet.ranges[address].formula2 = value;
                    else {
                        // Preserve the corpus's typed string: Excel otherwise
                        // converts "2" and "TRUE" into numeric/boolean cells.
                        if (typeof value === "string") sheet.ranges[address].numberFormat = "@";
                        sheet.ranges[address].value = value;
                    }
                });
                sheet.ranges["Z1"].formula2 = "=1111+2222";
                var anchor = c.check_range ? c.check_range.split(":")[0] : "F1";
                row.stage = "formula";
                try { sheet.ranges[anchor].formula2 = c.formula; }
                catch (error) { row.formulaError = String(error); }
                row.formulaRetained = sheet.ranges[anchor].hasFormula();
                if (!row.formulaRetained && !row.formulaError) row.formulaError = "Excel did not retain the requested formula";
                row.stage = "recalc";
                sheet.calculate();
                row.canary = sheet.ranges["Z1"].value2();
                row.date1904 = wb.date1904();
                row.stage = "calculated";
                row.status = row.formulaError ? "formula-rejected" : "ok";
            } catch (error) { row.error = String(error); }
            finally { row.workbookName = name; }
            report.cases.push(row);
            if (row.status === "cleanup-error" || row.status === "error") throw new Error(JSON.stringify(row));
        });
    } catch (error) { report.error=String(error); }
    finally {
        console.log("restoring alerts");
        app.displayAlerts = alerts;
        console.log("reading final workbook count");
        report.finalWorkbooks = (app.workbooks() || []).length;
    }
    return JSON.stringify(report);
}
