on run argv
    set workbookName to item 1 of argv
    set outputPath to item 2 of argv
    set outputName to item 3 of argv
    tell application "Microsoft Excel"
        set ownedBook to workbook workbookName
        if (path of ownedBook as text) is not "" then error "Oracle input workbook is already saved"
        set priorAlerts to display alerts
        set display alerts to false
        try
            save workbook as ownedBook filename outputPath file format Excel XML file format
            close workbook outputName saving no
            set display alerts to priorAlerts
        on error errorMessage number errorNumber
            set display alerts to priorAlerts
            error errorMessage number errorNumber
        end try
        set remaining to count of workbooks
        if remaining is 0 then quit
        return remaining
    end tell
end run
