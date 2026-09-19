on run argv
    set separator to ASCII character 9
    set inputPath to item 1 of argv
    set outputPath to item 2 of argv
    set outputName to item 3 of argv
    set sheetName to item 4 of argv
    set cellName to item 5 of argv
    set inputName to item 6 of argv
    tell application "Microsoft Excel"
        set initialCount to count of workbooks
        if exists workbook inputName then error "Oracle input is already open"
        set startupBlank to 0
        if initialCount is 1 then
            set wb to active workbook
            if name of wb is "Book1" and (path of wb as text) is "" and saved of wb is true then
                if (count of worksheets of wb) is 1 and (value of used range of active sheet) is "" then set startupBlank to 1
            end if
        end if
        set appVersion to version
        set priorAlerts to display alerts
        set display alerts to false
        try
            open POSIX file inputPath
            set ownedBook to active workbook
            set observedValue to value of range cellName of worksheet sheetName of ownedBook
            save workbook as ownedBook filename outputPath file format Excel XML file format
            close workbook outputName saving no
            set display alerts to priorAlerts
            set finalCount to count of workbooks
            if finalCount is 0 then quit
            return appVersion & separator & (observedValue as text) & separator & initialCount & separator & finalCount & separator & startupBlank
        on error errorMessage number errorNumber
            set display alerts to priorAlerts
            error errorMessage number errorNumber
        end try
    end tell
end run
