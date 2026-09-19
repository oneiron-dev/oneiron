on run argv
    set inputPath to item 1 of argv
    set outputPath to item 2 of argv
    set inputName to item 3 of argv
    set outputName to item 4 of argv
    set separator to ASCII character 9
    tell application "Microsoft Excel"
        if (count of workbooks) is 1 then
            set startupBook to active workbook
            if name of startupBook is "Book1" and (path of startupBook as text) is "" and saved of startupBook is true then
                if (count of worksheets of startupBook) is 1 and (value of used range of active sheet) is "" then close startupBook saving no
            end if
        end if
        if (count of workbooks) is not 0 then error "Foreign workbook is open"
        set appVersion to version
        set priorAlerts to display alerts
        set display alerts to false
        set statusCode to 0
        set detail to ""
        set ownedBook to missing value
        try
            open workbook workbook file name (POSIX file inputPath) update links do not update links
            if name of active workbook is not inputName then error "Excel did not open the owned input"
            set ownedBook to active workbook
            calculate full rebuild
            save workbook as ownedBook filename outputPath file format Excel XML file format
            set ownedBook to workbook outputName
            close ownedBook saving no
            set ownedBook to missing value
        on error errorMessage number errorNumber
            set statusCode to errorNumber
            set detail to errorMessage
            if ownedBook is not missing value then close ownedBook saving no
        end try
        set display alerts to priorAlerts
        set finalCount to count of workbooks
        if finalCount is not 0 then error "Owned workbook did not close"
        return appVersion & separator & statusCode & separator & finalCount & separator & detail
    end tell
end run
