on run argv
    set inputPath to item 1 of argv
    set outputPath to item 2 of argv
    set inputName to item 3 of argv
    set outputName to item 4 of argv
    set separator to ASCII character 9
    tell application "Microsoft Excel"
        my closeBlankStartup()
        set beforeIdentities to my workbookIdentities()
        if beforeIdentities is not {} then error "Foreign or recovered workbook is open"
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
        if (my workbookIdentities()) is not beforeIdentities then error "Workbook identities changed"
        return appVersion & separator & statusCode & separator & finalCount & separator & detail
    end tell
end run

-- Close only Excel's untouched startup document. A named/recovered/edited workbook is foreign.
on closeBlankStartup()
    tell application "Microsoft Excel"
        repeat with i from (count of workbooks) to 1 by -1
            if (name of workbook i) is "Book1" and ((path of workbook i) as text) is "" and (saved of workbook i) is true then
                if (count of worksheets of workbook i) is 1 then
                    set s to worksheet 1 of workbook i
                    if (name of s) is "Sheet1" and (count of shapes of s) is 0 then
                        if (value of used range of s) is "" and (formula of used range of s) is "" then close workbook i saving no
                    end if
                end if
            end if
        end repeat
    end tell
end closeBlankStartup

-- Index iteration avoids Excel's -50 on a repeat-reference path. Unsaved work is NEVER ignored.
on workbookIdentities()
    set identities to {}
    tell application "Microsoft Excel"
        repeat with i from 1 to count of workbooks
            set identity_ to {(name of workbook i) as text, (path of workbook i) as text, saved of workbook i}
            set end of identities to identity_
        end repeat
    end tell
    return identities
end workbookIdentities
