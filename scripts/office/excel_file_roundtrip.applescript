on run argv
    set fieldBreak to (ASCII character 9)
    set inputPath to item 1 of argv
    set outputPath to item 2 of argv
    set outputName to item 3 of argv
    set sheetName to item 4 of argv
    set cellName to item 5 of argv
    set inputName to item 6 of argv
    tell application "Microsoft Excel"
        my closeBlankStartup()
        set initialCount to count of workbooks
        set beforeIdentities to my workbookIdentities()
        set savedBefore to my identityField(beforeIdentities)
        if exists workbook inputName then error "Oracle input is already open"
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
            set afterIdentities to my workbookIdentities()
            if beforeIdentities is not afterIdentities then error "Workbook identities changed"
            set savedAfter to my identityField(afterIdentities)
            return appVersion & fieldBreak & (observedValue as text) & fieldBreak & initialCount & fieldBreak & finalCount & fieldBreak & savedBefore & fieldBreak & savedAfter
        on error errorMessage number errorNumber
            set display alerts to priorAlerts
            error errorMessage number errorNumber
        end try
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

on identityField(identities)
    set field_ to "["
    repeat with identity_ in identities
        set field_ to field_ & (item 1 of identity_) & ">" & (item 2 of identity_) & ">" & (item 3 of identity_ as text) & ";"
    end repeat
    return field_ & "]"
end identityField
