on run argv
    set workbookName to item 1 of argv
    set expectedPath to item 2 of argv
    tell application "Microsoft Excel"
        set ownedBook to workbook workbookName
        if (path of ownedBook as text) is not expectedPath then error "Oracle workbook path does not match"
        close ownedBook saving no
        set remaining to count of workbooks
        if remaining is 0 then quit
        return remaining
    end tell
end run
