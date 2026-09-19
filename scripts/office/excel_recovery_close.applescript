on run argv
    set expectedName to item 1 of argv
    set expectedPath to item 2 of argv
    tell application "Microsoft Excel"
        if (count of workbooks) is not 1 then error "Workbook custody changed"
        if name of workbook 1 is not expectedName then error "Not the owned workbook"
        if (path of workbook 1 as text) is not expectedPath then error "Not the owned staging path"
        set ownedBook to workbook expectedName
        close ownedBook saving no
        return count of workbooks
    end tell
end run
