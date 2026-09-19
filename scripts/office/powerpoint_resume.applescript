on run argv
    set expectedDirectory to item 1 of argv
    set expectedName to item 2 of argv
    set outputPath to item 3 of argv
    set pdfPath to item 4 of argv
    tell application "Microsoft PowerPoint"
        set initialCount to count of presentations
        set ownedPresentation to presentation expectedName
        if path of ownedPresentation is not expectedDirectory then error "PowerPoint path mismatch"
        set appVersion to version
        set slideCount to count of slides of ownedPresentation
        log "PowerPoint verified opened input"
        save ownedPresentation in POSIX file outputPath as save as Open XML presentation
        log "PowerPoint saved roundtrip"
        save active presentation in POSIX file pdfPath as save as PDF
        log "PowerPoint exported PDF"
        close active presentation saving no
        set finalCount to count of presentations
        if finalCount is not (initialCount - 1) then error "PowerPoint count mismatch"
        if finalCount is 0 then quit
        return appVersion & tab & slideCount & tab & initialCount & tab & finalCount
    end tell
end run
