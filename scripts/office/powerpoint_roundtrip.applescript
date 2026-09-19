on run argv
    set inputPath to item 1 of argv
    set outputPath to item 2 of argv
    set pdfPath to item 3 of argv
    tell application "Microsoft PowerPoint"
        set initialCount to count of presentations
        log "PowerPoint opening verified input"
        open POSIX file inputPath
        set ownedPresentation to active presentation
        set appVersion to version
        set slideCount to count of slides of ownedPresentation
        save active presentation in POSIX file outputPath as save as Open XML presentation
        save active presentation in POSIX file pdfPath as save as PDF
        close active presentation saving no
        set finalCount to count of presentations
        if finalCount is not initialCount then error "PowerPoint presentation count changed"
        if finalCount is 0 then quit
        return appVersion & tab & slideCount & tab & initialCount & tab & finalCount
    end tell
end run
