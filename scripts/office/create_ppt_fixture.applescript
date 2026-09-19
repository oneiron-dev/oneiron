on run argv
    set outputPath to item 1 of argv
    tell application "Microsoft PowerPoint"
        set initialCount to count of presentations
        set appVersion to version
        set p to make new presentation
        set s to make new slide at end of p
        set content of text range of text frame of shape 1 of s to "Retained package oracle"
        save p in POSIX file outputPath as save as Open XML presentation
        close active presentation saving no
        set finalCount to count of presentations
        if finalCount is not initialCount then error "PowerPoint presentation count changed"
        return appVersion & tab & initialCount & tab & finalCount
    end tell
end run
