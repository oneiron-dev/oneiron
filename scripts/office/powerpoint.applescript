-- One operation per call; never activate or quit PowerPoint here.
on run argv
    set actionName to item 1 of argv
    if actionName is "custody" then
        tell application "Microsoft PowerPoint"
            -- PowerPoint returns "missing value" for an empty "name of every" query.
            if (count of presentations) is 0 then return ""
            set names to name of every presentation
        end tell
        set AppleScript's text item delimiters to (ASCII character 10)
        set resultText to names as text
        set AppleScript's text item delimiters to ""
        return resultText
    end if
    if actionName is "close" then
        set ownedName to item 2 of argv
        tell application "Microsoft PowerPoint"
            close presentation ownedName saving no
        end tell
        return "closed"
    end if
    set sourceFile to (POSIX file (item 2 of argv)) as alias
    if (count of argv) > 2 then set destination to (POSIX file (item 3 of argv)) as text
    set sourceName to name of (info for sourceFile)
    tell application "Microsoft PowerPoint"
        if actionName is "open" then
            open sourceFile
            repeat 60 times
                try
                    set p to presentation sourceName
                    set slideCount to count of slides of p
                    delay 2
                    return (name of p) & ":" & slideCount
                end try
                delay 0.1
            end repeat
            error "candidate did not open"
        end if
        set p to presentation sourceName
        if actionName is "pdf" then
            save p in destination as save as PDF
            return "pdf requested"
        else if actionName is "saveback" then
            save p in destination as save as Open XML presentation
            return "pptx requested"
        end if
        error "unknown action"
    end tell
end run
