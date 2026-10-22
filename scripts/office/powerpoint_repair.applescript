-- Cancel only the repair alert naming the staged deck (item 1 of argv); never
-- repair or grant access. Windows are read by index; one that closes while it
-- is read is skipped.
on run argv
    tell application "System Events"
        tell process "Microsoft PowerPoint"
            set windowCount to count of windows
            repeat with i from 1 to windowCount
                try
                    set w to window i
                    if subrole of w is "AXDialog" then
                        set messageText to ""
                        set textValues to get value of every static text of w
                        repeat with textEntry in textValues
                            set actualText to contents of textEntry
                            if actualText is not missing value then set messageText to messageText & " " & (actualText as text)
                        end repeat
                        if messageText contains (item 1 of argv) and messageText contains "PowerPoint can attempt to repair" then
                            click button "Cancel" of w
                            return "cancelled owned repair alert"
                        end if
                    end if
                on error errorMessage number errorNumber
                    if errorNumber is not -1719 and errorNumber is not -1728 then error errorMessage number errorNumber
                end try
            end repeat
        end tell
    end tell
    error "owned repair alert not found; no UI action taken"
end run
