-- PowerPoint's windows, one entry each, read by index (deck_session.windows).
-- A window that closes while it is read (-1719 invalid index, -1728 no such
-- object) leaves a VANISHED entry, so the observation is read again rather
-- than taken as the deck's. Dialog text rides as DIALOG entries.
tell application "System Events"
    tell process "Microsoft PowerPoint"
        set labels to {}
        set windowCount to count of windows
        repeat with i from 1 to windowCount
            try
                set w to window i
                set windowKind to "WINDOW:"
                if subrole of w is "AXDialog" then set windowKind to "DIALOG:"
                set entryLabels to {}
                set windowTitle to name of w
                if windowTitle is not missing value then set end of entryLabels to windowKind & (windowTitle as text)
                if windowKind is "DIALOG:" then
                    set textValues to get value of every static text of w
                    repeat with textEntry in textValues
                        set actualText to contents of textEntry
                        if actualText is not missing value then set end of entryLabels to "DIALOG:" & (actualText as text)
                    end repeat
                end if
                set labels to labels & entryLabels
            on error errorMessage number errorNumber
                if errorNumber is not -1719 and errorNumber is not -1728 then error errorMessage number errorNumber
                set end of labels to "VANISHED:"
            end try
        end repeat
    end tell
end tell
set AppleScript's text item delimiters to (ASCII character 30)
set resultText to labels as text
set AppleScript's text item delimiters to ""
return resultText
