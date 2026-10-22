-- Click one dismiss button of the AXDialog window whose title or static text
-- is item 1 of argv; the rest of argv names the buttons, in the order tried.
-- When none is found, the window's own close button. A window that closes
-- while it is read (-1719, -1728) is skipped, never an error (deck_session).
on run argv
    set wanted to item 1 of argv
    set buttonNames to rest of argv
    tell application "System Events"
        tell process "Microsoft PowerPoint"
            set windowCount to count of windows
            repeat with i from 1 to windowCount
                try
                    set w to window i
                    if subrole of w is "AXDialog" then
                        set labels to {}
                        set windowTitle to name of w
                        if windowTitle is not missing value then set end of labels to (windowTitle as text)
                        repeat with textEntry in (get value of every static text of w)
                            set actualText to contents of textEntry
                            if actualText is not missing value then set end of labels to (actualText as text)
                        end repeat
                        if labels contains wanted then
                            repeat with buttonName in buttonNames
                                if exists button (buttonName as text) of w then
                                    click button (buttonName as text) of w
                                    return "clicked " & (buttonName as text)
                                end if
                            end repeat
                            repeat with element in (entire contents of w)
                                try
                                    if role of element is "AXButton" then
                                        set elementName to name of element
                                        repeat with buttonName in buttonNames
                                            if elementName is (buttonName as text) then
                                                click element
                                                return "clicked " & elementName
                                            end if
                                        end repeat
                                    end if
                                end try
                            end repeat
                            repeat with element in (every button of w)
                                if subrole of element is "AXCloseButton" then
                                    click element
                                    return "clicked the window's close button"
                                end if
                            end repeat
                            return "no dismiss button found"
                        end if
                    end if
                on error errorMessage number errorNumber
                    if errorNumber is not -1719 and errorNumber is not -1728 then error errorMessage number errorNumber
                end try
            end repeat
        end tell
    end tell
    return "the dialog was gone"
end run
