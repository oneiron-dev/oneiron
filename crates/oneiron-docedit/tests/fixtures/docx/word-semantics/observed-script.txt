on run argv
    set inputPath to item 1 of argv
    set revisionAction to item 2 of argv
    set textPath to item 3 of argv
    if revisionAction is not "accept" and revisionAction is not "reject" then error "Invalid revision action"
    tell application "Microsoft Word"
        set initialCount to count of documents
        set originalAlerts to display alerts
        set display alerts to alerts none
        set ownedDocument to missing value
        try
            open file name inputPath confirm conversions false read only false add to recent files false repair false showing repairs false
            set ownedDocument to active document
            set appVersion to version
            set beforeCount to count of revisions of ownedDocument
            repeat while (count of revisions of ownedDocument) > 0
                set previousCount to count of revisions of ownedDocument
                if revisionAction is "accept" then
                    accept revision 1 of ownedDocument
                else
                    reject revision 1 of ownedDocument
                end if
                if (count of revisions of ownedDocument) is not less than previousCount then error "Word revision operation made no progress"
            end repeat
            set revisionCount to count of revisions of ownedDocument
            set paragraphCount to count of paragraphs of ownedDocument
            set resolvedText to content of text object of ownedDocument
            set outputFile to open for access POSIX file textPath with write permission
            try
                set eof outputFile to 0
                write resolvedText to outputFile as «class utf8»
                close access outputFile
            on error textError number textNumber
                close access outputFile
                error textError number textNumber
            end try
            close ownedDocument saving no
            set ownedDocument to missing value
            set display alerts to originalAlerts
            set finalCount to count of documents
            if finalCount is not initialCount then error "Word document count changed"
            if finalCount is 0 then quit
            return appVersion & tab & beforeCount & tab & revisionCount & tab & paragraphCount & tab & initialCount & tab & finalCount
        on error errorText number errorNumber
            if ownedDocument is not missing value then
                try
                    close ownedDocument saving no
                end try
            end if
            set display alerts to originalAlerts
            error errorText number errorNumber
        end try
    end tell
end run
