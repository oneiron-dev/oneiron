on run argv
    set inputPath to item 1 of argv
    set outputPath to item 2 of argv
    set pdfPath to item 3 of argv
    tell application "Microsoft Word"
        log "Word inventory"
        set initialCount to count of documents
        set originalAlerts to display alerts
        set display alerts to alerts none
        set ownedDocument to missing value
        try
            log "Word opening verified input"
            open file name inputPath confirm conversions false read only true add to recent files false repair false showing repairs false
            log "Word input opened"
            set ownedDocument to active document
            set appVersion to version
            set revisionCount to count of revisions of ownedDocument
            set commentCount to count of word comments of ownedDocument
            set paragraphCount to count of paragraphs of ownedDocument
            set show revisions of ownedDocument to true
            log "Word saving native roundtrip"
            save as ownedDocument file name outputPath file format format document default add to recent files false
            set ownedDocument to active document
            log "Word exporting PDF"
            save as ownedDocument file name pdfPath file format format PDF add to recent files false
            close ownedDocument saving no
            set ownedDocument to missing value
            set display alerts to originalAlerts
            set finalCount to count of documents
            if finalCount is not initialCount then error "Word document count changed"
            return appVersion & tab & revisionCount & tab & commentCount & tab & paragraphCount & tab & initialCount & tab & finalCount
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
