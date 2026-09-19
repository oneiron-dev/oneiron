set sep to (ASCII character 9)
set lineBreak to (ASCII character 10)
tell application "Microsoft Excel"
    set savedPaths to get path of workbooks
    set n to count of workbooks
    set answer to (n as text) & lineBreak
    repeat with i from 1 to n
        set bookName to name of workbook i as text
        set bookPath to path of workbook i as text
        set bookSaved to saved of workbook i as text
        set answer to answer & bookName & sep & bookPath & sep & bookSaved & lineBreak
    end repeat
    return answer
end tell
