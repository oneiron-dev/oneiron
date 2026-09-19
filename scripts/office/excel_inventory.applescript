on run argv
    set sep to (ASCII character 9)
    my closeBlankStartup()
    set result_ to ""
    tell application "Microsoft Excel"
        repeat with i from 1 to count of workbooks
            set name_ to (name of workbook i) as text
            set path_ to (path of workbook i) as text
            set saved_ to (saved of workbook i) as text
            if name_ contains sep or name_ contains linefeed or path_ contains sep or path_ contains linefeed then error "Unrepresentable workbook identity"
            set result_ to result_ & name_ & sep & path_ & sep & saved_ & linefeed
        end repeat
    end tell
    return result_
end run

-- Close only Excel's untouched startup document. A named/recovered/edited workbook is foreign.
on closeBlankStartup()
    tell application "Microsoft Excel"
        repeat with i from (count of workbooks) to 1 by -1
            if (name of workbook i) is "Book1" and ((path of workbook i) as text) is "" and (saved of workbook i) is true then
                if (count of worksheets of workbook i) is 1 then
                    set s to worksheet 1 of workbook i
                    if (name of s) is "Sheet1" and (count of shapes of s) is 0 then
                        if (value of used range of s) is "" and (formula of used range of s) is "" then close workbook i saving no
                    end if
                end if
            end if
        end repeat
    end tell
end closeBlankStartup

