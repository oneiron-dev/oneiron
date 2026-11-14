-- Per-shape fit measurements for the deck-create-v1 Office pass.
-- osascript deck_fit.applescript <presentation name> <slide>:<shape index> [...]
-- For each pair, reads shape <index> of slide <slide> of the presentation:
-- its name, frame, whether it has a text frame (then its margins and its
-- text's extent) and whether it has a table (then its row heights).
-- Called by deck_oracle.py between `open` and `pdf`; it never activates,
-- closes, saves or quits anything. One line per pair, lengths as integer
-- EMU: OK<TAB>slide<TAB>index<TAB>name<TAB>left<TAB>top<TAB>width<TAB>height
-- <TAB>text(0|1)<TAB>ml<TAB>mt<TAB>mr<TAB>mb<TAB>bw<TAB>bh<TAB>table(0|1)
-- <TAB>rows, or ERR<TAB>slide<TAB>index<TAB>message for a failing pair.
-- bw is the widest line's glyph extent from the inner left edge: a line's
-- trailing blanks hang past the margin and PowerPoint's `bounds width` counts
-- them (vel, 15 Nov: three false overflows of 0.18-1.75 pt), so they are cut.
-- bh is the text range's `bounds height`. rows is -1 when PowerPoint gives no
-- table rows: its dictionary puts `table object` on `shape table` only, and a
-- table reached as `shape <i> of slide <s>` answers missing value.
on emu(v)
	return (round (v * 12700) rounding as taught in school) as integer
end emu

on run argv
	set presName to item 1 of argv
	set blankChars to {space, tab, character id 13, character id 10, character id 11, character id 12288}
	set rawResults to {}
	tell application "Microsoft PowerPoint"
		repeat with n from 2 to (count of argv)
			set pairText to item n of argv
			set slideNum to 0
			set shapeNum to 0
			try
				set AppleScript's text item delimiters to ":"
				set slideNum to (text item 1 of pairText) as integer
				set shapeNum to (text item 2 of pairText) as integer
				set AppleScript's text item delimiters to ""
				set sh to shape shapeNum of slide slideNum of presentation presName
				set shName to name of sh
				set l to left position of sh
				set t to top of sh
				set w to width of sh
				set h to height of sh
				set hasText to has text frame of sh
				set hasTbl to has table of sh
				if hasText then
					set fr to text frame of sh
					set ml to margin left of fr
					set mt to margin top of fr
					set mr to margin right of fr
					set mb to margin bottom of fr
					set tr to text range of fr
					set bh to bounds height of tr
					set rightMost to missing value
					repeat with i from 1 to (count of lines of tr)
						set ln to line i of tr
						set blankWidth to 0
						set k to count of characters of ln
						repeat while k > 0
							set ch to character k of ln
							if (content of ch) is not in blankChars then exit repeat
							set blankWidth to blankWidth + (bounds width of ch)
							set k to k - 1
						end repeat
						if k > 0 then
							set lineRight to (left bounds of ln) + (bounds width of ln) - blankWidth
							if rightMost is missing value or lineRight > rightMost then set rightMost to lineRight
						end if
					end repeat
					if rightMost is missing value then
						set bw to bounds width of tr
					else
						set bw to rightMost - (l + ml)
					end if
				else
					set ml to 0
					set mt to 0
					set mr to 0
					set mb to 0
					set bw to 0
					set bh to 0
				end if
				if hasTbl then
					-- Never 0 for an unread table: 0 rows would pass any frame.
					set rowsH to -1
					try
						set tbl to table object of sh
						if tbl is not missing value then
							set rowsH to 0
							repeat with r in (every row of tbl)
								set rowsH to rowsH + (height of r)
							end repeat
						end if
					on error
						set rowsH to -1
					end try
				else
					set rowsH to 0
				end if
				set end of rawResults to {"OK", slideNum, shapeNum, shName, l, t, w, h, hasText, ml, mt, mr, mb, bw, bh, hasTbl, rowsH}
			on error errorMessage
				set AppleScript's text item delimiters to ""
				set end of rawResults to {"ERR", slideNum, shapeNum, errorMessage}
			end try
		end repeat
	end tell
	-- Not `lines`: that word names every line element of a text, so assigning to it
	-- fails with -10006 (first Office run on vel, 15 Nov).
	set outputLines to {}
	repeat with r in rawResults
		if item 1 of r is "OK" then
			if item 9 of r then
				set textFlag to 1
			else
				set textFlag to 0
			end if
			if item 16 of r then
				set tableFlag to 1
			else
				set tableFlag to 0
			end if
			set end of outputLines to "OK" & tab & (item 2 of r) & tab & (item 3 of r) & tab & (item 4 of r) & tab & (my emu(item 5 of r)) & tab & (my emu(item 6 of r)) & tab & (my emu(item 7 of r)) & tab & (my emu(item 8 of r)) & tab & textFlag & tab & (my emu(item 10 of r)) & tab & (my emu(item 11 of r)) & tab & (my emu(item 12 of r)) & tab & (my emu(item 13 of r)) & tab & (my emu(item 14 of r)) & tab & (my emu(item 15 of r)) & tab & tableFlag & tab & (my emu(item 17 of r))
		else
			set end of outputLines to "ERR" & tab & (item 2 of r) & tab & (item 3 of r) & tab & (item 4 of r)
		end if
	end repeat
	set AppleScript's text item delimiters to (ASCII character 10)
	set resultText to outputLines as text
	set AppleScript's text item delimiters to ""
	return resultText
end run
