-- Per-shape fit measurements for the deck-create-v1 Office pass.
-- osascript deck_fit.applescript <presentation name> <slide>:<shape index> [...]
-- For each pair, reads shape <index> of slide <slide> of the presentation:
-- its name, frame, whether it has a text frame (then its margins and its
-- text range's bounds) and whether it has a table (then its row heights).
-- Called by deck_oracle.py between `open` and `pdf`; it never activates,
-- closes, saves or quits anything. One line per pair, lengths as integer
-- EMU: OK<TAB>slide<TAB>index<TAB>name<TAB>left<TAB>top<TAB>width<TAB>height
-- <TAB>text(0|1)<TAB>ml<TAB>mt<TAB>mr<TAB>mb<TAB>bw<TAB>bh<TAB>table(0|1)
-- <TAB>rows, or ERR<TAB>slide<TAB>index<TAB>message for a failing pair.
on emu(v)
	return (round (v * 12700) rounding as taught in school) as integer
end emu

on run argv
	set presName to item 1 of argv
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
					set bw to bounds width of tr
					set bh to bounds height of tr
				else
					set ml to 0
					set mt to 0
					set mr to 0
					set mb to 0
					set bw to 0
					set bh to 0
				end if
				if hasTbl then
					-- The sdef carries `table object` on class `shape table`;
					-- PowerPoint may also resolve it on the shape itself.
					try
						set tbl to table object of sh
					on error
						set tbl to table object of shape table 1 of sh
					end try
					set rowsH to 0
					repeat with r in (every row of tbl)
						set rowsH to rowsH + (height of r)
					end repeat
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
	set lines to {}
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
			set end of lines to "OK" & tab & (item 2 of r) & tab & (item 3 of r) & tab & (item 4 of r) & tab & (my emu(item 5 of r)) & tab & (my emu(item 6 of r)) & tab & (my emu(item 7 of r)) & tab & (my emu(item 8 of r)) & tab & textFlag & tab & (my emu(item 10 of r)) & tab & (my emu(item 11 of r)) & tab & (my emu(item 12 of r)) & tab & (my emu(item 13 of r)) & tab & (my emu(item 14 of r)) & tab & (my emu(item 15 of r)) & tab & tableFlag & tab & (my emu(item 17 of r))
		else
			set end of lines to "ERR" & tab & (item 2 of r) & tab & (item 3 of r) & tab & (item 4 of r)
		end if
	end repeat
	set AppleScript's text item delimiters to (ASCII character 10)
	set resultText to lines as text
	set AppleScript's text item delimiters to ""
	return resultText
end run
