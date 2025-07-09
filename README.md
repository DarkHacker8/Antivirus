How does it work?

Here are the main stages of the program (based on the provided code):

Importing libraries:
Standard Python libraries are used: os, pathlib, platform, re.

Checking the file:
Determines the actual path to the file (takes into account symbolic links).
Checks whether the program has the rights to read the file.
Warns you if the file is a symlink.

File streaming:
The file is read line by line, which allows you to process even very large files without loading them completely into memory.

Comment processing:
The program can skip both single-line (#, //) and multi-line (/* ... */) comments, so as not to analyze their contents.

Search for patterns:
To search for malicious code, regular expressions (patterns) are used, which are passed to the function.
All unique strings that match these patterns are saved.

Output of results:
If something suspicious is found, the program informs the user about it.

What can she do?

Scan files for malicious or suspicious lines of code according to specified patterns.
Ignore comments in the code so that there are no false positives.
Work with large files without the risk of "overflowing" memory.
Check access rights and process symlinks correctly.
