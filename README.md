This program is a simple Python script that performs static analysis of a text file for potentially dangerous or suspicious code structures. It is not a full-fledged antivirus, but it can help identify signs of malicious behavior in scripts or configuration files.

How does it work?
The user enters the path to the file for verification.

The program opens the file and reads its contents line by line.

Ignored when reading:

Multi-line comments in the /* style ... */

One-line comments starting with #, //, <!--

For each line, the presence of regular expressions (patterns) that correspond to dangerous or suspicious actions is checked (for example, deleting files from rm -rf, changing access rights to chmod 777, uploading files via wget or curl, executing code via eval or exec, leaking passwords and tokens, etc.).

If the string matches one of the patterns, it is displayed with an indication of the danger level (CRITICAL, HIGH, MEDIUM) and a brief description.

The program warns if the file is a symbolic link or if there are no permissions to read the file.

File processing is implemented taking into account large sizes (streaming reading) and possible errors (missing file, encoding errors, memory errors).

What can she do?
Analyze text files (for example, scripts, configs) for potentially dangerous commands or constructions.

Help you quickly find traces of malicious or risky operations in your code or configurations.

Work on different operating systems (Windows, Linux, etc.), clearing the screen before launching and using cross-platform file management methods.

Warn about problems with accessing the file and the specifics of its location (symbolic links).
