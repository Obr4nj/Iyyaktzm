@echo off
cls
set /p file=File ASM: 
\masm32\bin\ml /c /Zd /coff %file%.asm
\masm32\bin\Link /defaultlib:\masm32\lib\user32.lib /defaultlib:\masm32\lib\kernel32.lib /defaultlib:\Irvine\Irvine32.lib /SUBSYSTEM:CONSOLE %file%.obj
%file%.exe