#Requires AutoHotkey v2.0

; Set working directory to script location
SetWorkingDir A_ScriptDir

; Windows + F hotkey
#f:: {
    try {
        ; Save the current active window
        ActiveWindow := WinExist("A")

        ; Attempt to run the cargo executable
        Target := A_ScriptDir . "/target/debug/mini-insecure-totp.exe"
        Temp := A_ScriptDir . "/scratch/temp_out.txt"
        Secret := CredRead("totp_secret|ff")
        Code := RunWaitOne(Target ' ' Secret)

        ; Focus the previously active window
        ; since the console window from the exe might still be active
        WinActivate ActiveWindow
        Send Code
    } catch Error as err {
        MsgBox Format("{1}: {2}.`n`nFile:`t{3}`nLine:`t{4}`nWhat:`t{5}`nStack:`n{6}"
        , type(err), err.Message, err.File, err.Line, err.What, err.Stack)
    }
}

; https://www.autohotkey.com/docs/v2/lib/Run.htm#ExStdOut
RunWaitOne(command) {
    shell := ComObject("WScript.Shell")
    ; Execute a single command via cmd.exe
    exec := shell.Exec(A_ComSpec " /C " command)
    ; Read and return the command's output
    return exec.StdOut.ReadAll() . exec.StdErr.ReadAll()
}

; based on https://www.reddit.com/r/AutoHotkey/comments/1051mkc/storing_/j3921wj/
; and https://www.autohotkey.com/boards/viewtopic.php?t=116285
; https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw
CredRead(name)
{
    pCred := 0
    CRED_TYPE_GENERIC := 1
    Success := DllCall("Advapi32.dll\CredReadW"
      , "Str", name                    ; [in]  LPCWSTR      TargetName
      , "UInt", CRED_TYPE_GENERIC      ; [in]  DWORD
      , "UInt", 0                      ; [in]  DWORD        Flags
      , "Ptr*", &pCred                 ; [out] PCREDENTIALW *Credential
      , "UInt" ; BOOL
    )
    
    if !Success || !pCred
        throw OsError()

    ; CREDENTIALW struct: https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
    ; name     := StrGet(NumGet(pCred + 8  + A_PtrSize * 0, "UPtr"), 256, "UTF-16")
    ; username := StrGet(NumGet(pCred + 24 + A_PtrSize * 6, "UPtr"), 256, "UTF-16")
    len      := NumGet(       pCred + 16 + A_PtrSize * 2, "UInt")
    password := StrGet(NumGet(pCred + 16 + A_PtrSize * 3, "UPtr"), len/2, "UTF-16")
    DllCall("Advapi32.dll\CredFree", "Ptr", pCred)
    return password
}