@echo off
rem
rem  Unattended installer for the Claude Code safeguards (Windows).
rem
rem  Safe to run from a remote shell (SSH, WinRM, PsExec) or an RMM job: it
rem  never prompts and returns a distinct exit code on failure.
rem
rem    install.bat                      :: user install -> %USERPROFILE%\.claude
rem    install.bat --dry-run            :: print what would change, write nothing
rem    install.bat --ref v1.2.0         :: install a specific branch or tag
rem    install.bat --project C:\src\app :: project install -> <dir>\.claude
rem    install.bat --uninstall
rem
rem  If install.cjs sits next to this script (you cloned the repo), that copy is
rem  used. Otherwise the repo is cloned into %TEMP% and removed again afterwards.
rem
rem  Run it as the developer who uses Claude Code. An RMM agent running as
rem  SYSTEM installs into SYSTEM's profile, where Claude Code will never read
rem  it -- push it as the logged-on user instead.
rem
rem  Exit codes: 0 ok | 2 bad usage | 3 missing prerequisite | 4 download failed
rem              5 installer failed

setlocal EnableExtensions EnableDelayedExpansion

set "REPO_URL=https://github.com/thecrmfirm/claude_safeguards.git"
set "REF="
set "PROJECT_DIR="
set "MODE_PROJECT=0"
set "PASS_THROUGH="
set "KEEP_CLONE=0"
set "DRY=0"
set "TMP_CLONE="
set "RC=0"

rem --- arguments ---------------------------------------------------------

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="--repo"      goto opt_repo
if /i "%~1"=="--ref"       goto opt_ref
if /i "%~1"=="--project"   goto opt_project
if /i "%~1"=="--dry-run"   goto opt_dryrun
if /i "%~1"=="--uninstall" goto opt_uninstall
if /i "%~1"=="--keep"      goto opt_keep
if /i "%~1"=="--help"      goto usage
if /i "%~1"=="-h"          goto usage
if /i "%~1"=="/?"          goto usage
call :err "unknown option: %~1 (try --help)"
set "RC=2"
goto done

:opt_repo
if "%~2"=="" ( call :err "--repo needs a URL" & set "RC=2" & goto done )
set "REPO_URL=%~2"
shift
shift
goto parse

:opt_ref
if "%~2"=="" ( call :err "--ref needs a branch or tag" & set "RC=2" & goto done )
set "REF=%~2"
shift
shift
goto parse

:opt_project
set "MODE_PROJECT=1"
set "NEXT=%~2"
if not defined NEXT goto opt_project_done
if "!NEXT:~0,1!"=="-"  goto opt_project_done
set "PROJECT_DIR=%~2"
shift
:opt_project_done
shift
goto parse

:opt_dryrun
set "DRY=1"
set "PASS_THROUGH=%PASS_THROUGH% --dry-run"
shift
goto parse

:opt_uninstall
set "PASS_THROUGH=%PASS_THROUGH% --uninstall"
shift
goto parse

:opt_keep
set "KEEP_CLONE=1"
shift
goto parse

:parsed

rem --- prerequisites -----------------------------------------------------

where node >nul 2>&1
if errorlevel 1 (
  call :err "node not found on PATH. Install Node 18+ and re-run."
  set "RC=3"
  goto done
)

node -e "process.exit(parseInt(process.versions.node,10)>=18?0:1)" >nul 2>&1
if errorlevel 1 (
  call :err "Node 18+ required. Found:"
  node --version 1>&2
  set "RC=3"
  goto done
)

rem --- locate the sources ------------------------------------------------

set "SRC=%~dp0"
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"

if exist "%SRC%\install.cjs" (
  call :log "Using local sources at %SRC%"
  goto have_src
)

where git >nul 2>&1
if errorlevel 1 (
  call :err "git not found on PATH, and no local copy next to this script."
  set "RC=3"
  goto done
)

set "TMP_CLONE=%TEMP%\claude_safeguards_%RANDOM%%RANDOM%"
set "SRC=%TMP_CLONE%\repo"
set "BRANCH_ARG="
if defined REF set "BRANCH_ARG=--branch "%REF%""
call :log "Cloning %REPO_URL% %REF%"
rem GIT_TERMINAL_PROMPT=0 makes a credential prompt fail instead of hanging a
rem job that has no console attached.
set "GIT_TERMINAL_PROMPT=0"
git clone --quiet --depth 1 %BRANCH_ARG% "%REPO_URL%" "%SRC%"
if errorlevel 1 (
  call :err "clone failed. Check the URL, the ref, and this machine's git credentials."
  set "RC=4"
  goto done
)

:have_src
if not exist "%SRC%\install.cjs" (
  call :err "install.cjs not found in %SRC%"
  set "RC=4"
  goto done
)

rem --- run the installer -------------------------------------------------

if "%MODE_PROJECT%"=="1" goto project_install

call :log "Running user install for %USERNAME% (home: %USERPROFILE%)"
node "%SRC%\install.cjs"%PASS_THROUGH%
if errorlevel 1 (
  call :err "installer failed (see output above)."
  set "RC=5"
  goto done
)
goto finished

:project_install
set "TARGET=%PROJECT_DIR%"
if not defined TARGET set "TARGET=%CLAUDE_PROJECT_DIR%"
if not defined TARGET set "TARGET=%CD%"
if not exist "%TARGET%\" (
  call :err "project directory does not exist: %TARGET%"
  set "RC=2"
  goto done
)
pushd "%TARGET%" || ( call :err "cannot enter %TARGET%" & set "RC=2" & goto done )
set "TARGET=%CD%"

rem A project install references %CLAUDE_PROJECT_DIR%\hooks, so the hooks have
rem to be in the project before the installer wires them up.
if /i not "%SRC%"=="%TARGET%" (
  if "%DRY%"=="1" (
    call :log "DRY RUN - would copy hooks -> %TARGET%\hooks"
  ) else (
    call :log "Copying hooks -> %TARGET%\hooks"
    xcopy "%SRC%\hooks" "%TARGET%\hooks\" /E /I /Y /Q >nul
    if errorlevel 1 (
      call :err "copying hooks into %TARGET% failed."
      popd
      set "RC=5"
      goto done
    )
  )
)

call :log "Running project install in %TARGET%"
set "CLAUDE_PROJECT_DIR=%TARGET%"
node "%SRC%\install.cjs" --project%PASS_THROUGH%
if errorlevel 1 (
  call :err "installer failed (see output above)."
  popd
  set "RC=5"
  goto done
)
popd

:finished
call :log "Finished. Restart Claude Code, or type /hooks in an open session and press Esc."
goto done

rem --- helpers -----------------------------------------------------------

:log
echo %DATE% %TIME% [safeguards] %~1
goto :eof

:err
echo %DATE% %TIME% [safeguards] ERROR: %~1 1>&2
goto :eof

:usage
for /f "tokens=1,* delims=:" %%a in ('findstr /n "^rem" "%~f0"') do (
  if %%a LEQ 22 echo.%%b
)
goto done

:done
if defined TMP_CLONE if "%KEEP_CLONE%"=="0" if exist "%TMP_CLONE%\" rd /s /q "%TMP_CLONE%" 2>nul
endlocal & exit /b %RC%
