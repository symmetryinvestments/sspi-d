
Dlang wrapper for Windows SSPI authentication

[![Build status](https://ci.appveyor.com/api/projects/status/ve5ecj8ejrxsxt8b/branch/master?svg=true)](https://ci.appveyor.com/project/Laeeth/sspi-d/branch/master)


Client works and is used in production.  ClientAuth.authorize [leaks memory](https://github.com/symmetryinvestments/sspi-d/blob/ff9438c5cb81e8ec6ebb95673e2c83316f0ceea3/source/sspi/package.d#L276) since for some unknown reason releasing memory leads to a crash.  It's not much memory and the code only runs on authorization so it was not a problem in production.
Server builds but has not even been tested.

- incomplete client example in examples/client
- complete server example in examples/server (builds but not tested yet)

Pull Requests welcomed!

