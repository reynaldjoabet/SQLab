# Postgres Locks

`/usr/bin/false` or `/usr/bin/nologin` are used to prevent user login on a linux machine

```sh
# list all users on macOS along with whether they have an interactive shell or not (e.g., /bin/bash, /usr/bin/false, /usr/bin/nologin),
dscl . -list /Users UserShell

```

There are three levels of locks
- table
- page
- row
